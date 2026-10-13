//! The handshake, key schedule and packet protection (SPEC §4, §5).

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use poly1305::Poly1305;
use poly1305::universal_hash::{KeyInit, UniversalHash};
use rand_core::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Error;

/// The truncated Poly1305 tag: a forgery succeeds with p=2^-64 per attempt.
pub const TAG_LEN: usize = 8;
pub const SAMPLE_LEN: usize = 12;
/// The plaintext floor that gives packet-number protection a full sample.
pub const MIN_PLAIN: usize = SAMPLE_LEN - TAG_LEN;
pub const PUB_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
/// A hello reply: server ephemeral || sid || signature.
pub const HELLO_REPLY_LEN: usize = PUB_LEN + 2 + SIG_LEN;

const SIG_CONTEXT: &[u8] = b"soar v1 hello";
/// Domain-separates the server's signed "no such session" reply.
const UNKNOWN_CONTEXT: &[u8] = b"soar v1 unknown session";
const KDF_LABEL: &str = "soar v1 ";

/// Seals one direction's packets: ChaCha20-Poly1305 (RFC 8439) with the tag truncated to 8 bytes,
/// a per-packet nonce derived from the packet number, and protection of the truncated packet
/// number so it doesn't appear as a counter on the wire.
#[derive(Clone, PartialEq, Eq)]
pub struct PacketCipher {
    pub key: [u8; 32],
    pub iv: [u8; 12],
    pub hp: [u8; 32],
}

impl std::fmt::Debug for PacketCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PacketCipher")
    }
}

impl PacketCipher {
    pub fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut n = self.iv;
        for (b, p) in n[4..].iter_mut().zip(pn.to_be_bytes()) {
            *b ^= p;
        }
        n
    }

    /// A ChaCha20 stream for pn positioned at block 1, and the Poly1305 key from block 0.
    fn stream(&self, pn: u64) -> (ChaCha20, [u8; 32]) {
        let mut s = ChaCha20::new(&self.key.into(), &self.nonce(pn).into());
        let mut block0 = [0u8; 64];
        s.apply_keystream(&mut block0);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block0[..32]);
        (s, poly_key)
    }

    fn tag(poly_key: &[u8; 32], ad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
        let mut m = Poly1305::new(poly_key.into());
        m.update_padded(ad);
        m.update_padded(ct);
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
        m.update_padded(&lens);
        let full = m.finalize();
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(&full[..TAG_LEN]);
        t
    }

    /// Appends the encryption of plain and its tag to dst.
    pub fn seal(&self, dst: &mut Vec<u8>, ad: &[u8], plain: &[u8], pn: u64) {
        let (mut s, poly_key) = self.stream(pn);
        let start = dst.len();
        dst.extend_from_slice(plain);
        s.apply_keystream(&mut dst[start..]);
        let tag = Self::tag(&poly_key, ad, &dst[start..]);
        dst.extend_from_slice(&tag);
    }

    /// Authenticates and decrypts ciphertext || tag.
    pub fn open(&self, ad: &[u8], sealed: &[u8], pn: u64) -> Result<Vec<u8>, Error> {
        let split = sealed.len().checked_sub(TAG_LEN).ok_or(Error::Auth)?;
        let (ct, tag) = sealed.split_at(split);
        let (mut s, poly_key) = self.stream(pn);
        if !bool::from(Self::tag(&poly_key, ad, ct).ct_eq(tag)) {
            return Err(Error::Auth);
        }
        let mut plain = ct.to_vec();
        s.apply_keystream(&mut plain);
        Ok(plain)
    }

    /// The 2-byte packet-number mask for a ciphertext sample. Unlike QUIC, the whole 12-byte
    /// sample is the nonce and the counter is 0.
    pub fn mask(&self, sealed: &[u8]) -> [u8; 2] {
        let mut sample = [0u8; SAMPLE_LEN];
        sample.copy_from_slice(&sealed[..SAMPLE_LEN]);
        let mut m = [0u8; 2];
        ChaCha20::new(&self.hp.into(), &sample.into()).apply_keystream(&mut m);
        m
    }

    /// Builds an upstream packet: the session id, the protected truncated packet number, and the
    /// sealed plaintext. The associated data is the session id and the truncated packet number
    /// unmasked; on the wire the packet number is masked.
    pub fn seal_up(&self, sid: u16, pn: u64, plain: &[u8]) -> Vec<u8> {
        let mut hdr = [0u8; 4];
        hdr[..2].copy_from_slice(&sid.to_be_bytes());
        hdr[2..].copy_from_slice(&(pn as u16).to_be_bytes());
        let mut p = Vec::with_capacity(hdr.len() + plain.len() + TAG_LEN);
        p.extend_from_slice(&hdr);
        self.seal(&mut p, &hdr, plain, pn);
        let m = self.mask(&p[4..]);
        p[2] ^= m[0];
        p[3] ^= m[1];
        p
    }

    /// Authenticates the upstream packet p, expanding its truncated packet number with decode.
    pub fn open_up(
        &self,
        p: &[u8],
        decode: impl FnOnce(u16) -> u64,
    ) -> Result<(u64, Vec<u8>), Error> {
        if p.len() < 4 + SAMPLE_LEN {
            return Err(Error::Auth);
        }
        let sealed = &p[4..];
        let m = self.mask(sealed);
        let hdr = [p[0], p[1], p[2] ^ m[0], p[3] ^ m[1]];
        let pn = decode(u16::from_be_bytes([hdr[2], hdr[3]]));
        Ok((pn, self.open(&hdr, sealed, pn)?))
    }

    /// Builds a downstream packet answering the query that carried upstream packet up_pn: the
    /// protected truncated packet number, then the sealed plaintext.
    pub fn seal_down(&self, pn: u64, up_pn: u64, plain: &[u8]) -> Vec<u8> {
        let hdr = (pn as u16).to_be_bytes();
        let mut p = Vec::with_capacity(hdr.len() + plain.len() + TAG_LEN);
        p.extend_from_slice(&hdr);
        self.seal(&mut p, &down_ad(hdr, up_pn), plain, pn);
        let m = self.mask(&p[2..]);
        p[0] ^= m[0];
        p[1] ^= m[1];
        p
    }

    /// Authenticates the downstream packet p as the answer to upstream packet up_pn.
    pub fn open_down(
        &self,
        p: &[u8],
        up_pn: u64,
        decode: impl FnOnce(u16) -> u64,
    ) -> Result<(u64, Vec<u8>), Error> {
        if p.len() < 2 + SAMPLE_LEN {
            return Err(Error::Auth);
        }
        let sealed = &p[2..];
        let m = self.mask(sealed);
        let hdr = [p[0] ^ m[0], p[1] ^ m[1]];
        let pn = decode(u16::from_be_bytes(hdr));
        Ok((pn, self.open(&down_ad(hdr, up_pn), sealed, pn)?))
    }
}

/// A downstream packet's associated data: its truncated packet number on the wire, and,
/// implicitly, the upstream packet number of the query it answers, so a valid answer can't be
/// replayed onto another query (which would falsely acknowledge that query's data).
fn down_ad(trunc: [u8; 2], up_pn: u64) -> [u8; 10] {
    let mut ad = [0u8; 10];
    ad[..2].copy_from_slice(&trunc);
    ad[2..].copy_from_slice(&up_pn.to_be_bytes());
    ad
}

/// Expands a truncated 16-bit packet number (RFC 9000 §A.3; SPEC §5.3).
pub fn decode_pn(largest: u64, have: bool, trunc: u16) -> u64 {
    const WIN: u64 = 1 << 16;
    const HWIN: u64 = 1 << 15;
    const MASK: u64 = WIN - 1;
    let expected = if have { largest + 1 } else { 0 };
    let cand = expected & !MASK | u64::from(trunc);
    if cand + HWIN <= expected && cand < (1 << 62) - WIN {
        cand + WIN
    } else if cand > expected + HWIN && cand >= WIN {
        cand - WIN
    } else {
        cand
    }
}

fn new_cipher(prk: &Hkdf<Sha256>, dir: &str) -> PacketCipher {
    let mut c = PacketCipher {
        key: [0; 32],
        iv: [0; 12],
        hp: [0; 32],
    };
    for (dst, label) in [
        (&mut c.key[..], "key"),
        (&mut c.iv[..], "iv"),
        (&mut c.hp[..], "hp"),
    ] {
        let info = format!("{KDF_LABEL}{dir} {label}");
        prk.expand(info.as_bytes(), dst).expect("HKDF output fits");
    }
    c
}

/// Both directions' ciphers from the ephemeral-ephemeral secret, salted with the transcript.
pub fn session_ciphers(ee: &[u8], transcript: &[u8]) -> (PacketCipher, PacketCipher) {
    let prk = Hkdf::<Sha256>::new(Some(transcript), ee);
    (new_cipher(&prk, "up"), new_cipher(&prk, "down"))
}

pub fn transcript(client_eph: &[u8; PUB_LEN], server_eph: &[u8; PUB_LEN], sid: u16) -> Vec<u8> {
    let mut t = Vec::with_capacity(SIG_CONTEXT.len() + 2 * PUB_LEN + 2);
    t.extend_from_slice(SIG_CONTEXT);
    t.extend_from_slice(client_eph);
    t.extend_from_slice(server_eph);
    t.extend_from_slice(&sid.to_be_bytes());
    t
}

/// The key exchange, refusing a low-order peer key.
fn exchange(ours: &StaticSecret, theirs: &[u8; PUB_LEN]) -> Result<[u8; 32], Error> {
    let ee = ours.diffie_hellman(&PublicKey::from(*theirs));
    if !ee.was_contributory() {
        return Err(Error::WeakKey);
    }
    Ok(ee.to_bytes())
}

/// The result of a handshake: the session id and the up and down ciphers.
#[derive(Debug)]
pub struct Session {
    pub sid: u16,
    pub up: PacketCipher,
    pub down: PacketCipher,
}

/// Answers a client's ephemeral key: the reply payload and the session (SPEC §4.2).
pub fn server_hello(
    key: &SigningKey,
    client_eph: &[u8; PUB_LEN],
    sid: u16,
) -> Result<(Vec<u8>, Session), Error> {
    server_hello_with(key, &StaticSecret::random_from_rng(OsRng), client_eph, sid)
}

/// server_hello with the server's ephemeral key given.
pub fn server_hello_with(
    key: &SigningKey,
    eph: &StaticSecret,
    client_eph: &[u8; PUB_LEN],
    sid: u16,
) -> Result<(Vec<u8>, Session), Error> {
    let ee = exchange(eph, client_eph)?;
    let server_eph = PublicKey::from(eph).to_bytes();
    let tr = transcript(client_eph, &server_eph, sid);
    let (up, down) = session_ciphers(&ee, &tr);
    let mut reply = Vec::with_capacity(HELLO_REPLY_LEN);
    reply.extend_from_slice(&server_eph);
    reply.extend_from_slice(&sid.to_be_bytes());
    reply.extend_from_slice(&key.sign(&tr).to_bytes());
    Ok((reply, Session { sid, up, down }))
}

/// Verifies the server's hello reply and derives the session.
pub fn client_finish(
    server: &VerifyingKey,
    eph: &StaticSecret,
    reply: &[u8],
) -> Result<Session, Error> {
    if reply.len() < HELLO_REPLY_LEN {
        return Err(Error::BadSignature);
    }
    let server_eph: [u8; PUB_LEN] = reply[..PUB_LEN].try_into().expect("length checked");
    let sid = u16::from_be_bytes([reply[PUB_LEN], reply[PUB_LEN + 1]]);
    let tr = transcript(&PublicKey::from(eph).to_bytes(), &server_eph, sid);
    let sig = Signature::from_slice(&reply[PUB_LEN + 2..HELLO_REPLY_LEN])
        .map_err(|_| Error::BadSignature)?;
    server
        .verify_strict(&tr, &sig)
        .map_err(|_| Error::BadSignature)?;
    let ee = exchange(eph, &server_eph)?;
    let (up, down) = session_ciphers(&ee, &tr);
    Ok(Session { sid, up, down })
}

/// What the server signs to say a query's session doesn't exist: the question, lower-cased since
/// resolvers may randomize case on the way to it. Only ASCII letters are folded (SPEC §4.5).
pub fn unknown_session_msg(question: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(UNKNOWN_CONTEXT.len() + question.len());
    m.extend_from_slice(UNKNOWN_CONTEXT);
    m.extend(question.iter().map(u8::to_ascii_lowercase));
    m
}

/// Signs the unknown-session reply to question.
pub fn sign_unknown_session(key: &SigningKey, question: &[u8]) -> [u8; SIG_LEN] {
    key.sign(&unknown_session_msg(question)).to_bytes()
}

/// Verifies a signed unknown-session reply to question.
pub fn verify_unknown_session(server: &VerifyingKey, question: &[u8], sig: &[u8]) -> bool {
    Signature::from_slice(sig).is_ok_and(|s| {
        server
            .verify_strict(&unknown_session_msg(question), &s)
            .is_ok()
    })
}
