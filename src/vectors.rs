//! Checks against the reference implementation's wire test vectors (`testdata/vectors.json`,
//! copied from getlantern/soar; see SPEC.md §10 there).

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{self, PacketCipher, decode_pn};
use crate::dns::{self, Zone};
use crate::frames::{self, Frame};
use crate::ranges::{RangeSet, Span};
use crate::{Error, base32, varint};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors"))
        .expect("parse vectors")
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn n(v: &Value) -> u64 {
    v.as_u64().expect("number")
}

fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().expect("array")
}

fn key32(v: &Value) -> [u8; 32] {
    h(v).try_into().expect("32 bytes")
}

#[test]
fn varint() {
    for c in arr(&vectors()["varint"]) {
        let enc = h(&c["encoded"]);
        let mut b = Vec::new();
        varint::put(&mut b, n(&c["value"]));
        assert_eq!(b, enc, "encode {c}");
        let mut r = varint::Reader::new(&enc);
        assert_eq!(r.varint().unwrap(), n(&c["value"]));
        assert!(r.b.is_empty());
    }
}

#[test]
fn base32() {
    for c in arr(&vectors()["base32"]) {
        let (data, enc) = (h(&c["data"]), c["encoded"].as_str().unwrap());
        let mut b = Vec::new();
        base32::encode(&mut b, &data);
        assert_eq!(b, enc.as_bytes());
        assert_eq!(base32::decode(enc.as_bytes()).unwrap(), data);
        assert_eq!(base32::decode(enc.to_uppercase().as_bytes()).unwrap(), data);
    }
}

#[test]
fn name_capacity() {
    for c in arr(&vectors()["name_capacity"]) {
        let z = Zone::parse(c["zone"].as_str().unwrap()).unwrap();
        assert_eq!(
            z.max_payload(n(&c["max_name_length"]) as usize) as u64,
            n(&c["max_payload"]),
            "{c}"
        );
    }
}

#[test]
fn packet_number() {
    for c in arr(&vectors()["packet_number"]) {
        let got = decode_pn(
            n(&c["largest"]),
            c["have_largest"].as_bool().unwrap(),
            n(&c["truncated"]) as u16,
        );
        assert_eq!(got, n(&c["pn"]), "{c}");
    }
}

fn frame_json(f: &Frame<'_>) -> Value {
    match f {
        Frame::Ping => json!({"type": "ping"}),
        Frame::Ack(rs) => {
            json!({"type": "ack", "ranges": rs.0.iter().map(|s| [s.lo, s.hi]).collect::<Vec<_>>()})
        }
        Frame::ResetStream { id, code } => json!({"type": "reset_stream", "id": id, "code": code}),
        Frame::MaxStreamData { id, max } => {
            json!({"type": "max_stream_data", "id": id, "max": max})
        }
        Frame::Close { code } => json!({"type": "close", "code": code}),
        Frame::Lost(pns) => json!({"type": "lost", "pns": pns}),
        Frame::Opened { id } => json!({"type": "opened", "id": id}),
        Frame::Stream {
            id,
            offset,
            data,
            fin,
            explicit_len,
        } => json!({
            "type": "stream", "id": id, "offset": offset, "data": hex::encode(data), "fin": fin,
            "explicit_length": explicit_len,
        }),
    }
}

/// The frame v describes; a stream's data is `data`, already decoded from v.
fn frame_from_json<'a>(v: &Value, data: &'a [u8]) -> Frame<'a> {
    let id = || n(&v["id"]);
    match v["type"].as_str().unwrap() {
        "ping" => Frame::Ping,
        "ack" => Frame::Ack(RangeSet(
            arr(&v["ranges"])
                .iter()
                .map(|r| Span {
                    lo: n(&r[0]),
                    hi: n(&r[1]),
                })
                .collect(),
        )),
        "reset_stream" => Frame::ResetStream {
            id: id(),
            code: n(&v["code"]),
        },
        "max_stream_data" => Frame::MaxStreamData {
            id: id(),
            max: n(&v["max"]),
        },
        "close" => Frame::Close {
            code: n(&v["code"]),
        },
        "lost" => Frame::Lost(arr(&v["pns"]).iter().map(n).collect()),
        "opened" => Frame::Opened { id: id() },
        "stream" => Frame::Stream {
            id: id(),
            offset: n(&v["offset"]),
            data,
            fin: v["fin"].as_bool().unwrap(),
            explicit_len: v["explicit_length"].as_bool().unwrap(),
        },
        t => panic!("unknown frame type {t}"),
    }
}

#[test]
fn frames() {
    for c in arr(&vectors()["frames"]) {
        let enc = h(&c["encoded"]);
        let parsed = frames::parse(&enc).unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
        let got: Vec<Value> = parsed.iter().map(frame_json).collect();
        assert_eq!(Value::Array(got), c["frames"], "{}", c["name"]);

        let mut b = Vec::new();
        for f in arr(&c["frames"]) {
            let data = f.get("data").map(h).unwrap_or_default();
            frame_from_json(f, &data).put(&mut b);
        }
        // Padding isn't a frame: re-encoding gives the bytes before it (SPEC §10).
        assert_eq!(b, enc[..b.len()], "{}", c["name"]);
        if c["name"] != "padding runs to the end of the packet" {
            assert_eq!(b, enc, "{}", c["name"]);
        }
    }
}

#[test]
fn bad_frames() {
    for c in arr(&vectors()["bad_frames"]) {
        assert!(
            frames::parse(&h(&c["encoded"])).is_err(),
            "{} accepted",
            c["name"]
        );
    }
}

#[test]
fn stream_open() {
    for c in arr(&vectors()["stream_open"]) {
        let a = c["address"].as_str().unwrap();
        let mut b = vec![a.len() as u8];
        b.extend_from_slice(a.as_bytes());
        assert_eq!(b, h(&c["encoded"]));
    }
}

struct Fixed {
    key: SigningKey,
    client_eph: StaticSecret,
    server_eph: StaticSecret,
    sid: u16,
}

fn fixed(v: &Value) -> Fixed {
    let hs = &v["handshake"];
    Fixed {
        key: SigningKey::from_bytes(&key32(&hs["server_seed"])),
        client_eph: StaticSecret::from(key32(&hs["client_ephemeral_private"])),
        server_eph: StaticSecret::from(key32(&hs["server_ephemeral_private"])),
        sid: n(&hs["sid"]) as u16,
    }
}

fn cipher_json(c: &PacketCipher) -> Value {
    json!({"key": hex::encode(c.key), "iv": hex::encode(c.iv), "hp": hex::encode(c.hp)})
}

/// The fixed session's ciphers, checked against the handshake vector on the way.
fn session(v: &Value) -> crypto::Session {
    let f = fixed(v);
    let hs = &v["handshake"];
    let client_pub = PublicKey::from(&f.client_eph).to_bytes();
    let (reply, s) = crypto::server_hello_with(&f.key, &f.server_eph, &client_pub, f.sid).unwrap();
    assert_eq!(reply, h(&hs["hello_reply"]), "hello reply");
    let c = crypto::client_finish(&f.key.verifying_key(), &f.client_eph, &reply).unwrap();
    assert_eq!((c.sid, &c.up, &c.down), (s.sid, &s.up, &s.down));
    s
}

#[test]
fn handshake() {
    let v = vectors();
    let hs = &v["handshake"];
    let f = fixed(&v);
    let client_pub = PublicKey::from(&f.client_eph).to_bytes();
    let server_pub = PublicKey::from(&f.server_eph).to_bytes();
    assert_eq!(
        f.key.verifying_key().to_bytes().to_vec(),
        h(&hs["server_public_key"])
    );
    assert_eq!(client_pub.to_vec(), h(&hs["client_ephemeral_public"]));
    assert_eq!(server_pub.to_vec(), h(&hs["server_ephemeral_public"]));
    let mut hello = vec![0, 0];
    hello.extend_from_slice(&client_pub);
    assert_eq!(hello, h(&hs["hello_payload"]));

    let ee = f
        .client_eph
        .diffie_hellman(&PublicKey::from(server_pub))
        .to_bytes();
    assert_eq!(ee.to_vec(), h(&hs["shared_secret"]));
    let tr = crypto::transcript(&client_pub, &server_pub, f.sid);
    assert_eq!(tr, h(&hs["transcript"]));
    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&tr), &ee);
    assert_eq!(prk.to_vec(), h(&hs["prk"]));

    let s = session(&v);
    assert_eq!(cipher_json(&s.up), hs["up"]);
    assert_eq!(cipher_json(&s.down), hs["down"]);

    // A tampered reply fails.
    let mut reply = h(&hs["hello_reply"]);
    reply[40] ^= 1;
    assert_eq!(
        crypto::client_finish(&f.key.verifying_key(), &f.client_eph, &reply).unwrap_err(),
        Error::BadSignature
    );
}

fn decoder(largest: &Value) -> impl FnOnce(u16) -> u64 {
    let l = largest.as_u64();
    move |t| decode_pn(l.unwrap_or(0), l.is_some(), t)
}

#[test]
fn packets() {
    let v = vectors();
    let s = session(&v);
    for c in arr(&v["packets"]) {
        let (pn, plain, payload) = (n(&c["pn"]), h(&c["plaintext"]), h(&c["payload"]));
        let (cipher, sealed_at) = if c["direction"] == "up" {
            (&s.up, 4)
        } else {
            (&s.down, 2)
        };
        assert_eq!(cipher.nonce(pn).to_vec(), h(&c["nonce"]), "{c}");
        assert_eq!(
            cipher.mask(&payload[sealed_at..]).to_vec(),
            h(&c["mask"]),
            "{c}"
        );
        let (got_pn, got) = if c["direction"] == "up" {
            assert_eq!(
                s.up.seal_up(n(&c["sid"]) as u16, pn, &plain),
                payload,
                "{c}"
            );
            s.up.open_up(&payload, decoder(&c["largest_received"]))
                .unwrap()
        } else {
            let up_pn = n(&c["up_pn"]);
            assert_eq!(s.down.seal_down(pn, up_pn, &plain), payload, "{c}");
            s.down
                .open_down(&payload, up_pn, decoder(&c["largest_received"]))
                .unwrap()
        };
        assert_eq!((got_pn, got), (pn, plain), "{c}");
    }
}

#[test]
fn bad_packets() {
    let v = vectors();
    let s = session(&v);
    for c in arr(&v["bad_packets"]) {
        let p = h(&c["payload"]);
        let res = if c["direction"] == "up" {
            s.up.open_up(&p, decoder(&c["largest_received"]))
        } else {
            s.down
                .open_down(&p, n(&c["up_pn"]), decoder(&c["largest_received"]))
        };
        assert_eq!(res.unwrap_err(), Error::Auth, "{} accepted", c["name"]);
    }
}

#[test]
fn dns() {
    let v = vectors();
    let z = Zone::parse(v["zone"].as_str().unwrap()).unwrap();
    let key = fixed(&v).key;
    for c in arr(&v["dns"]) {
        let name = &c["name"];
        let build = c["build"].as_bool().unwrap_or(false);
        match c["kind"].as_str().unwrap() {
            "query" => {
                let (msg, payload) = (h(&c["message"]), h(&c["payload"]));
                if build {
                    let mut b = Vec::new();
                    dns::put_query(
                        &mut b,
                        n(&c["txn"]) as u16,
                        &payload,
                        &z,
                        n(&c["qtype"]) as u16,
                        n(&c["edns_size"]) as u16,
                    );
                    assert_eq!(b, msg, "{name}");
                }
                let q = dns::parse_query(&msg, &z).unwrap();
                assert_eq!(q.payload.as_deref(), Some(&payload[..]), "{name}");
                assert_eq!(
                    (u64::from(q.txn), u64::from(q.qtype)),
                    (n(&c["txn"]), n(&c["qtype"])),
                    "{name}"
                );
                assert_eq!(q.edns as u64, n(&c["edns_size"]), "{name}");
            }
            "answer" => {
                let (msg, qmsg) = (h(&c["message"]), h(&c["query"]));
                let q = dns::parse_query(&qmsg, &z).unwrap();
                let rcode = n(&c["rcode"]) as u8;
                let payload = c.get("payload").map(h);
                if build {
                    let mut b = Vec::new();
                    match c["subkind"].as_str().unwrap() {
                        "no_data" => dns::put_no_data(&mut b, &q, &z),
                        "unknown_session" => {
                            let sig = crypto::sign_unknown_session(&key, &q.question);
                            assert_eq!(
                                crypto::unknown_session_msg(&q.question),
                                h(&c["signed_message"]),
                                "{name}"
                            );
                            assert_eq!(Some(sig.to_vec()), payload, "{name}");
                            dns::put_answer(&mut b, &q, rcode, Some(&sig));
                        }
                        _ => dns::put_answer(&mut b, &q, rcode, payload.as_deref()),
                    }
                    assert_eq!(b, msg, "{name}");
                }
                let a = dns::parse_answer(&msg).unwrap();
                assert_eq!((a.txn, a.rcode), (q.txn, rcode), "{name}");
                assert!(a.question.eq_ignore_ascii_case(&q.question), "{name}");
                if c["subkind"] == "no_data" {
                    continue;
                }
                assert_eq!(a.carried, payload.is_some(), "{name}");
                assert_eq!(a.payload, payload.clone().unwrap_or_default(), "{name}");
                if c["subkind"] == "unknown_session" {
                    assert!(crypto::verify_unknown_session(
                        &key.verifying_key(),
                        &a.question,
                        &a.payload
                    ));
                }
            }
            "capacity" => {
                let q = dns::parse_query(&h(&c["query"]), &z).unwrap();
                let limit = n(&c["limit"]) as usize;
                let cap = dns::capacity(&q, limit);
                assert_eq!(cap as u64, n(&c["capacity"]), "{name}");
                let mut b = Vec::new();
                dns::put_answer(&mut b, &q, dns::RCODE_OK, Some(&vec![0; cap]));
                assert!(b.len() <= limit, "{name}: {} > {limit}", b.len());
            }
            k => panic!("unknown dns kind {k}"),
        }
    }
}

#[test]
fn exchange() {
    let v = vectors();
    let z = Zone::parse(v["zone"].as_str().unwrap()).unwrap();
    let f = fixed(&v);
    let s = session(&v);
    let (mut up_largest, mut down_largest): (Option<u64>, Option<u64>) = (None, None);
    for step in arr(&v["exchange"]) {
        let (qmsg, amsg) = (h(&step["query"]), h(&step["answer"]));
        let q = dns::parse_query(&qmsg, &z).unwrap();
        let a = dns::parse_answer(&amsg).unwrap();
        assert_eq!((a.txn, a.rcode), (q.txn, dns::RCODE_OK));
        // Every message rebuilds byte for byte.
        let mut b = Vec::new();
        dns::put_query(
            &mut b,
            q.txn,
            q.payload.as_deref().unwrap(),
            &z,
            q.qtype,
            dns::EDNS_SIZE,
        );
        assert_eq!(b, qmsg);
        let mut b = Vec::new();
        dns::put_answer(&mut b, &q, dns::RCODE_OK, Some(&a.payload));
        assert_eq!(b, amsg);

        if let Some(hello) = step.get("hello_payload") {
            assert_eq!(q.payload.as_deref(), Some(&h(hello)[..]));
            assert_eq!(a.payload, h(&step["hello_reply"]));
            let c =
                crypto::client_finish(&f.key.verifying_key(), &f.client_eph, &a.payload).unwrap();
            assert_eq!(c.sid, f.sid);
            continue;
        }
        let up_pn = n(&step["up_pn"]);
        let dec = |l: Option<u64>| move |t| decode_pn(l.unwrap_or(0), l.is_some(), t);
        let (pn, plain) =
            s.up.open_up(q.payload.as_deref().unwrap(), dec(up_largest))
                .unwrap();
        assert_eq!((pn, plain), (up_pn, h(&step["up_plaintext"])));
        let (pn, plain) = s
            .down
            .open_down(&a.payload, up_pn, dec(down_largest))
            .unwrap();
        assert_eq!(
            (pn, plain.clone()),
            (n(&step["down_pn"]), h(&step["down_plaintext"]))
        );
        // The frames parse.
        frames::parse(&plain[2..]).unwrap();
        up_largest = Some(up_pn);
        down_largest = Some(pn);
    }
}
