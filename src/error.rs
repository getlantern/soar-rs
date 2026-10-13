use std::fmt;

/// Errors from parsing and authenticating Soar's wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A buffer ended before the value it should hold.
    Short,
    /// A malformed frame.
    Frame,
    /// A malformed DNS message.
    Dns,
    /// A zone that can't carry the tunnel.
    Zone(&'static str),
    /// A packet failed authentication.
    Auth,
    /// The server's handshake signature didn't verify.
    BadSignature,
    /// A key exchange produced an all-zero secret (a low-order public key).
    WeakKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Short => f.write_str("soar: short buffer"),
            Error::Frame => f.write_str("soar: malformed frame"),
            Error::Dns => f.write_str("soar: malformed DNS message"),
            Error::Zone(why) => write!(f, "soar: {why}"),
            Error::Auth => f.write_str("soar: packet authentication failed"),
            Error::BadSignature => f.write_str("soar: server signature verification failed"),
            Error::WeakKey => f.write_str("soar: low-order key exchange"),
        }
    }
}

impl std::error::Error for Error {}
