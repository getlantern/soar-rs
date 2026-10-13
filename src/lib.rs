//! Soar: a DNS tunnel for networks that censor everything but DNS.
//!
//! A wire-compatible Rust implementation of [Soar](https://github.com/getlantern/soar). The wire
//! format is specified in that repository's `SPEC.md`; `testdata/vectors.json` is its test vectors,
//! which this crate's tests check against.

mod base32;
pub mod client;
mod crypto;
mod dns;
mod error;
mod frames;
mod ranges;
pub mod server;
mod session;
mod stream;
mod varint;

#[cfg(test)]
mod vectors;

pub use error::Error;
pub use session::Read;
pub use stream::StreamError;
