//! Soar: a DNS tunnel for networks that censor everything but DNS.
//!
//! A wire-compatible Rust implementation of [Soar](https://github.com/getlantern/soar). The wire
//! format is specified in that repository's `SPEC.md`; `testdata/vectors.json` is its test vectors,
//! which this crate's tests check against.

// The wire layer lands before the session, client and server that use it.
#![allow(dead_code)] // remove once the session layer uses all of it

mod base32;
mod crypto;
mod dns;
mod error;
mod frames;
mod ranges;
mod varint;

#[cfg(test)]
mod vectors;

pub use error::Error;
