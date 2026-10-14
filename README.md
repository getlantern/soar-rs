# soar-rs

A wire-compatible Rust implementation of [Soar](https://github.com/getlantern/soar), the DNS tunnel
for networks that censor everything except DNS. Its client and server interoperate with the Go
ones.

The protocol is specified in Soar's [SPEC.md](https://github.com/getlantern/soar/blob/main/SPEC.md),
and described at [soar.lantern.io](https://soar.lantern.io).
This crate is tested against the reference implementation's wire test vectors, in
[`testdata/vectors.json`](testdata/vectors.json). They're copied from `getlantern/soar` at the
commit pinned in [`testdata/VECTORS_REF`](testdata/VECTORS_REF), and CI checks that the copy
matches.

## Status

Early work. The protocol itself is still pre-release.

- [x] **Wire layer:** varints, base32, the DNS carrier (TXT and AAAA), frames, the handshake and
  key schedule, packet protection. Every section of the test vectors passes.
- [x] **Session:** streams, packet numbers, acknowledgement and loss, flow control. A sans-IO
  core: no sockets and no clock, so it's deterministic under test and embeddable without Tokio.
- [x] **Server:** an authoritative name server for the zone, with held polls, signed
  unknown-session answers, amplification limits, and public-only dialing. `ServerCore` is the
  sans-IO protocol; `server::serve` runs it on Tokio. The `soar-server` binary takes the same
  flags and key files as the Go one.
- [x] **Client:** every resolver as a path with its own RTT, loss and congestion window; name-length
  and answer-size probing; AAAA fallback; TCP/53 links; signed unknown-session handling; resolver
  discovery with the same bundled lists as the Go client. `ClientCore` is the sans-IO protocol;
  `client::Client` runs it on Tokio, with each stream a `Conn` that implements `AsyncRead` and
  `AsyncWrite`. The `soar-client` binary forwards local TCP connections through the tunnel.
- [x] **Interop CI**, both ways: the Go client against the Rust server (`interop/run.sh`), and the
  Rust client against the Go server (`interop/run-reverse.sh`).
- [x] **A `dnsbench` contender** in `getlantern/soar/bench`, so the Rust implementation is
  benchmarked alongside Soar's Go one and the other DNS tunnels.

## Running the server

```sh
cargo install --path .        # or: cargo build --release
(umask 077; soar-server keygen | awk '$1 == "private" { print $2 }' > key)
soar-server pubkey key        # the public key, for clients
soar-server -zone t.example.com -key-file key -listen :53
```

By default streams may reach only public addresses on ports 80 and 443 (`-allow-ports`,
`-allow-private`).

## Running the client

```sh
soar-client -zone t.example.com -pubkey BASE64 -resolver 8.8.8.8,1.1.1.1 \
    -listen 127.0.0.1:7000 -forward example.com:443
```

Or as a library:

```rust
let mut cfg = ClientConfig::new("t.example.com", server_key, &["8.8.8.8", "1.1.1.1"]);
cfg.discovery.enabled = true;
let client = Client::new(cfg).await?;
let mut conn = client.connect("example.com:443").await?; // AsyncRead + AsyncWrite
```

## Interop

`interop/run.sh` builds the Rust server and drives the Go client from `getlantern/soar` against it:
fetches, uploads, echo, concurrent streams, refused destinations. `interop/run-reverse.sh` runs
the same checks with the Rust client (`examples/interop_client.rs`) against the Go server. Both
check programs also run against any server (`-server`, `-pubkey`, `-v` for path stats).

## Updating the vectors

When the wire format changes in `getlantern/soar`, pull its new vectors and pin the commit:

```sh
scripts/sync-vectors.sh main   # or a commit sha
cargo test
```

## License

Apache 2.0.
