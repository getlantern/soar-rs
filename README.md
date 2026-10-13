# soar-rs

A wire-compatible Rust implementation of [Soar](https://github.com/getlantern/soar), the DNS tunnel
for networks that censor everything except DNS. Its client and server interoperate with the Go
ones.

The protocol is specified in Soar's [SPEC.md](https://github.com/getlantern/soar/blob/main/SPEC.md).
This crate is tested against the reference implementation's wire test vectors, in
[`testdata/vectors.json`](testdata/vectors.json). They're copied from `getlantern/soar` at the
commit pinned in [`testdata/VECTORS_REF`](testdata/VECTORS_REF), and CI checks that the copy
matches.

## Status

Early work. The protocol itself is still pre-release.

- [x] **Wire layer:** varints, base32, the DNS carrier (TXT and AAAA), frames, the handshake and
  key schedule, packet protection. Every section of the test vectors passes.
- [ ] **Session:** streams, packet numbers, acknowledgement and loss, flow control.
- [ ] **Server:** an authoritative name server for the zone, with held polls, dialing, and limits.
- [ ] **Client:** resolver paths, congestion control, size probing, TCP/53, discovery.
- [ ] **Interop CI** against the Go `soar-server` and client.
- [ ] **A `dnsbench` contender** in `getlantern/soar/bench`.

## Updating the vectors

When the wire format changes in `getlantern/soar`, pull its new vectors and pin the commit:

```sh
scripts/sync-vectors.sh main   # or a commit sha
cargo test
```

## License

Apache 2.0.
