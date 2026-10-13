#!/bin/sh
# Runs the Rust Soar client against the Go soar-server on loopback.
set -eu
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'kill $pid 2>/dev/null || true; rm -rf "$tmp"' EXIT

# The Go server at the commit interop/go.mod pins.
(cd interop && go build -o "$tmp/soar-server" github.com/getlantern/soar/cmd/soar-server)
cargo build --release --example interop_client

(umask 077; "$tmp/soar-server" keygen | awk '$1 == "private" { print $2 }' > "$tmp/key")
pub=$("$tmp/soar-server" pubkey "$tmp/key")
port=${SOAR_INTEROP_PORT:-15354}

"$tmp/soar-server" -zone t.example.com -key-file "$tmp/key" -listen "127.0.0.1:$port" \
	-allow-private -allow-ports any 2>/dev/null &
pid=$!
sleep 0.5

target/release/examples/interop_client -server "127.0.0.1:$port" -pubkey "$pub" "$@"
