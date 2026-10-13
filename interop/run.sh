#!/bin/sh
# Runs the Go Soar client against the Rust soar-server on loopback.
set -eu
cd "$(dirname "$0")/.."

cargo build --release --bin soar-server
tmp=$(mktemp -d)
trap 'kill $pid 2>/dev/null || true; rm -rf "$tmp"' EXIT

(umask 077; target/release/soar-server keygen | awk '$1 == "private" { print $2 }' > "$tmp/key")
pub=$(target/release/soar-server pubkey "$tmp/key")
port=${SOAR_INTEROP_PORT:-15353}

target/release/soar-server -zone t.example.com -key-file "$tmp/key" -listen "127.0.0.1:$port" \
	-allow-private -allow-ports any &
pid=$!
sleep 0.5

cd interop
go run . -server "127.0.0.1:$port" -pubkey "$pub" -zone t.example.com
