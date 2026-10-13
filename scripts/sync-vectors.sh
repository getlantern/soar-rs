#!/bin/sh
# Copies the wire test vectors from getlantern/soar at a commit (default: the pinned one) into
# testdata/, and pins that commit. With --check, verifies the copy matches the pin instead.
set -eu
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--check" ]; then
	ref=$(cat testdata/VECTORS_REF)
	tmp=$(mktemp)
	trap 'rm -f "$tmp"' EXIT
	curl -fsSL "https://raw.githubusercontent.com/getlantern/soar/$ref/testdata/vectors.json" -o "$tmp"
	if ! cmp -s "$tmp" testdata/vectors.json; then
		echo "testdata/vectors.json differs from getlantern/soar@$ref; run scripts/sync-vectors.sh $ref" >&2
		exit 1
	fi
	echo "vectors match getlantern/soar@$ref"
	exit 0
fi

ref=${1:-$(cat testdata/VECTORS_REF)}
sha=$(git ls-remote https://github.com/getlantern/soar.git "$ref" | awk 'NR == 1 { print $1 }')
sha=${sha:-$ref} # a commit sha doesn't show up in ls-remote
curl -fsSL "https://raw.githubusercontent.com/getlantern/soar/$sha/testdata/vectors.json" -o testdata/vectors.json
echo "$sha" > testdata/VECTORS_REF
echo "synced vectors from getlantern/soar@$sha"
