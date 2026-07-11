#!/usr/bin/env bash
#
# Update the vendored serialize.h from upstream (github.com/mas-bandwidth/serialize).
#
# serialize.h is canonical and vendored verbatim. After running this, rebuild and run the
# SDK unit tests, then run the functional tests on CI (./dist/deploy test) to validate wire
# compatibility. Reconcile the adapter headers (next_bitpacker.h / next_stream.h /
# next_serialize.h) only if upstream renamed macros or changed the stream API.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="https://raw.githubusercontent.com/mas-bandwidth/serialize/main/serialize.h"

echo "fetching $URL"
curl -fsSL -o "$DIR/serialize.h" "$URL"

VERSION="$(grep -oE '#define SERIALIZE_VERSION "[^"]+"' "$DIR/serialize.h" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo unknown)"
echo "vendored serialize.h version $VERSION"
echo "next: rebuild + run 'dist/test', then './dist/deploy test' to validate wire compatibility on CI."
