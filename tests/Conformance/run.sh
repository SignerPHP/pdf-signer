#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cd "$root"

php tests/Conformance/fixture.php prepare "$workdir"
for key in rsa ec; do
    # The input is the SHA-256 digest of DER signed attributes, not the attributes.
    # OpenSSL's pkeyutl signs this digest without hashing it again.
    openssl pkeyutl -sign -inkey "$workdir/$key/key.pem" \
        -in "$workdir/$key/digest.bin" \
        -pkeyopt digest:sha256 \
        -out "$workdir/$key/signature.der"
done
php tests/Conformance/fixture.php complete "$workdir"
python3 tests/Conformance/check.py "$workdir"
