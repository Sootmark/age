#!/bin/sh
# Regenerates tests/fixtures/age: files encrypted by the reference Go
# implementation (`age`, `age-keygen`; `apt-get install age`), and the
# identity that opens them (a test key, public on purpose). The plaintexts
# aren't stored: they are scripts/plaintext.sh's, of the size in each
# file's name.
set -eu
cd "$(dirname "$0")/.."
out=tests/fixtures/age
mkdir -p "$out"
rm -f "$out"/*.age "$out"/identity.txt

age-keygen -o "$out/identity.txt" 2>/dev/null
recipient=$(age-keygen -y "$out/identity.txt")
other=$(age-keygen 2>/dev/null | age-keygen -y)

# Empty, one byte, a chunk less one, exactly one chunk, one byte more, and
# a few chunks.
for size in 0 1 65535 65536 65537 200000; do
    scripts/plaintext.sh "$size" | age -r "$recipient" > "$out/x25519-$size.age"
done
# Two recipients, ours second.
scripts/plaintext.sh 1000 | age -r "$other" -r "$recipient" > "$out/two-recipients-1000.age"

age --version > "$out/VERSION"
