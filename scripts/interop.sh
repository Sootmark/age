#!/bin/sh
# Checks this crate against the reference Go implementation, both ways:
# files encrypted here decrypt with `age -d -i`, files from `age -r`
# decrypt here, at every size around the chunk boundaries and a large one.
# Needs `age` and `age-keygen` (`apt-get install age`). Runs in CI.
set -eu
cd "$(dirname "$0")/.."
cargo build --release --locked --example age
ours=target/release/examples/age
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

age-keygen -o "$tmp/identity.txt" 2>/dev/null
recipient=$(age-keygen -y "$tmp/identity.txt")
age-keygen -o "$tmp/other.txt" 2>/dev/null
other=$(age-keygen -y "$tmp/other.txt")

check() {
    size=$1
    shift
    scripts/plaintext.sh "$size" > "$tmp/plain"
    "$ours" "$@" < "$tmp/plain" > "$tmp/ours.age"
    age -d -i "$tmp/identity.txt" < "$tmp/ours.age" | cmp -s - "$tmp/plain" \
        || { echo "age could not decrypt our $size-byte file"; exit 1; }
    age "$@" < "$tmp/plain" > "$tmp/theirs.age"
    "$ours" -d -i "$tmp/identity.txt" < "$tmp/theirs.age" | cmp -s - "$tmp/plain" \
        || { echo "we could not decrypt age's $size-byte file"; exit 1; }
    echo "ok: $size bytes ($*)"
}

for size in 0 1 1000 65535 65536 65537 131071 131072 131073 1000000; do
    check "$size" -r "$recipient"
done
check 100000 -r "$other" -r "$recipient"
check 100000 -r "$recipient" -r "$other"
check 100000000 -r "$recipient"

# A file of ours with one byte changed must not decrypt with age.
scripts/plaintext.sh 1000 | "$ours" -r "$recipient" > "$tmp/ours.age"
size=$(wc -c < "$tmp/ours.age")
for offset in 30 $((size - 500)) $((size - 1)); do
    cp "$tmp/ours.age" "$tmp/damaged.age"
    was=$(dd if="$tmp/ours.age" bs=1 skip="$offset" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
    if [ "$was" = 255 ]; then byte='\000'; else byte='\377'; fi
    printf "$byte" | dd of="$tmp/damaged.age" bs=1 seek="$offset" conv=notrunc 2>/dev/null
    if age -d -i "$tmp/identity.txt" < "$tmp/damaged.age" > /dev/null 2>&1; then
        echo "age decrypted our file damaged at byte $offset"
        exit 1
    fi
done
echo "ok: damaged files rejected by age"
