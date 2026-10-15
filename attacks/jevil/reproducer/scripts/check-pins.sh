#!/usr/bin/env bash
set -euo pipefail

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$package_dir"

for required in sha256sum find sort awk diff python3; do
    if ! command -v "$required" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$required" >&2
        exit 2
    fi
done

sha256sum -c SOURCE-PINS.sha256

expected_files=$(mktemp)
actual_files=$(mktemp)
trap 'rm -f "$expected_files" "$actual_files"' EXIT
awk '{print $2}' SOURCE-PINS.sha256 | sort > "$expected_files"
find attack-source clean-verifier-source -type f -print | sort > "$actual_files"
if ! diff -u "$expected_files" "$actual_files"; then
    printf 'Source file set differs from SOURCE-PINS.sha256\n' >&2
    exit 1
fi

expected_sign=34a61da541e7239402e2e49fedee76aaa50fc4c328c49cc9a307dca3bac2fb74
expected_verify=d84341b99aa3b76413c20118f7fb0a78886754e1d9c7c0f952c7f930037e569b
for tree in attack-source clean-verifier-source; do
    actual_sign=$(sha256sum "$tree/src/sign.rs" | awk '{print $1}')
    actual_verify=$(sha256sum "$tree/src/verify.rs" | awk '{print $1}')
    if [[ "$actual_sign" != "$expected_sign" || "$actual_verify" != "$expected_verify" ]]; then
        printf '%s ordinary signer/verifier pin mismatch\n' "$tree" >&2
        exit 1
    fi
done

python3 scripts/check-layout.py
printf 'SOURCE_PINS=PASS\n'

