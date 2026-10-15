#!/usr/bin/env bash
set -euo pipefail

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$package_dir"

usage() {
    printf 'Usage: %s --smoke|--full\n' "$0" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
case "$1" in
    --smoke) mode=smoke ;;
    --full) mode=full ;;
    *) usage ;;
esac

for required in sha256sum python3 find sort awk uname getconf date; do
    if ! command -v "$required" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$required" >&2
        exit 2
    fi
done
if [[ ! -x /usr/bin/time ]]; then
    printf 'GNU time is required at /usr/bin/time\n' >&2
    exit 2
fi

cargo_bin=${CARGO:-cargo}
rustc_bin=${RUSTC:-rustc}
if ! command -v "$cargo_bin" >/dev/null 2>&1; then
    printf 'Cargo executable not found: %s\n' "$cargo_bin" >&2
    exit 2
fi
if ! command -v "$rustc_bin" >/dev/null 2>&1; then
    printf 'rustc executable not found: %s\n' "$rustc_bin" >&2
    exit 2
fi
if [[ $("$cargo_bin" --version) != cargo\ 1.88.0* ]]; then
    printf 'This reproducer requires Cargo 1.88.0; found: %s\n' \
        "$("$cargo_bin" --version)" >&2
    exit 2
fi
if [[ $("$rustc_bin" --version) != rustc\ 1.88.0* ]]; then
    printf 'This reproducer requires rustc 1.88.0; found: %s\n' \
        "$("$rustc_bin" --version)" >&2
    exit 2
fi

export CARGO_BUILD_JOBS=1
export RAYON_NUM_THREADS=1
export MAKEFLAGS=-j1
export LC_ALL=C

cargo_flags=(--locked)
if [[ ${JEVIL_OFFLINE:-0} == 1 ]]; then
    cargo_flags+=(--offline)
fi

output_root=${JEVIL_OUTPUT_ROOT:-$package_dir/output}
build_root=${JEVIL_BUILD_ROOT:-$package_dir/build}
mkdir -p "$output_root" "$build_root"

./scripts/check-pins.sh

write_environment() {
    local destination=$1
    {
        printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'mode=%s\n' "$mode"
        printf 'workers=1\n'
        printf 'cargo_build_jobs=%s\n' "$CARGO_BUILD_JOBS"
        printf 'rayon_num_threads=%s\n' "$RAYON_NUM_THREADS"
        printf 'cargo=%s\n' "$("$cargo_bin" --version)"
        printf 'rustc=%s\n' "$("$rustc_bin" --version)"
        printf 'uname='; uname -a
        printf 'architecture='; uname -m
        printf 'logical_cpus='; getconf _NPROCESSORS_ONLN
        printf 'source_commit=905466fbe3be99d90fd41e461e0c68271d09104b\n'
        printf 'source_tree=f4a7366dac1a1f079186d87a2aca79c9918ee79e\n'
        printf 'paper=ePrint-2026-1103-revision-4\n'
        printf 'paper_pdf_sha256=c0da79bdf8b2d2c9667d6167d6ab008b8eeaf838b463a40eb64f2abe123c01c5\n'
    } > "$destination"
}

if [[ "$mode" == smoke ]]; then
    output_dir=$output_root/smoke
    rm -rf "$output_dir"
    mkdir -p "$output_dir"
    write_environment "$output_dir/environment.txt"
    printf '%s\n' \
        'cargo test --release --locked independent::tests::subproduct_interpolation_recovers_four_small_rows -- --exact --nocapture' \
        > "$output_dir/command.txt"
    CARGO_TARGET_DIR="$build_root/cargo" \
        /usr/bin/time -v -o "$output_dir/time.txt" \
        "$cargo_bin" test --manifest-path attack-source/Cargo.toml \
        --release "${cargo_flags[@]}" \
        independent::tests::subproduct_interpolation_recovers_four_small_rows \
        -- --exact --nocapture > "$output_dir/run.log" 2>&1
    cat > "$output_dir/summary.json" <<'JSON'
{
  "checks": {
    "source_layout_checked": true,
    "synthetic_four_row_interpolation": true
  },
  "full_attack_reproduced": false,
  "mode": "structural_smoke",
  "result": "STRUCTURAL_SMOKE_PASS",
  "schema": "org.eprint-signature-audit.jevil-reproducer-run/v1",
  "verdict": "PASS",
  "workers": 1
}
JSON
    (
        cd "$output_dir"
        find . -type f ! -name MANIFEST.sha256 -print0 \
            | sort -z | xargs -0 sha256sum > MANIFEST.sha256
        sha256sum -c MANIFEST.sha256 >/dev/null
    )
    printf 'JEVIL STRUCTURE SMOKE: PASS\n'
    printf 'Output: %s\n' "$output_dir"
    exit 0
fi

output_dir=$output_root/full
rm -rf "$output_dir"
mkdir -p "$output_dir"
write_environment "$output_dir/environment.txt"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/jevil-reproducer.XXXXXXXX")
cleanup() {
    chmod u+rwx "$work_dir" 2>/dev/null || true
    if [[ -n ${private_dir:-} && -d ${private_dir:-} ]]; then
        chmod u+rwx "$private_dir" 2>/dev/null || true
    fi
    chmod -R u+rwX "$work_dir" 2>/dev/null || true
    rm -rf "$work_dir"
}
trap cleanup EXIT

private_dir=$work_dir/private
public_dir=$work_dir/public-transcripts
result_dir=$work_dir/results
empty_cwd=$work_dir/public-process-cwd
mkdir -p "$private_dir" "$public_dir" "$result_dir" "$empty_cwd"
umask 077
dd if=/dev/urandom of="$private_dir/key-seed.bin" bs=32 count=1 status=none

printf '%s\n' \
    'cargo build --release --locked --example exp002_oracle --example exp002_recover' \
    > "$output_dir/build-attack.command.txt"
CARGO_TARGET_DIR="$build_root/cargo" \
    /usr/bin/time -v -o "$output_dir/build-attack.time.txt" \
    "$cargo_bin" build --manifest-path attack-source/Cargo.toml \
    --release "${cargo_flags[@]}" --example exp002_oracle --example exp002_recover \
    > "$output_dir/build-attack.log" 2>&1

printf '%s\n' \
    'cargo build --release --locked --example exp002_clean_verify' \
    > "$output_dir/build-clean-verifier.command.txt"
CARGO_TARGET_DIR="$build_root/cargo" \
    /usr/bin/time -v -o "$output_dir/build-clean-verifier.time.txt" \
    "$cargo_bin" build --manifest-path clean-verifier-source/Cargo.toml \
    --release "${cargo_flags[@]}" --example exp002_clean_verify \
    > "$output_dir/build-clean-verifier.log" 2>&1

oracle_bin=$build_root/cargo/release/examples/exp002_oracle
recover_bin=$build_root/cargo/release/examples/exp002_recover
clean_verify_bin=$build_root/cargo/release/examples/exp002_clean_verify
for binary in "$oracle_bin" "$recover_bin" "$clean_verify_bin"; do
    [[ -x "$binary" ]] || { printf 'Missing built executable: %s\n' "$binary" >&2; exit 1; }
done

printf '%s\n' 'exp002_oracle PRIVATE_SEED PUBLIC_TRANSCRIPTS 650' \
    > "$output_dir/oracle.command.txt"
/usr/bin/time -v -o "$output_dir/oracle.time.txt" \
    "$oracle_bin" "$private_dir/key-seed.bin" "$public_dir" 650 \
    > "$output_dir/oracle.log" 2>&1

chmod -R a-w "$public_dir"
chmod 000 "$private_dir/key-seed.bin" "$private_dir"
printf '%s\n' 'env -i PATH=/usr/bin:/bin RAYON_NUM_THREADS=1 exp002_recover PUBLIC_TRANSCRIPTS RESULTS' \
    > "$output_dir/recovery.command.txt"
(
    cd "$empty_cwd"
    /usr/bin/time -v -o "$output_dir/recovery.time.txt" \
        env -i PATH=/usr/bin:/bin RAYON_NUM_THREADS=1 \
        "$recover_bin" "$public_dir" "$result_dir" \
        > "$output_dir/recovery.log" 2>&1
)

printf '%s\n' 'exp002_clean_verify PUBLIC_KEY FRESH_MESSAGE FRESH_SIGNATURE CLEAN_RESULT_JSON' \
    > "$output_dir/clean-verifier.command.txt"
/usr/bin/time -v -o "$output_dir/clean-verifier.time.txt" \
    "$clean_verify_bin" \
    "$result_dir/public-key.bin" \
    "$result_dir/fresh-message.bin" \
    "$result_dir/fresh-signature.bin" \
    "$result_dir/clean-verifier-result.json" \
    > "$output_dir/clean-verifier.log" 2>&1

python3 scripts/validate-full.py \
    "$public_dir/COMPLETE.txt" \
    "$result_dir/result.json" \
    "$result_dir/clean-verifier-result.json" \
    "$output_dir/summary.json" \
    "$output_dir" \
    > "$output_dir/validation.log"

mkdir -p "$output_dir/artifacts"
cp "$public_dir/COMPLETE.txt" "$output_dir/oracle-completion.txt"
cp "$result_dir"/* "$output_dir/artifacts/"

(
    cd "$output_dir"
    find . -type f ! -name MANIFEST.sha256 -print0 \
        | sort -z | xargs -0 sha256sum > MANIFEST.sha256
    sha256sum -c MANIFEST.sha256 >/dev/null
)

cleanup
trap - EXIT

python3 scripts/report-full.py "$output_dir/summary.json"
printf 'Output: %s\n' "$output_dir"

