#!/usr/bin/env bash
set -euo pipefail

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$package_dir"

case "${1:-}" in
    --quick)
        mode=quick
        trials=8
        ;;
    --full)
        mode=full
        trials=64
        ;;
    *)
        printf 'Usage: %s --quick|--full\n' "$0" >&2
        exit 2
        ;;
esac
if [[ $# -ne 1 ]]; then
    printf 'Usage: %s --quick|--full\n' "$0" >&2
    exit 2
fi

for required in make cc sha256sum nm awk uname openssl getconf grep head \
        date find sort xargs ldd wc; do
    if ! command -v "$required" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$required" >&2
        exit 2
    fi
done
if [[ ! -x /usr/bin/time ]]; then
    printf 'GNU time is required at /usr/bin/time\n' >&2
    exit 2
fi

export LC_ALL=C
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export MAKEFLAGS=-j1

printf 'Checking byte-exact upstream source pins...\n'
expected_hash_list=2b31d7ebaa0a7b8bef07e90cdeeb9f1f313ba1a3af6e47d940190fffd0fdc52c
expected_provenance=4dd762d16074a6503bd402129c4fc9e4e16a481bc7239e0766c5af7229e411d5
actual_hash_list=$(sha256sum UPSTREAM-SOURCES.sha256 | awk '{print $1}')
actual_provenance=$(sha256sum UPSTREAM-SOURCES.json | awk '{print $1}')
if [[ "$actual_hash_list" != "$expected_hash_list" ||
      "$actual_provenance" != "$expected_provenance" ]]; then
    printf 'Upstream provenance manifest pin mismatch\n' >&2
    exit 2
fi
sha256sum -c UPSTREAM-SOURCES.sha256
if [[ $(find vendor/glyph -type f | wc -l) -ne 15 ]]; then
    printf 'Unexpected file in the minimal vendored upstream source set\n' >&2
    exit 2
fi

output_dir="output/$mode"
rm -rf "$output_dir"
mkdir -p "$output_dir"

{
    printf 'mode=%s\n' "$mode"
    printf 'trials=%s\n' "$trials"
    printf 'workers=1\n'
    printf 'outer_command=./reproducer/reproduce.sh --%s\n' "$mode"
    printf 'inner_command=./build/glyph-reproducer --mode %s --trials %s --summary output/%s/summary.json --trials-csv output/%s/trials.csv\n' \
        "$mode" "$trials" "$mode" "$mode"
} > "$output_dir/commands.txt"

{
    printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'workers=1\n'
    printf 'thread_limits=OMP:1,OPENBLAS:1,MKL:1,NUMEXPR:1\n'
    printf 'uname='; uname -a
    printf 'architecture='; uname -m
    printf 'word_bits='; getconf LONG_BIT
    printf 'byte_order_required=little (enforced by executable)\n'
    printf 'logical_cpus='; getconf _NPROCESSORS_ONLN
    printf 'compiler='; cc --version | head -n 1
    printf 'openssl='; openssl version
    printf 'gnu_time='; /usr/bin/time --version | head -n 1
    printf 'source_commit=74b96d691391f687fe8f91e1d5cb3c251762d7cc\n'
    printf 'source_tree=2ae8eec4b23dc57fc816c8935da8c2a59a753196\n'
    printf 'target_pdf_sha256=ff0eeaea3a9fcb830197ea954472869a08adbf42e64e727470fa8e0038c6682a\n'
} > "$output_dir/environment.txt" 2>&1

make clean >/dev/null
make all 2>&1 | tee "$output_dir/build.log"

nm -u build/public_forge.o > "$output_dir/public-forger-undefined-symbols.txt"
if grep -Eq 'glp_(gen|sign|deterministic_sign|verify)|sample_glp_secret' \
        "$output_dir/public-forger-undefined-symbols.txt"; then
    printf 'Public forger object references a secret/signing/verifier symbol\n' >&2
    exit 1
fi
nm -u build/reproducer.o > "$output_dir/driver-undefined-symbols.txt"
if ! grep -Eq '[[:space:]]U[[:space:]]+glp_verify$' \
        "$output_dir/driver-undefined-symbols.txt"; then
    printf 'Driver does not call ordinary glp_verify\n' >&2
    exit 1
fi
if grep -Eq '[[:space:]]U[[:space:]]+glp_(sign|deterministic_sign)$' \
        "$output_dir/driver-undefined-symbols.txt"; then
    printf 'Driver references a signing function\n' >&2
    exit 1
fi
nm -g build/glyph-reproducer > "$output_dir/binary-symbols.txt"
if ! grep -Eq '[[:space:]]T[[:space:]]+glp_verify$' \
        "$output_dir/binary-symbols.txt"; then
    printf 'Linked binary does not contain pinned glp_verify\n' >&2
    exit 1
fi

{
    printf 'binary_sha256='; sha256sum build/glyph-reproducer | awk '{print $1}'
    printf 'public_forge_object_sha256='; sha256sum build/public_forge.o | awk '{print $1}'
    printf 'upstream_glp_object_sha256='; sha256sum build/glp.o | awk '{print $1}'
    printf 'dynamic_dependencies:\n'
    ldd build/glyph-reproducer
} > "$output_dir/binary.txt"

set +e
/usr/bin/time -v -o "$output_dir/time.txt" \
    ./build/glyph-reproducer \
    --mode "$mode" \
    --trials "$trials" \
    --summary "$output_dir/summary.json" \
    --trials-csv "$output_dir/trials.csv" \
    2>&1 | tee "$output_dir/run.log"
run_status=${PIPESTATUS[0]}
set -e
printf '%s\n' "$run_status" > "$output_dir/exit-status.txt"
if [[ $run_status -ne 0 ]]; then
    exit "$run_status"
fi

(
    cd "$output_dir"
    find . -type f ! -name MANIFEST.sha256 -print0 \
        | sort -z \
        | xargs -0 sha256sum > MANIFEST.sha256
    sha256sum -c MANIFEST.sha256
)

printf 'Sealed output: %s/MANIFEST.sha256\n' "$output_dir"
