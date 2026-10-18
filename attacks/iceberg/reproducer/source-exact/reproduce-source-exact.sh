#!/bin/sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PINNED_COMMIT=b2f87cb047467dd78852bc32722a5228a7167f5e
OFFICIAL_URL=https://github.com/furszy/benchmark-iceberg.git
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/iceberg-source-exact.XXXXXX")
trap 'rm -rf "$WORK_ROOT"' EXIT HUP INT TERM

SOURCE_TARGET="$WORK_ROOT/source-cache/iceberg-2026-1757/upstream/benchmark-iceberg"
mkdir -p "$(dirname "$SOURCE_TARGET")"

if [ -n "${ICEBERG_SOURCE_DIR:-}" ]; then
    git clone --quiet --no-hardlinks "$ICEBERG_SOURCE_DIR" "$SOURCE_TARGET"
else
    git clone --quiet "$OFFICIAL_URL" "$SOURCE_TARGET"
fi
git -C "$SOURCE_TARGET" checkout --quiet --detach "$PINNED_COMMIT"

ACTUAL_COMMIT=$(git -C "$SOURCE_TARGET" rev-parse HEAD)
if [ "$ACTUAL_COMMIT" != "$PINNED_COMMIT" ]; then
    echo "unexpected source commit: $ACTUAL_COMMIT" >&2
    exit 1
fi

(
    cd "$SOURCE_TARGET"
    cat <<'EOF' | sha256sum -c -
16db2bff7e41f5a9f959cf691125a587ac6fc6062a08b4c7d9d4876f29a13c61  sources/secp256k1-kmp/native/secp256k1/src/modules/iceberg/session_impl.h
6664edc6a0c1532051a90ca42e669442eb8a73ccf4656cd26d1443476dcbc7f0  sources/secp256k1-kmp/native/secp256k1/include/secp256k1_iceberg.h
EOF
)

ATTACK_DIR="$WORK_ROOT/experiments/iceberg-2026-1757/EXP-0001-context-splitting-key-recovery"
mkdir -p "$ATTACK_DIR"
cp "$HERE/attack.c" "$ATTACK_DIR/attack.c"
(
    cd "$ATTACK_DIR"
    printf '%s  %s\n' \
        e9787f333a1cd09411629eae9d1751de5c21e29f5b61e8d13102c708ec624e01 \
        attack.c | sha256sum -c -
    SRC=../../../source-cache/iceberg-2026-1757/upstream/benchmark-iceberg/sources/secp256k1-kmp/native/secp256k1
    CC_BIN=${CC:-cc}
    "$CC_BIN" -std=c99 -O2 -Wall -Wextra -Wno-unused-function \
        -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 \
        -DENABLE_MODULE_MUSIG=1 -DENABLE_MODULE_ICEBERG=1 \
        -DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6 \
        -I"$SRC" -I"$SRC/src" \
        attack.c "$SRC/src/precomputed_ecmult.c" "$SRC/src/precomputed_ecmult_gen.c" \
        -o attack
    ./attack | tee result.txt
    grep -qx 'result=PASS' result.txt
)

echo "source_exact_result=PASS"
