#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -eq 0 ]; then
    RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fdsd-public-reproduce.XXXXXX")
    CLEAN=1
elif [ "$#" -eq 2 ] && [ "$1" = "--output" ]; then
    RUN_DIR=$2
    mkdir -p "$RUN_DIR"
    CLEAN=0
else
    echo "usage: $0 [--output DIRECTORY]" >&2
    exit 2
fi

cleanup() {
    if [ "$CLEAN" -eq 1 ]; then
        rm -rf "$RUN_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

export PYTHONHASHSEED=0
export PYTHONDONTWRITEBYTECODE=1
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1

PUBLIC_DIR="$RUN_DIR/public"
python3 "$ROOT/generate_case.py" --output "$PUBLIC_DIR" \
    >"$RUN_DIR/generation.stdout"
python3 "$ROOT/public_attack.py" --public-dir "$PUBLIC_DIR" \
    --output "$RUN_DIR/attack-result.json" >"$RUN_DIR/attack.stdout"
python3 "$ROOT/verify_forgery.py" --public-dir "$PUBLIC_DIR" \
    --attack-result "$RUN_DIR/attack-result.json" \
    --output "$RUN_DIR/summary.json"
