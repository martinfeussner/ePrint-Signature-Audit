#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC="$ROOT/src"
OUT=${1:-"$ROOT/reproduction-run"}

mkdir -p "$OUT"
FIRST_EXISTING=$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit)
if [[ -n "$FIRST_EXISTING" ]]; then
  echo "refusing to use nonempty output directory: $OUT" >&2
  exit 2
fi

export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export PYTHONHASHSEED=0

START_NS=$(date +%s%N)

python3 -I "$SRC/record_environment.py" --output "$OUT/environment.json"

/usr/bin/time -v -o "$OUT/keygen.time" \
  python3 -I "$SRC/tot_keygen.py" \
  --public-key "$OUT/public_key.bin" \
  >"$OUT/keygen.stdout" 2>"$OUT/keygen.stderr"

/usr/bin/time -v -o "$OUT/forge.time" \
  python3 -I "$SRC/tot_forge.py" \
  --public-key "$OUT/public_key.bin" \
  --forgery "$OUT/forgery.json" \
  >"$OUT/forge.stdout" 2>"$OUT/forge.stderr"

/usr/bin/time -v -o "$OUT/verify.time" \
  python3 -I "$SRC/tot_verify.py" \
  --public-key "$OUT/public_key.bin" \
  --forgery "$OUT/forgery.json" \
  --result "$OUT/result.json" \
  >"$OUT/verify.stdout" 2>"$OUT/verify.stderr"

END_NS=$(date +%s%N)
ELAPSED=$(python3 -c "print(($END_NS - $START_NS) / 1000000000)")
python3 -I "$SRC/summarize_resources.py" \
  --run-dir "$OUT" \
  --elapsed-seconds "$ELAPSED" \
  --output "$OUT/resource_usage.json" \
  >"$OUT/resource-summary.stdout"

cat "$OUT/keygen.stdout"
cat "$OUT/forge.stdout"
cat "$OUT/verify.stdout"
cat "$OUT/resource-summary.stdout"
