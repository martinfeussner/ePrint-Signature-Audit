#!/usr/bin/env bash
set -euo pipefail

export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export PYTHONDONTWRITEBYTECODE=1
export LC_ALL=C
export TZ=UTC

umask 077

cd "$(dirname "$0")"

test -f empty-signing-query-transcript.txt
test ! -s empty-signing-query-transcript.txt

outputs=(
  patent-toy-results.json
  public-key.bin
  fixture-results.json
  forged-pair.json
  verification-results.json
  results.json
)
for output in "${outputs[@]}"; do
  if [[ -e "$output" ]]; then
    echo "refusing to overwrite pre-existing experiment output: $output" >&2
    exit 2
  fi
done

python3 -B patent_toy_conformance.py --results patent-toy-results.json
python3 -B generate_full_row.py \
  --public-key public-key.bin \
  --results fixture-results.json
python3 -B forge_public.py \
  --public-key public-key.bin \
  --query-transcript empty-signing-query-transcript.txt \
  --output forged-pair.json
python3 -B verify_and_controls.py \
  --public-key public-key.bin \
  --pair forged-pair.json \
  --results verification-results.json
python3 -B summarize.py \
  --fixture fixture-results.json \
  --forgery forged-pair.json \
  --verification verification-results.json \
  --toy patent-toy-results.json \
  --public-key public-key.bin \
  --query-transcript empty-signing-query-transcript.txt \
  --output results.json
