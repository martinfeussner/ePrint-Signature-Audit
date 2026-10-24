#!/bin/sh
set -eu

attack_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-}

case "$mode" in
  --quick)
    if [ "$#" -ne 1 ]; then
      echo "usage: $0 --quick" >&2
      exit 2
    fi
    exec python3 -B "$attack_dir/reproduce.py" --reference
    ;;
  --full)
    if [ "$#" -ne 2 ]; then
      echo "usage: $0 --full NEW_EVIDENCE.json" >&2
      exit 2
    fi
    output=$2
    if [ -e "$output" ]; then
      echo "refusing to overwrite existing output: $output" >&2
      exit 2
    fi
    python3 -B "$attack_dir/reproduce-all-rows.py" --trials 1 --output "$output"
    exec python3 -B "$attack_dir/reproducer/validate_evidence.py" \
      --evidence "$output" --implementation "$attack_dir/reproduce-all-rows.py"
    ;;
  *)
    echo "usage: $0 --quick | --full NEW_EVIDENCE.json" >&2
    exit 2
    ;;
esac
