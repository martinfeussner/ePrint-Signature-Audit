#!/bin/sh
set -eu

case "${1:-}" in
  --quick)
    exec python3 -B "$(dirname "$0")/../reproduce.py"
    ;;
  --all-rows)
    exec python3 -B "$(dirname "$0")/../reproduce-all-rows.py"
    ;;
  --reference-quick)
    exec python3 -B "$(dirname "$0")/../reproduce.py" --reference
    ;;
  --reference-all-rows)
    exec python3 -B "$(dirname "$0")/../reproduce-all-rows.py" --reference
    ;;
  *)
    echo "usage: $0 --quick|--all-rows|--reference-quick|--reference-all-rows" >&2
    exit 2
    ;;
esac
