#!/bin/sh
set -eu

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$PACKAGE_DIR"

case "${1:---quick}" in
  --quick)
    exec env PYTHONDONTWRITEBYTECODE=1 python3 reproduce.py
    ;;
  --full)
    exec env PYTHONDONTWRITEBYTECODE=1 python3 reproduce-all-rows.py
    ;;
  --reference-quick)
    exec env PYTHONDONTWRITEBYTECODE=1 python3 reproduce.py --reference
    ;;
  --reference-full)
    exec env PYTHONDONTWRITEBYTECODE=1 python3 reproduce-all-rows.py --reference
    ;;
  *)
    echo "usage: $0 [--quick|--full|--reference-quick|--reference-full]" >&2
    exit 2
    ;;
esac

