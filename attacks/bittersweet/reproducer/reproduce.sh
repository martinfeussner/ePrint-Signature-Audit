#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON_BIN="$ROOT/.venv/bin/python"
else
  PYTHON_BIN=${PYTHON:-python3.12}
fi
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 12) else 1)'; then
  echo "Bittersweet reproducer requires CPython 3.12 with reproducer/requirements.txt installed" >&2
  exit 2
fi

case "${1:---quick}" in
  --quick)
    shift || true
    exec "$PYTHON_BIN" -B "$ROOT/reproduce.py" "$@"
    ;;
  --full)
    shift
    exec "$PYTHON_BIN" -B "$ROOT/reproduce.py" --full "$@"
    ;;
  *)
    echo "usage: $0 --quick|--full [reproducer options]" >&2
    exit 2
    ;;
esac
