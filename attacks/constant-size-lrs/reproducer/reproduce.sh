#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
attack_dir="$(dirname -- "$script_dir")"

mode="${1:---quick}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$mode" in
  --quick)
    exec python3 -B "$attack_dir/reproduce.py" --reference "$@"
    ;;
  --full)
    exec python3 -B "$attack_dir/reproduce-all-rows.py" "$@"
    ;;
  *)
    echo "usage: $0 [--quick|--full] [reproducer options]" >&2
    exit 2
    ;;
esac
