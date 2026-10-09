#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

PYTHONDONTWRITEBYTECODE=1 python3 reproduce.py
PYTHONDONTWRITEBYTECODE=1 python3 reproduce-all-rows.py
