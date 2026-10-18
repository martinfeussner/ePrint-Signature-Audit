#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
exec python3 -B -m reproducer.runner "$@"

