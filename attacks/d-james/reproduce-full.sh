#!/usr/bin/env bash
set -euo pipefail

attack_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$attack_dir"

mkdir -p work
python3 export_public_magma.py \
  full-q5-128-public-key.json work/public-data.m

/usr/bin/time -v -o work/recover.time \
  magma -b recover.m | tee work/recover.log

/usr/bin/time -v -o work/complete-and-sign.time \
  magma -b complete_and_sign.m

grep -q '^ATTACK_REPRODUCTION: PASS$' work/full-attack-results.txt
python3 extract_replay_witness.py
python3 reproduce.py \
  --forgery work/replay-forgery.json \
  --output work/public-verification.json

printf '%s\n' '========================================'
printf '%s\n' 'ATTACK REPRODUCTION: PASS'
printf '%s\n' 'Scheme: D-James q5/128'
printf '%s\n' 'Result: equivalent signing key recovered'
printf '%s\n' 'Fresh-message forgery: ACCEPTED'
printf '%s\n' 'Negative control: REJECTED'
printf '%s\n' '========================================'
