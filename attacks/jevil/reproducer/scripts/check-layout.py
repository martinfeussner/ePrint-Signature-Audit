#!/usr/bin/env python3
"""Check the exact, narrow delta between the attack and clean source trees."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
ATTACK = ROOT / "attack-source"
CLEAN = ROOT / "clean-verifier-source"

ATTACK_ONLY = {
    Path("examples/exp002_oracle.rs"),
    Path("examples/exp002_recover.rs"),
    Path("src/independent.rs"),
}
CLEAN_ONLY = {Path("examples/exp002_clean_verify.rs")}
ALLOWED_DIFFERENT = {
    Path("src/lib.rs"),
    Path("src/whir/protocol.rs"),
}


def files(root: Path) -> set[Path]:
    return {
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file()
    }


def fail(message: str) -> None:
    print(f"source-layout check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


attack_files = files(ATTACK)
clean_files = files(CLEAN)

if attack_files - clean_files != ATTACK_ONLY:
    fail(f"unexpected attack-only files: {sorted(attack_files - clean_files)}")
if clean_files - attack_files != CLEAN_ONLY:
    fail(f"unexpected clean-only files: {sorted(clean_files - attack_files)}")

different = {
    path
    for path in attack_files & clean_files
    if (ATTACK / path).read_bytes() != (CLEAN / path).read_bytes()
}
if different != ALLOWED_DIFFERENT:
    fail(f"unexpected common-file deltas: {sorted(different)}")

for forbidden in ("target", "oracle-private", "public-transcripts"):
    if any(path.name == forbidden for path in ATTACK.rglob("*")):
        fail(f"forbidden generated path in attack source: {forbidden}")
    if any(path.name == forbidden for path in CLEAN.rglob("*")):
        fail(f"forbidden generated path in clean source: {forbidden}")

print("SOURCE_LAYOUT=PASS")
print("ATTACK_ONLY=" + ",".join(map(str, sorted(ATTACK_ONLY))))
print("CLEAN_ONLY=" + ",".join(map(str, sorted(CLEAN_ONLY))))
print("COMMON_DELTAS=" + ",".join(map(str, sorted(ALLOWED_DIFFERENT))))

