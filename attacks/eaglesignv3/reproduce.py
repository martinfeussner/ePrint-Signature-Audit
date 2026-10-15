#!/usr/bin/env python3
"""Run the fast EagleSignV3 paper-level arithmetic smoke check."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    attack_dir = Path(__file__).resolve().parent
    if sys.argv[1:] == ["--reference"]:
        sys.stdout.write(
            (attack_dir / "reference-output.json").read_text(encoding="utf-8")
        )
        return 0
    if sys.argv[1:]:
        raise SystemExit("usage: reproduce.py [--reference]")

    reproducer = attack_dir / "reproducer"
    completed = subprocess.run(
        [str(reproducer / "reproduce.sh"), "--smoke"],
        cwd=reproducer,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    sys.stderr.write(completed.stdout)
    if completed.returncode != 0:
        return completed.returncode
    if "EAGLESIGNV3 STRUCTURE SMOKE: PASS" not in completed.stdout:
        raise SystemExit("SMOKE REPORT: FAIL: success banner missing")

    result = {
        "checks": {"paper_level_arithmetic_selftest": True},
        "digests": {
            "public_scheme_source_sha256": sha256(
                reproducer / "src" / "public_scheme.hpp"
            ),
            "selftest_source_sha256": sha256(reproducer / "src" / "selftest.cpp"),
        },
        "environment": {"workers": 1},
        "full_attack_reproduced": False,
        "mode": "structural_smoke",
        "result": (
            "STRUCTURAL_SMOKE_PASS (ring arithmetic, decomposition, and "
            "challenge sampling only; no attack executed)"
        ),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

