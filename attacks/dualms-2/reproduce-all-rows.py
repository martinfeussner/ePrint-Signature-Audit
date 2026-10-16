#!/usr/bin/env python3
"""Run both advertised DualMS 2.0 rounded rows with the stable seed."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from reproducer.dualms2_reference import run_all


REFERENCE_SEED = bytes.fromhex(
    "b54788155733e2f4898e263673996949837f1816b18e620f8e7d77b50169bda2"
)


def main() -> int:
    attack_dir = Path(__file__).resolve().parent
    if sys.argv[1:] == ["--reference"]:
        sys.stdout.write(
            (attack_dir / "all-rows-reference-output.json").read_text(
                encoding="utf-8"
            )
        )
        return 0
    if sys.argv[1:]:
        raise SystemExit("usage: reproduce-all-rows.py [--reference]")
    print(json.dumps(run_all(seed=REFERENCE_SEED), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
