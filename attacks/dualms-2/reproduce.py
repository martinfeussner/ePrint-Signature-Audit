#!/usr/bin/env python3
"""Run the DualMS 2.0 two-row replay with fresh operating-system entropy."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from reproducer.dualms2_reference import run_all


def main() -> int:
    attack_dir = Path(__file__).resolve().parent
    if sys.argv[1:] == ["--reference"]:
        sys.stdout.write(
            (attack_dir / "reference-output.json").read_text(encoding="utf-8")
        )
        return 0
    if sys.argv[1:]:
        raise SystemExit("usage: reproduce.py [--reference]")
    print(json.dumps(run_all(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
