#!/usr/bin/env python3
"""Run the complete EagleSignV3 Ring-L2 fresh-key reproduction."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


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

    reproducer = attack_dir / "reproducer"
    completed = subprocess.run(
        [str(reproducer / "reproduce.sh"), "--full"],
        cwd=reproducer,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    sys.stderr.write(completed.stdout)
    if completed.returncode != 0:
        return completed.returncode
    completed = subprocess.run(
        [sys.executable, "-B", "report.py", "output/full"],
        cwd=reproducer,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        return completed.returncode
    value = json.loads(completed.stdout)
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

