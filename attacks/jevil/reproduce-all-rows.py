#!/usr/bin/env python3
"""Run the complete 650-query Jevil fresh-key attack reproduction."""

from __future__ import annotations

import json
import os
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
    environment = os.environ.copy()
    environment["JEVIL_OUTPUT_ROOT"] = str(reproducer / "output")
    completed = subprocess.run(
        [str(reproducer / "reproduce.sh"), "--full"],
        cwd=attack_dir,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    sys.stderr.write(completed.stdout)
    if completed.returncode != 0:
        return completed.returncode
    result = json.loads(
        (reproducer / "output" / "full" / "summary.json").read_text(
            encoding="utf-8"
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

