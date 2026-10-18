#!/usr/bin/env python3
"""Replay both retained CUBE verifier profiles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cube_reference import all_rows_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", action="store_true")
    args = parser.parse_args()
    report = all_rows_report()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.reference:
        expected = Path(__file__).with_name("all-rows-reference-output.json").read_text()
        if rendered != expected:
            raise SystemExit("all-rows-reference-output.json does not match this reproducer")
    print(rendered, end="")
    return 0 if report["all_rows_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
