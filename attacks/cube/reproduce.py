#!/usr/bin/env python3
"""Run the deterministic quick CUBE identity-proof reproduction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cube_reference import quick_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", action="store_true")
    args = parser.parse_args()
    report = quick_report()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.reference:
        expected = Path(__file__).with_name("reference-output.json").read_text()
        if rendered != expected:
            raise SystemExit("reference-output.json does not match this reproducer")
    print(rendered, end="")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
