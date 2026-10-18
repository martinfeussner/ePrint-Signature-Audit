#!/usr/bin/env python3
"""Command-line runner for the dependency-free FABS paper model."""

from __future__ import annotations

import argparse
import json

from .report import all_rows_report, quick_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="run all retained cases")
    parser.add_argument("--reference", action="store_true", help="stable replay marker")
    args = parser.parse_args()
    report = all_rows_report() if args.full else quick_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    passed = report.get("all_rows_pass", report.get("full_attack_reproduced", False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

