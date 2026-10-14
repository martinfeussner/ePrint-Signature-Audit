#!/usr/bin/env python3
"""Run the full 18-row HPPK DS paper-level reproduction."""

from __future__ import annotations

import argparse
import json

from reproducer.report import all_rows_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference",
        action="store_true",
        help="use the stable public reference fixture instead of OS entropy",
    )
    args = parser.parse_args()
    report = all_rows_report(reference=args.reference)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
