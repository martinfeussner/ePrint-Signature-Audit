#!/usr/bin/env python3
"""Replay all retained public FABS Figure 1 attack presentations."""

from __future__ import annotations

import argparse
import json

from reproducer.report import all_rows_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference",
        action="store_true",
        help="emit the stable deterministic public reference replay",
    )
    parser.parse_args()
    report = all_rows_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_rows_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

