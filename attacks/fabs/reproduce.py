#!/usr/bin/env python3
"""Run the quick FABS Figure 1 fresh-message forgery reproduction."""

from __future__ import annotations

import argparse
import json

from reproducer.report import quick_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference",
        action="store_true",
        help="emit the stable deterministic public reference replay",
    )
    parser.parse_args()
    report = quick_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["full_attack_reproduced"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

