#!/usr/bin/env python3
"""Run 64 messages on every affected Figure 3 row and both residue lifts."""

from __future__ import annotations

import argparse
import json

from reproducer.report import all_rows_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference",
        action="store_true",
        help="use the fixed public reference fixture instead of fresh OS entropy",
    )
    args = parser.parse_args()
    print(json.dumps(all_rows_report(reference=args.reference), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

