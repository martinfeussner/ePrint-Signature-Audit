#!/usr/bin/env python3
"""Replay the sole claimed full Constant-Size LRS parameter profile."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reproducer.report import all_rows_report, run_full, validate_retained


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference",
        action="store_true",
        help="validate and report the retained independently reproduced evidence",
    )
    parser.add_argument(
        "--raw-output-dir",
        type=Path,
        help="preserve raw core, validator, and evidence outputs from a fresh run",
    )
    args = parser.parse_args()
    if args.reference and args.raw_output_dir is not None:
        parser.error("--raw-output-dir applies only to a fresh full run")
    report = validate_retained() if args.reference else run_full(args.raw_output_dir)
    rows = all_rows_report(report)
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0 if rows["all_rows_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
