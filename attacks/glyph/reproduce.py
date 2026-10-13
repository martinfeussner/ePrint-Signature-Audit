#!/usr/bin/env python3
"""Run the quick full-parameter GLYPH forgery reproduction."""

from __future__ import annotations

import json

from reproducer.report import quick_report


def main() -> int:
    print(json.dumps(quick_report(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
