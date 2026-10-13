#!/usr/bin/env python3
"""Run the full GLYPH reproduction for every affected advertised row."""

from __future__ import annotations

import json

from reproducer.report import full_report


def main() -> int:
    print(json.dumps(full_report(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
