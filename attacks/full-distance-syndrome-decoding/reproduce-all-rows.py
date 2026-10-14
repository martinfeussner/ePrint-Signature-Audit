#!/usr/bin/env python3
"""Run every affected advertised row (the demonstrated Level-I row)."""

from __future__ import annotations

import json

from reproducer.report import all_rows_report


if __name__ == "__main__":
    print(json.dumps(all_rows_report(), indent=2, sort_keys=True))
