#!/usr/bin/env python3
"""Run one fresh full-Level-I public FDSD attack reproduction."""

from __future__ import annotations

import json

from reproducer.report import quick_report


if __name__ == "__main__":
    print(json.dumps(quick_report(), indent=2, sort_keys=True))
