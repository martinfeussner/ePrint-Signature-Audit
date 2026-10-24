#!/usr/bin/env python3
"""Validate the retained Sphinx-in-the-Head evidence without running the attack."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> int:
    validator = Path(__file__).resolve().parent / "reproducer" / "validate_evidence.py"
    namespace = runpy.run_path(str(validator))
    return int(namespace["main"](sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())
