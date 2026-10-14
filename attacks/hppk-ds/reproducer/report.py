"""Stable report wrappers for the HPPK DS paper-level reproducer."""

from __future__ import annotations

from typing import Any

from .hppk_reference import run_rows


def quick_report(*, reference: bool = False) -> dict[str, Any]:
    """Check all 18 affected rows with one complete hash per row."""
    return run_rows(full=False, reference=reference)


def all_rows_report(*, reference: bool = False) -> dict[str, Any]:
    """Check all 18 affected rows with four complete hashes per row."""
    return run_rows(full=True, reference=reference)
