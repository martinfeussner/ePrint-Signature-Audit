#!/usr/bin/env python3
"""Stable entry points for fresh and canonical public reproduction reports."""

from __future__ import annotations

from .hbaisis_reference import build_report, fresh_seed, reference_seed


def quick_report(*, reference: bool = False) -> dict[str, object]:
    seed = reference_seed("quick") if reference else fresh_seed()
    source = "public_reference_fixture" if reference else "os_entropy"
    return build_report(seed, trials=8, seed_source=source)


def all_rows_report(*, reference: bool = False) -> dict[str, object]:
    seed = reference_seed("all-rows") if reference else fresh_seed()
    source = "public_reference_fixture" if reference else "os_entropy"
    return build_report(seed, trials=64, seed_source=source)

