#!/usr/bin/env python3
"""Run and summarize the primary full-parameter Yagisawa reproduction."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path

from reproducer.primary import main


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(raw: dict) -> dict:
    controls = raw["control_results"]
    checks = {
        "all_four_challenge_classes_accept": raw["all_p_residue_classes"] == 4,
        "forgery_accepts": raw["forgery_accepts"] == raw["forgery_trials"],
        "honest_same_message_accepts": raw["honest_accepts"] == raw["honest_trials"],
        "hidden_domain_conditions_hold": (
            raw["domain_audit"]["R_noncommuting_with_message"]
            and raw["domain_audit"]["R_commuting_secret_constants"] == 0
            and raw["domain_audit"]["message_commuting_secret_constants"] == 0
        ),
        "legacy_g1_correctness_defect_reproduced": (
            raw["legacy_g1_regression"]["forgery_all_p"]
            and not raw["legacy_g1_regression"]["honest_output_all_p"]
        ),
        "negative_controls_rejected": (
            raw["negative_controls_rejected"] == raw["negative_controls"]
            and not any(controls.values())
        ),
        "public_coefficient_count_is_2240": raw["public_coefficients"] == 2240,
        "public_secret_cross_checks_pass": raw["public_secret_cross_checks"] == 8,
        "zero_signing_queries": raw["signing_queries"] == 0,
    }
    root = Path(__file__).resolve().parent
    return {
        "attack": {
            "R": raw["R"],
            "fresh_message_E": raw["fresh_message"],
            "result": "public-key-only zero-query fresh-message forgery",
            "signing_queries": raw["signing_queries"],
        },
        "checks": checks,
        "digests": {
            "primary_core_sha256": sha256_file(root / "reproducer" / "primary.py"),
            "target_pdf_sha256": raw["target_pdf_sha256"],
        },
        "environment": {
            "language": f"Python {raw['python']} standard library",
            "workers": raw["workers"],
        },
        "measurements": {
            "attack_seconds": raw["attack_seconds"],
            "elapsed_seconds": raw["elapsed_seconds"],
            "parameter_row": "q=1048609, d=2, r=3, m=448, s=13",
            "peak_rss_kib": raw["peak_rss_kib"],
        },
        "raw_result": raw,
        "result": "PASS: zero-query fresh-message forgery accepted at full parameters",
    }


def run() -> int:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        status = main()
    raw = json.loads(captured.getvalue())
    summary = summarize(raw)
    if not all(summary["checks"].values()):
        raise RuntimeError("one or more primary reproduction checks failed")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return int(status or 0)


if __name__ == "__main__":
    raise SystemExit(run())
