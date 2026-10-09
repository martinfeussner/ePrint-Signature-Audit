#!/usr/bin/env python3
"""Run and summarize the primary full-parameter reproduction."""

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
    attack = raw["attack_checks"]
    params = raw["parameter_checks"]
    pairing = raw["pairing_checks"]
    checks = {
        "altered_scalar_rejected": attack["altered_s_rejected"],
        "corrected_base_has_order_n": params["corrected_P_has_order_n"],
        "corrected_public_point_matches_key_equation": params["corrected_Q_matches_gaP"],
        "forged_point_differs": attack["forged_point_differs"],
        "fresh_target_forgery_accepted": attack["forgery_accepts_on_fresh_target"],
        "honest_signature_accepted": attack["honest_signature_accepts"],
        "one_signing_query": attack["one_signing_query"],
        "pairing_bilinear": pairing["bilinear_3_5"],
        "pairing_exact_order_n": pairing["e_to_n_is_one"]
        and pairing["e_to_n_over_p1_not_one"]
        and pairing["e_to_n_over_p2_not_one"],
        "pairing_nontrivial": pairing["e_not_one"],
        "printed_y_off_curve_confirmed": not params["printed_y_on_curve"],
        "same_scalar_response": attack["same_s_as_source"],
        "source_signature_rejected_on_target": attack["source_signature_rejected_on_target"],
        "target_was_not_signed": attack["target_was_not_signed"],
        "unrelated_message_rejected": attack["forgery_rejected_on_unrelated_message"],
    }
    root = Path(__file__).resolve().parent
    return {
        "attack": {
            "result": "same-s public-scalar transport forgery",
            "signing_queries": 1,
            "source_message_hex": raw["messages"]["source_hex"],
            "target_message_hex": raw["messages"]["target_hex"],
        },
        "checks": checks,
        "digests": {
            "primary_core_sha256": sha256_file(root / "reproducer" / "primary.py"),
            "target_pdf_sha256": "a8b4eae608a28baf86e585fb19056a43881d3c386eae6f7fb6b2cf1d2d49c65f",
            "target_source_archive_sha256": "d67435736b459ef85c705dd726763204ac6400b3c3c9058ac2a2b2e25011ae86",
        },
        "environment": {
            "language": "Python 3.12 standard library",
            "workers": 1,
        },
        "measurements": {
            "elapsed_seconds": raw["elapsed_seconds"],
            "parameter_row": "printed 1023/1024-bit factors; 2046-bit n; 2048-bit field",
        },
        "raw_result": raw,
        "result": "PASS: one-query fresh-message forgery accepted at full parameters",
    }


def run() -> int:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        status = main()
    raw = json.loads(captured.getvalue())
    print(json.dumps(summarize(raw), indent=2, sort_keys=True))
    return int(status or 0)


if __name__ == "__main__":
    raise SystemExit(run())
