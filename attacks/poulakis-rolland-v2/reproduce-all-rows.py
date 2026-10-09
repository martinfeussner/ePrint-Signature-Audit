#!/usr/bin/env python3
"""Run and summarize the independent fresh-key full-parameter reproduction.

Poulakis--Rolland v2 publishes one concrete parameter endpoint.  This second
entry point follows the repository's all-row convention while independently
reconstructing that sole endpoint with a newly generated subgroup generator,
secret exponent, public key, and signing split.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path

from reproducer.independent import main


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(raw: dict) -> dict:
    controls_reject = all(
        item["accepted"] is False for item in raw["negative_controls"].values()
    )
    checks = {
        "fixed_target_same_s_forgery_accepted": raw["forgery_same_s"]["accepted"],
        "fresh_key_material": raw["endpoint"]["fresh_key_material"],
        "honest_signature_accepted": raw["honest_signature"]["accepted"],
        "messages_distinct": raw["messages_distinct"],
        "negative_controls_rejected": controls_reject,
        "prime_checks_pass": all(raw["parameter_probable_prime_checks"].values()),
        "range_sampled_forgery_accepted": raw["forgery_range_sampled"]["accepted"],
        "range_sampled_scalar_in_phi_range": raw["forgery_range_sampled"]["s_in_actual_phi_range_observer_check"],
        "result_pass": raw["result"] == "PASS",
    }
    root = Path(__file__).resolve().parent
    return {
        "all_rows_pass": all(checks.values()),
        "digests": {
            "independent_core_sha256": sha256_file(root / "reproducer" / "independent.py"),
            "target_pdf_sha256": "a8b4eae608a28baf86e585fb19056a43881d3c386eae6f7fb6b2cf1d2d49c65f",
            "target_source_archive_sha256": "d67435736b459ef85c705dd726763204ac6400b3c3c9058ac2a2b2e25011ae86",
        },
        "results": [
            {
                "all_expected_checks_pass": all(checks.values()),
                "checks": checks,
                "parameter_row": "published 1023/1024-bit factors; 2046-bit n; 2048-bit field",
                "raw_result": raw,
                "signing_queries": 1,
            }
        ],
    }


def run() -> None:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        main()
    raw = json.loads(captured.getvalue())
    print(json.dumps(summarize(raw), indent=2, sort_keys=True))


if __name__ == "__main__":
    run()
