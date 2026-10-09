#!/usr/bin/env python3
"""Run the separately structured deterministic full-row reproduction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from reproducer.independent import run_audit


ROOT = Path(__file__).resolve().parent


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(raw: dict) -> dict:
    results = []
    for row in raw["rows"]:
        variants = row["variants"]
        checks = {
            "algorithm3_count_matches": row["algorithm3_exact"],
            "both_forgery_variants_accept": all(
                item["ordinary_verifier"]["accepted"] for item in variants
            ),
            "changed_signature_controls_reject": all(
                not item["changed_signature_control"]["accepted"]
                for item in variants
            ),
            "format_controls_reject": all(
                not control["accepted"]
                for item in variants
                for control in item["format_controls"].values()
            ),
            "invalid_block_controls_reject": all(
                not item["one_invalid_block_control"]["accepted"]
                for item in variants
            ),
            "public_only_zero_query_boundary": (
                not row["private_material_passed_to_forge"]
                and all(item["signing_queries"] == 0 for item in variants)
            ),
        }
        dimensions = row["dimensions"]
        results.append(
            {
                "all_expected_checks_pass": all(checks.values()),
                "checks": checks,
                "message_sha256": {
                    item["name"]: item["message_sha256"] for item in variants
                },
                "parameter_row": (
                    f"{row['profile']}: n={dimensions['n']}, k={dimensions['k']}, "
                    f"ell={dimensions['ell']}, s={dimensions['s']}"
                ),
                "public_key_sha256": row["public_key_sha256"],
                "valid_error_splits": row["valid_error_splits"],
            }
        )
    if not all(item["all_expected_checks_pass"] for item in results):
        raise RuntimeError("one or more independent reproduction checks failed")
    return {
        "all_rows_pass": True,
        "attack": {
            "message_scope": "fresh attacker-chosen raw z tuple in Algorithms 5-6",
            "result": "zero-query existential forgery for the literal raw-z interface",
            "signing_queries": 0,
        },
        "digests": {
            "independent_core_sha256": sha256_file(
                ROOT / "reproducer" / "independent.py"
            ),
            "target_pdf_sha256": raw["target"]["pdf_sha256"],
            "target_text_sha256": raw["target"]["text_sha256"],
        },
        "environment": {
            "language": "Python 3 standard library",
            "workers": 1,
        },
        "result": "PASS: independent deterministic reproduction passes both full rows",
        "results": results,
        "scope_exclusion": raw["scope_exclusion"],
    }


def main() -> int:
    print(json.dumps(summarize(run_audit()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
