#!/usr/bin/env python3
"""Run the deterministic primary full-row St-Gen reproduction.

The output intentionally excludes wall-clock measurements and process IDs so
that it is byte-for-byte reproducible.  Timing from the sealed audit run is
reported in the accompanying paper and README.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from reproducer.primary import run_audit


ROOT = Path(__file__).resolve().parent


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(raw: dict) -> dict:
    results = []
    for row in raw["rows"]:
        variants = row["variants"]
        checks = {
            "algorithm3_count_matches": row["algorithm3"]["exact_count_matches"],
            "both_forgery_variants_accept": all(
                item["ordinary_verifier"]["accepted"] for item in variants
            ),
            "complete_valid_split_set_covered": all(
                item["all_public_valid_splits_covered"] for item in variants
            ),
            "format_controls_reject": all(
                not control["accepted"]
                for item in variants
                for control in item["format_controls"].values()
            ),
            "one_invalid_block_controls_reject": all(
                not item["one_invalid_block_control"]["accepted"]
                for item in variants
            ),
            "public_only_zero_query_boundary": (
                not row["private_key_passed_to_forge"]
                and all(item["signing_queries"] == 0 for item in variants)
                and all(not item["private_inputs_used"] for item in variants)
            ),
            "separate_signer_correctness_witness_rejects": (
                not row["separate_signer_correctness_issue"]["ordinary_verifier"][
                    "accepted"
                ]
            ),
        }
        dimensions = row["printed_dimensions"]
        results.append(
            {
                "all_expected_checks_pass": all(checks.values()),
                "checks": checks,
                "fresh_raw_message_sha256": {
                    item["name"]: item["fresh_raw_message_sha256"]
                    for item in variants
                },
                "parameter_row": (
                    f"{row['parameter_set']}: n={dimensions['n']}, "
                    f"k={dimensions['k']}, ell={dimensions['ell']}, s=2"
                ),
                "public_key_sha256": row["public_key_sha256"],
                "valid_error_splits": row["algorithm3"][
                    "derived_valid_error_splits"
                ],
            }
        )

    checks = {
        "all_four_forgery_variants_accept": raw["summary_checks"][
            "all_forgery_variants_accept"
        ],
        "all_four_invalid_block_controls_reject": raw["summary_checks"][
            "all_four_one_invalid_block_controls_reject"
        ],
        "all_format_controls_reject": raw["summary_checks"][
            "all_format_controls_reject"
        ],
        "both_full_printed_rows_pass": all(
            item["all_expected_checks_pass"] for item in results
        ),
        "positive_blocks_checked_is_2550": raw["summary_checks"][
            "total_positive_blocks_checked"
        ]
        == 2550,
        "zero_signing_queries": raw["attack_model"]["signing_queries"] == 0,
    }
    if not all(checks.values()):
        raise RuntimeError("one or more normalized primary checks failed")
    return {
        "attack": {
            "message_scope": "fresh attacker-chosen raw z tuple in Algorithms 5-6",
            "result": "zero-query existential forgery for the literal raw-z interface",
            "signing_queries": 0,
        },
        "checks": checks,
        "digests": {
            "primary_core_sha256": sha256_file(ROOT / "reproducer" / "primary.py"),
            "target_pdf_sha256": raw["target"]["pdf_sha256"],
            "target_text_sha256": raw["target"]["text_sha256"],
        },
        "environment": {
            "language": "Python 3 standard library",
            "workers": 1,
        },
        "result": "PASS: both full rows accept zero- and nonzero-sigma raw-z forgeries",
        "results": results,
        "scope_exclusion": (
            "No claim is made for arbitrary documents or for an unspecified "
            "external document-to-z hash wrapper."
        ),
    }


def main() -> int:
    print(json.dumps(summarize(run_audit()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
