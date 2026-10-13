#!/usr/bin/env python3
"""Fail closed and print one compact sealed-run summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tot_public import sha256_file, write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--forgery", type=Path, required=True)
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--toy", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--query-transcript", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    fixture = json.loads(args.fixture.read_text())
    forgery = json.loads(args.forgery.read_text())
    verification = json.loads(args.verification.read_text())
    toy = json.loads(args.toy.read_text())
    assertions = {
        "fixture_conformance_pass": fixture["status"] == "PASS",
        "exact_claimed_row": fixture["parameter_row"]
        == {"q": 2, "n": 128, "d": 6, "t": 64},
        "advertised_public_payload_bits": fixture["public_payload_bits"]
        == 1_073_280,
        "canonical_boolean_quadratic_form": fixture[
            "canonical_diagonal_nonzero"
        ]
        == 0,
        "frobenius_inverse_identity": fixture["inverse_exponent_identity"] == 1,
        "no_private_material_serialized": not fixture["private_material_serialized"],
        "public_key_hash_bound": forgery["public_key_sha256"]
        == sha256_file(args.public_key),
        "zero_signing_queries": forgery["signing_queries"] == 0
        and args.query_transcript.read_bytes() == b"",
        "ordinary_verifier_accepts": verification["forged_pair_accepted"],
        "all_negative_controls_reject": verification["negative_control_rejects"]
        == verification["negative_control_count"],
        "patent_toy_vector_accepts": toy["ordinary_verifier_accepts"],
        "patent_toy_control_rejects": toy["changed_message_rejects"],
    }
    status = "PASS" if all(assertions.values()) else "FAIL"
    result = {
        "status": status,
        "classification": "verified full-row zero-query raw-vector forgery",
        "scope": "literal raw F_2^128 message-vector interface only",
        "signing_queries": 0,
        "freshness_basis": "no message was submitted to a signing oracle",
        "forged_pair_accepted_by_ordinary_verifier": verification[
            "forged_pair_accepted"
        ],
        "negative_controls": verification["negative_controls"],
        "assertions": assertions,
        "attack_elapsed_ns": forgery["attack_elapsed_ns_including_public_key_parse"],
        "public_key_sha256": sha256_file(args.public_key),
        "forged_pair_sha256": sha256_file(args.forgery),
    }
    write_json(args.output, result)
    print("========================================")
    print(f"ATTACK REPRODUCTION: {status}")
    print("Parameter row: q=2, n=128, d=6, t=64")
    print("Signing queries: 0")
    print(
        "Fresh raw-message forgery: "
        + ("ACCEPTED" if verification["forged_pair_accepted"] else "REJECTED")
    )
    print(
        "Negative controls: "
        f"{verification['negative_control_rejects']}/"
        f"{verification['negative_control_count']} rejected"
    )
    print("Scope: literal raw F_2^128 message-vector API")
    print("========================================")
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
