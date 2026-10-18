#!/usr/bin/env python3
"""Deterministic multi-key check of the Definition 33 algebraic model."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reproduce import (
    CHANGED_MESSAGE,
    FRESH_MESSAGE,
    G1_GENERATOR,
    G2_GENERATOR,
    ORDER,
    hash_to_g2,
    is_valid_nonidentity_g1,
    is_valid_nonidentity_g2,
    scalar_mul_g1,
    scalar_mul_g2,
    verify,
)


TRIALS = 32


def run_trials() -> dict[str, object]:
    counters = {
        "aggregate_cancellations": 0,
        "attack_acceptances": 0,
        "changed_message_rejections": 0,
        "changed_signature_rejections": 0,
        "honest_key_substitution_rejections": 0,
        "valid_nonidentity_rogue_keys": 0,
        "valid_nonidentity_aggregate_keys": 0,
        "valid_nonidentity_signatures": 0,
    }

    for trial in range(TRIALS):
        honest_secret = int.from_bytes(
            hashlib.sha256(f"definition-33-all-rows-honest-{trial}".encode()).digest(),
            "big",
        ) % ORDER
        if honest_secret == 0:
            honest_secret = 1
        vk_a = scalar_mul_g1(honest_secret, G1_GENERATOR)

        beta = 0xB15000 + trial
        beta_key = scalar_mul_g1(beta, G1_GENERATOR)
        if beta_key == vk_a:
            beta += 1
            beta_key = scalar_mul_g1(beta, G1_GENERATOR)
        vk_e = beta_key - vk_a
        aggregate_key = vk_a + vk_e

        message = FRESH_MESSAGE + b" / trial " + str(trial).encode()
        signature = scalar_mul_g2(beta, hash_to_g2(message))
        changed_signature = signature + G2_GENERATOR
        replacement = scalar_mul_g1(honest_secret + 1, G1_GENERATOR)

        counters["aggregate_cancellations"] += aggregate_key == beta_key
        counters["attack_acceptances"] += verify(aggregate_key, message, signature)
        counters["changed_message_rejections"] += not verify(
            aggregate_key, CHANGED_MESSAGE + str(trial).encode(), signature
        )
        counters["changed_signature_rejections"] += not verify(
            aggregate_key, message, changed_signature
        )
        counters["honest_key_substitution_rejections"] += not verify(
            replacement + vk_e, message, signature
        )
        counters["valid_nonidentity_rogue_keys"] += is_valid_nonidentity_g1(vk_e)
        counters["valid_nonidentity_aggregate_keys"] += is_valid_nonidentity_g1(
            aggregate_key
        )
        counters["valid_nonidentity_signatures"] += is_valid_nonidentity_g2(signature)

    passed = all(value == TRIALS for value in counters.values())
    return {
        "all_rows_pass": passed,
        "results": [
            {
                "all_expected_checks_pass": passed,
                "counts": counters,
                "parameter_row": "BLS12-381-G1PK-G2SIG-SHA256-XMD-DEFINITION33",
                "signing_queries_per_trial": 0,
                "trials": TRIALS,
            }
        ],
        "scope": "ePrint 2026/1394 Definition 33 chosen-key DS2 interface only",
    }


def canonical(result: dict[str, object]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", action="store_true")
    args = parser.parse_args()
    rendered = canonical(run_trials())
    if args.reference:
        expected = Path(__file__).with_name("all-rows-reference-output.json").read_text()
        if rendered != expected:
            raise SystemExit("all-rows-reference-output.json does not match")
    print(rendered, end="")


if __name__ == "__main__":
    main()
