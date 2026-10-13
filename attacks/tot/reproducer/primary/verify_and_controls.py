#!/usr/bin/env python3
"""Ordinary public verifier plus fixed negative controls."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from tot_public import decode_vector, read_public_key, write_json


def verify(public_key, message: int, signature: int) -> bool:
    # This is exactly the paper/patent verification equation P(sigma)=M.
    return public_key.evaluate(signature) == message


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--pair", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()

    public_key = read_public_key(args.public_key)
    pair = json.loads(args.pair.read_text())
    message = decode_vector(pair["message_little_endian_hex"])
    signature = decode_vector(pair["signature_little_endian_hex"])

    started = time.perf_counter_ns()
    forged_accepts = verify(public_key, message, signature)
    changed_message_rejects = not verify(public_key, message ^ 1, signature)
    changed_signature_rejects = not verify(public_key, message, signature ^ 1)
    swapped_fields_rejects = not verify(public_key, signature, message)

    # Mutating the constant coefficient changes P(sigma) unconditionally.
    # This is a public-key integrity control, not part of the attack.
    mutated_public_key = type(public_key)(
        public_key.n,
        public_key.constant ^ 1,
        public_key.linear,
        public_key.quadratic,
    )
    mutated_key_rejects = not verify(mutated_public_key, message, signature)
    elapsed_ns = time.perf_counter_ns() - started

    controls = {
        "changed_message": changed_message_rejects,
        "changed_signature": changed_signature_rejects,
        "swapped_fields": swapped_fields_rejects,
        "mutated_public_key": mutated_key_rejects,
    }
    status = "PASS" if forged_accepts and all(controls.values()) else "FAIL"
    write_json(
        args.results,
        {
            "status": status,
            "ordinary_verifier_equation": "P(sigma) == M",
            "forged_pair_accepted": forged_accepts,
            "negative_controls": controls,
            "negative_control_rejects": sum(controls.values()),
            "negative_control_count": len(controls),
            "verification_and_controls_elapsed_ns": elapsed_ns,
        },
    )
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
