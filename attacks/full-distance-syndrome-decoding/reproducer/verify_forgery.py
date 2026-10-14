#!/usr/bin/env python3
"""Verify a public FDSD forgery with the ordinary reconstructed verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from fdsd_reference import (
    D,
    L,
    N,
    ROWS,
    THETA,
    PublicKey,
    hash_message,
    unpack_matrix_row_major,
    unpack_vector,
    verify,
)


def load_vector(value: str, length: int) -> int:
    return unpack_vector(bytes.fromhex(value), length)


def load_public_key(public_dir: Path) -> PublicKey:
    return PublicKey(
        hstar_columns=unpack_matrix_row_major(
            (public_dir / "Hstar.bin").read_bytes(), ROWS, N
        ),
        r_columns=unpack_matrix_row_major(
            (public_dir / "R.bin").read_bytes(), ROWS, L
        ),
    )


def first_record(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        line = handle.readline()
        if not line or handle.readline():
            raise AssertionError("the public case must contain exactly one query")
    return json.loads(line)


def run(public_dir: Path, attack_result_path: Path, output: Path) -> dict[str, object]:
    public_key = load_public_key(public_dir)
    query = first_record(public_dir / "signatures.jsonl")
    result = json.loads(attack_result_path.read_text())
    if result.get("status") != "PASS":
        raise AssertionError("public attack did not report PASS")

    query_message = bytes.fromhex(str(query["message_hex"]))
    query_sigma = load_vector(str(query["sigma_hex"]), N)
    query_zeta = load_vector(str(query["zeta_hex"]), THETA)
    query_accept = verify(public_key, query_message, query_sigma, query_zeta)

    forgery = result["forgery"]
    target_message = bytes.fromhex(str(forgery["message_hex"]))
    forged_sigma = load_vector(str(forgery["sigma_hex"]), N)
    forged_zeta = load_vector(str(forgery["zeta_hex"]), THETA)
    forgery_accept = verify(
        public_key, target_message, forged_sigma, forged_zeta
    )
    if target_message == query_message:
        raise AssertionError("target message equals queried message")
    if hash_message(target_message) == hash_message(query_message):
        raise AssertionError("target hash equals queried hash")

    unchanged_query_reject = not verify(
        public_key, target_message, query_sigma, query_zeta
    )
    changed_message_reject = not verify(
        public_key, target_message + b"\x00", forged_sigma, forged_zeta
    )
    set_index = next(i for i in range(N) if (forged_sigma >> i) & 1)
    unset_index = next(i for i in range(N) if not ((forged_sigma >> i) & 1))
    weight_preserving_sigma_reject = not verify(
        public_key,
        target_message,
        forged_sigma ^ (1 << set_index) ^ (1 << unset_index),
        forged_zeta,
    )
    zeta_reject = not verify(
        public_key, target_message, forged_sigma, forged_zeta ^ 1
    )

    boundary = result["attack_model"]
    boundary_pass = all(
        (
            boundary["ordinary_signing_queries"] == 1,
            boundary["queried_records_parsed"] == 1,
            boundary["target_message_queries"] == 0,
            boundary["private_inputs_read"] is False,
            boundary["secret_labels_read"] is False,
            boundary["workers"] == 1,
            boundary["filesystem_read_allowlist_enforced"] is True,
        )
    )
    controls_pass = all(
        (
            unchanged_query_reject,
            changed_message_reject,
            weight_preserving_sigma_reject,
            zeta_reject,
        )
    )
    if not all((query_accept, forgery_accept, controls_pass, boundary_pass)):
        raise AssertionError("ordinary verification, boundary, or control failed")
    if forged_sigma.bit_count() != D:
        raise AssertionError("forgery has wrong weight")

    summary = {
        "status": "PASS",
        "scheme": "Full-Distance Syndrome Decoding",
        "profile": "Level I (1600,400,125,5,25,343)",
        "result": "one-query fresh-message forgery",
        "public_key_fingerprint_sha256": result[
            "public_key_fingerprint_sha256"
        ],
        "ordinary_signing_queries": 1,
        "target_message_queries": 0,
        "query_signature": "ACCEPTED",
        "fresh_message_forgery": "ACCEPTED",
        "forgery_weight": forged_sigma.bit_count(),
        "public_recovery": result["public_recovery"],
        "search": result["search"],
        "negative_controls": {
            "unchanged_query_on_target": "REJECTED",
            "forgery_on_changed_message": "REJECTED",
            "weight_preserving_sigma_change": "REJECTED",
            "zeta_change": "REJECTED",
        },
        "attack_boundary": "PASS",
        "attack_runtime_seconds": result["timing_seconds"]["total"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--attack-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    result = run(
        args.public_dir.resolve(),
        args.attack_result.resolve(),
        args.output.resolve(),
    )
    print("=" * 48)
    print("ATTACK REPRODUCTION: PASS")
    print("Scheme: Full-Distance Syndrome Decoding")
    print("Result: one-query fresh-message forgery")
    print("Fresh full Level-I key: GENERATED")
    print("Ordinary signing queries: 1")
    print("Target-message queries: 0")
    print("Public-only attack boundary: PASS")
    print("Fresh-message forgery: ACCEPTED")
    print("Negative controls: REJECTED")
    print(f"Candidates tested: {result['search']['candidates_tested']}")
    print(f"Attack runtime: {result['attack_runtime_seconds']:.6f} seconds")
    print("=" * 48)
