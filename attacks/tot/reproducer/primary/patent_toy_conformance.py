#!/usr/bin/env python3
"""Replay the same-authors patent's q=2,n=4 public verifier vector."""

from __future__ import annotations

import argparse
from pathlib import Path

from tot_public import write_json


def bit(value: int, index: int) -> int:
    return (value >> index) & 1


def patent_public_map(signature: int) -> int:
    x1, x2, x3, x4 = (bit(signature, i) for i in range(4))
    p1 = x1*x2 ^ x1*x3 ^ x2*x3 ^ x2 ^ x3*x4 ^ x3 ^ 1
    p2 = x1*x2 ^ x3 ^ x2*x3 ^ x2 ^ x3*x4 ^ x4 ^ 1
    p3 = x1*x3 ^ x2*x4 ^ x4
    p4 = x1*x3 ^ x1*x4 ^ x1 ^ x2*x3 ^ x3 ^ 1
    return p1 | (p2 << 1) | (p3 << 2) | (p4 << 3)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    signature = 0b1111
    expected_message = 0b0111
    actual_message = patent_public_map(signature)
    honest_accepts = actual_message == expected_message
    changed_message_rejects = actual_message != (expected_message ^ 1)
    status = "PASS" if honest_accepts and changed_message_rejects else "FAIL"
    write_json(
        args.results,
        {
            "status": status,
            "parameter_row": {"q": 2, "n": 4, "d": 4, "t": 8},
            "patent_signature": [1, 1, 1, 1],
            "patent_message": [1, 1, 1, 0],
            "ordinary_verifier_accepts": honest_accepts,
            "changed_message_rejects": changed_message_rejects,
        },
    )
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
