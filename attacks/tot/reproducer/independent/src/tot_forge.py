#!/usr/bin/env python3
"""Public-only, zero-query existential forger for TOT's raw-vector API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tot_public import evaluate_public, load_public_key, sha256_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--forgery", required=True, type=Path)
    args = parser.parse_args()
    if args.forgery.exists():
        raise SystemExit("refusing to overwrite an existing forgery")

    key = load_public_key(args.public_key)
    signature = 0
    while signature == 0:
        signature = int.from_bytes(secrets.token_bytes(key.n // 8), "little")
    message = evaluate_public(key, signature)

    record = {
        "scheme": "TOT",
        "eprint": "2013/771",
        "parameters": {"q": key.q, "n": key.n, "d": key.d, "t": key.t},
        "interface": "raw_vector_F2^128",
        "construction": "choose fresh nonzero signature sigma; set message=P(sigma)",
        "signature_hex_little_endian": signature.to_bytes(16, "little").hex(),
        "message_hex_little_endian": message.to_bytes(16, "little").hex(),
        "signature_nonzero": signature != 0,
        "signing_queries": 0,
        "secret_reads": 0,
        "attacker_inputs": [str(args.public_key)],
        "public_key_sha256": sha256_file(args.public_key),
        "freshness_basis": "zero signing queries; this raw message was never submitted to a signer",
    }
    args.forgery.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "stage": "public_only_forgery",
                "status": "PASS",
                "signature_nonzero": True,
                "signing_queries": 0,
                "secret_reads": 0,
                "public_key_sha256": record["public_key_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
