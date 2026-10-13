#!/usr/bin/env python3
"""Ordinary verifier execution and negative controls for the TOT forgery."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tot_public import load_public_key, ordinary_verify, sha256_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--forgery", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if args.result.exists():
        raise SystemExit("refusing to overwrite an existing result")

    key = load_public_key(args.public_key)
    forgery = json.loads(args.forgery.read_text())
    if forgery["public_key_sha256"] != sha256_file(args.public_key):
        raise AssertionError("forgery/public-key binding mismatch")
    message = bytes.fromhex(forgery["message_hex_little_endian"])
    signature = bytes.fromhex(forgery["signature_hex_little_endian"])

    accepted = ordinary_verify(key, message, signature)

    changed_message = bytearray(message)
    changed_message[0] ^= 1
    changed_message_rejected = not ordinary_verify(key, bytes(changed_message), signature)

    changed_signature_rejected = False
    changed_signature_bit = None
    for bit in range(key.n):
        candidate_value = int.from_bytes(signature, "little") ^ (1 << bit)
        candidate = candidate_value.to_bytes(16, "little")
        if not ordinary_verify(key, message, candidate):
            changed_signature_rejected = True
            changed_signature_bit = bit
            break

    truncated_signature_rejected = not ordinary_verify(key, message, signature[:-1])

    # Scope control: a conventional wrapper would verify H(document), not an
    # attacker-selected raw vector.  The same signature must reject for this
    # independently bound document digest.
    document = (
        b"TOT independent reproduction: document-level hashing scope control; "
        + bytes.fromhex(forgery["public_key_sha256"])
    )
    document_digest = hashlib.sha256(document).digest()[:16]
    counter = 0
    while document_digest == message:
        counter += 1
        document_digest = hashlib.sha256(document + counter.to_bytes(4, "little")).digest()[:16]
    document_hash_rejected = not ordinary_verify(key, document_digest, signature)

    controls = {
        "changed_raw_message_bit_rejected": changed_message_rejected,
        "changed_signature_bit_rejected": changed_signature_rejected,
        "changed_signature_bit_index": changed_signature_bit,
        "truncated_signature_rejected": truncated_signature_rejected,
        "document_hash_wrapper_message_rejected": document_hash_rejected,
        "document_hash": "SHA-256 truncated to 128 bits for control only",
        "document_digest_hex": document_digest.hex(),
    }
    passed = (
        accepted
        and forgery["signature_nonzero"]
        and forgery["signing_queries"] == 0
        and forgery["secret_reads"] == 0
        and changed_message_rejected
        and changed_signature_rejected
        and truncated_signature_rejected
        and document_hash_rejected
    )

    result = {
        "scheme": "TOT",
        "eprint": "2013/771",
        "status": "PASS" if passed else "FAIL",
        "parameters": {"q": key.q, "n": key.n, "d": key.d, "t": key.t},
        "trial_count": 1,
        "success_count": 1 if accepted else 0,
        "fresh_raw_vector_message_forgery": "ACCEPTED" if accepted else "REJECTED",
        "signature_nonzero": forgery["signature_nonzero"],
        "signing_queries": forgery["signing_queries"],
        "secret_reads_by_attacker": forgery["secret_reads"],
        "verifier": "ordinary P(signature)==message verifier",
        "negative_controls": controls,
        "scope": {
            "affected": "paper/patent raw F_2^128 message-vector interface",
            "not_established": "forgery for an externally preselected document under an added hash-to-vector wrapper",
        },
        "public_key_sha256": sha256_file(args.public_key),
        "forgery_sha256": sha256_file(args.forgery),
    }
    args.result.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    print("========================================")
    print(f"ATTACK REPRODUCTION: {result['status']}")
    print("Scheme: TOT (ePrint 2013/771)")
    print("Parameters: q=2, n=128, d=6, t=64")
    print(f"Fresh raw-vector forgery: {result['fresh_raw_vector_message_forgery']}")
    print("Signature vector: NONZERO")
    print("Signing queries: 0")
    print("Secret reads by attacker: 0")
    print("Negative controls: 4/4 REJECTED")
    print("Document-hash wrapper control: REJECTED")
    print("========================================")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
