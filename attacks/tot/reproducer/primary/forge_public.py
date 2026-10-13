#!/usr/bin/env python3
"""Zero-query existential forgery against TOT's literal raw-vector API."""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

from tot_public import encode_vector, read_public_key, sha256_file, write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--query-transcript", type=Path, required=True)
    args = parser.parse_args()

    if args.query_transcript.read_bytes() != b"":
        raise ValueError("the sealed signing-query transcript is not empty")

    started = time.perf_counter_ns()
    public_key = read_public_key(args.public_key)
    # This fixed nonzero sigma is selected without looking at a secret key,
    # signing transcript, or target message.
    signature = int.from_bytes(
        hashlib.sha256(b"TOT-2013-771/raw-vector-forgery/v1").digest()[:16],
        "little",
    )
    message = public_key.evaluate(signature)
    elapsed_ns = time.perf_counter_ns() - started
    if not signature or not message:
        raise AssertionError("sealed nonzero-candidate requirement failed")

    write_json(
        args.output,
        {
            "scheme": "TOT ePrint 2013/771",
            "parameter_row": {"q": 2, "n": 128, "d": 6, "t": 64},
            "scope": "literal raw F_2^128 message-vector interface",
            "attack": "choose sigma, compute M=P(sigma), output (M,sigma)",
            "signing_queries": 0,
            "message_little_endian_hex": encode_vector(message),
            "signature_little_endian_hex": encode_vector(signature),
            "public_key_sha256": sha256_file(args.public_key),
            "attack_elapsed_ns_including_public_key_parse": elapsed_ns,
        },
    )


if __name__ == "__main__":
    main()
