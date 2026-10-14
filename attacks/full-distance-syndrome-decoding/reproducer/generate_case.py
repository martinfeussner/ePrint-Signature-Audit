#!/usr/bin/env python3
"""Generate one fresh full-parameter FDSD Level-I public attack case.

The fresh seed and secret key remain in this process and are never written.
Only the public key and one ordinary signature cross the attack boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from fdsd_reference import (
    D,
    ELL,
    EPSILON,
    K,
    L,
    N,
    ROWS,
    THETA,
    keygen,
    pack_matrix_row_major,
    pack_vector,
    public_key_fingerprint,
    sign,
    verify,
)


QUERY_MESSAGE = b"FDSD public reproducer: sole ordinary signing query, v1"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(output: Path) -> dict[str, object]:
    started = time.monotonic()
    output.mkdir(parents=True, exist_ok=False)

    # This is the only source of secret material. Neither value is serialized.
    seed = os.urandom(32)
    public_key, secret_key, evidence = keygen(seed)
    message_hash, sigma, zeta = sign(secret_key, QUERY_MESSAGE)
    if not verify(public_key, QUERY_MESSAGE, sigma, zeta):
        raise AssertionError("fresh ordinary signature failed verification")
    if sigma.bit_count() != D:
        raise AssertionError("fresh ordinary signature has the wrong weight")

    hstar = pack_matrix_row_major(public_key.hstar_columns, ROWS, N)
    r_matrix = pack_matrix_row_major(public_key.r_columns, ROWS, L)
    (output / "Hstar.bin").write_bytes(hstar)
    (output / "R.bin").write_bytes(r_matrix)

    public_metadata = {
        "schema_version": 1,
        "target": "Full-Distance Syndrome Decoding, ePrint 2023/1956",
        "profile": "Level I",
        "parameters": {
            "n": N,
            "k": K,
            "rows": ROWS,
            "L": L,
            "epsilon": EPSILON,
            "theta": THETA,
            "d": D,
            "ell": ELL,
        },
        "Hstar": {
            "path": "Hstar.bin",
            "rows": ROWS,
            "columns": N,
            "bytes": len(hstar),
            "sha256": digest(hstar),
        },
        "R": {
            "path": "R.bin",
            "rows": ROWS,
            "columns": L,
            "bytes": len(r_matrix),
            "sha256": digest(r_matrix),
        },
        "public_key_fingerprint_sha256": public_key_fingerprint(public_key),
        "source": {
            "kind": "independent paper-level mathematical reconstruction",
            "author_implementation_available": False,
            "paper_pdf_sha256": "394b7a3e4f8d935cfabffd90e17b4c8cdd5708267a14ede67b39c49ab9ead822",
        },
    }
    write_json(output / "public-key.json", public_metadata)

    query = {
        "index": 0,
        "message_hex": QUERY_MESSAGE.hex(),
        "hash_125_hex": pack_vector(message_hash, L).hex(),
        "sigma_hex": pack_vector(sigma, N).hex(),
        "zeta_hex": pack_vector(zeta, THETA).hex(),
    }
    (output / "signatures.jsonl").write_text(
        json.dumps(query, sort_keys=True) + "\n"
    )

    summary = {
        "status": "PASS",
        "profile": "FDSD Level I (1600,400,125,5,25,343)",
        "public_key_fingerprint_sha256": public_metadata[
            "public_key_fingerprint_sha256"
        ],
        "ordinary_signatures_exported": 1,
        "ordinary_signature_verified": True,
        "seed_source": "os.urandom(32)",
        "seed_persisted": False,
        "secret_key_persisted": False,
        "secret_coordinate_labels_persisted": False,
        "basic_identity_checks": evidence.basic_identity_checks,
        "advanced_identity_checks": evidence.advanced_identity_checks,
        "elapsed_seconds": time.monotonic() - started,
    }
    # This summary is public and contains no seed, secret key, or labels.
    write_json(output / "generation-summary.json", summary)
    return summary


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    result = run(args.output.resolve())
    print(json.dumps(result, sort_keys=True))
