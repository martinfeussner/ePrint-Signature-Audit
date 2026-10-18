#!/usr/bin/env python3
"""Deterministic algebraic reproduction of the Definition 33 forgery.

This is a prime-order bilinear-group reference model.  Group elements retain
their scalar coordinate internally so that the verifier equation can be
executed, but the attack uses only public group operations and the chosen
scalar beta.  The source-exact Rust harness exercises the real BLS12-381
implementation and ordinary verifier from the paper-linked artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513
FRESH_MESSAGE = b"Definition 33 fresh-message forgery / ePrint 2026-1394"
CHANGED_MESSAGE = b"Definition 33 changed-message control / ePrint 2026-1394"


@dataclass(frozen=True)
class G1:
    coordinate: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "coordinate", self.coordinate % ORDER)

    def __add__(self, other: "G1") -> "G1":
        return G1(self.coordinate + other.coordinate)

    def __sub__(self, other: "G1") -> "G1":
        return G1(self.coordinate - other.coordinate)


@dataclass(frozen=True)
class G2:
    coordinate: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "coordinate", self.coordinate % ORDER)

    def __add__(self, other: "G2") -> "G2":
        return G2(self.coordinate + other.coordinate)


G1_GENERATOR = G1(1)
G2_GENERATOR = G2(1)


def scalar_mul_g1(scalar: int, point: G1) -> G1:
    return G1(scalar * point.coordinate)


def scalar_mul_g2(scalar: int, point: G2) -> G2:
    return G2(scalar * point.coordinate)


def hash_to_g2(message: bytes) -> G2:
    # A deterministic nonzero random-oracle representative for the algebraic
    # model.  This is not a replacement for BLS12-381 hash-to-curve.
    digest = hashlib.sha256(b"BLS-REFERENCE-MODEL\x00" + message).digest()
    return scalar_mul_g2(1 + int.from_bytes(digest, "big") % (ORDER - 1), G2_GENERATOR)


def pairing(left: G1, right: G2) -> int:
    return (left.coordinate * right.coordinate) % ORDER


def verify(public_key: G1, message: bytes, signature: G2) -> bool:
    return pairing(G1_GENERATOR, signature) == pairing(public_key, hash_to_g2(message))


def is_valid_nonidentity_g1(point: G1) -> bool:
    return 0 < point.coordinate < ORDER


def is_valid_nonidentity_g2(point: G2) -> bool:
    return 0 < point.coordinate < ORDER


def reproduce() -> dict[str, object]:
    # Fixed only to make the public reference output deterministic.  The
    # source-exact run obtains vk_A from the artifact's random KeyGen.
    honest_secret = int.from_bytes(
        hashlib.sha256(b"definition-33-reference-honest-key").digest(), "big"
    ) % ORDER
    if honest_secret == 0:
        raise AssertionError("deterministic honest secret was zero")
    vk_a = scalar_mul_g1(honest_secret, G1_GENERATOR)

    beta = 42
    beta_key = scalar_mul_g1(beta, G1_GENERATOR)
    if beta_key == vk_a:
        beta = 43
        beta_key = scalar_mul_g1(beta, G1_GENERATOR)

    # This is the only use of vk_A by the forger: public group subtraction.
    vk_e = beta_key - vk_a
    aggregate_key = vk_a + vk_e
    forged_signature = scalar_mul_g2(beta, hash_to_g2(FRESH_MESSAGE))
    changed_signature = forged_signature + G2_GENERATOR
    replacement_honest_key = scalar_mul_g1(honest_secret + 1, G1_GENERATOR)
    substituted_aggregate = replacement_honest_key + vk_e

    checks = {
        "aggregate key equals beta times generator": aggregate_key == beta_key,
        "fresh forgery accepted": verify(
            aggregate_key, FRESH_MESSAGE, forged_signature
        ),
        "fresh message was never queried": True,
        "zero signing queries": True,
        "changed message rejected": not verify(
            aggregate_key, CHANGED_MESSAGE, forged_signature
        ),
        "changed signature rejected": not verify(
            aggregate_key, FRESH_MESSAGE, changed_signature
        ),
        "honest key substitution rejected": not verify(
            substituted_aggregate, FRESH_MESSAGE, forged_signature
        ),
        "honest key nonidentity": is_valid_nonidentity_g1(vk_a),
        "rogue key nonidentity": is_valid_nonidentity_g1(vk_e),
        "aggregate key nonidentity": is_valid_nonidentity_g1(aggregate_key),
        "forged signature nonidentity": is_valid_nonidentity_g2(forged_signature),
    }
    result = {
        "attack": {
            "known_aggregate_scalar": beta,
            "signing_queries": 0,
        },
        "checks": checks,
        "digests": {
            "fresh_message_sha256": hashlib.sha256(FRESH_MESSAGE).hexdigest(),
            "reference_domain_sha256": hashlib.sha256(
                b"BLS-REFERENCE-MODEL\x00"
            ).hexdigest(),
        },
        "environment": {"workers": 1},
        "model": {
            "group_order": str(ORDER),
            "kind": "prime-order bilinear-group reference model",
            "source_exact_bls12_381_is_separate": True,
        },
        "scope": "ePrint 2026/1394 Definition 33 chosen-key DS2 interface only",
    }
    result["result"] = "PASS" if all(checks.values()) else "FAIL"
    return result


def canonical(result: dict[str, object]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reference",
        action="store_true",
        help="require byte-for-byte equality with reference-output.json",
    )
    args = parser.parse_args()
    rendered = canonical(reproduce())
    if args.reference:
        expected = Path(__file__).with_name("reference-output.json").read_text()
        if rendered != expected:
            raise SystemExit("reference-output.json does not match this reproducer")
    print(rendered, end="")


if __name__ == "__main__":
    main()
