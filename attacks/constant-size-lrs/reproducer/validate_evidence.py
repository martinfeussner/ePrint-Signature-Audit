#!/usr/bin/env python3
"""Independent structural validator for the frozen LRS evidence JSON.

This intentionally does not import reproduce.py.  It checks the public KGO
mapping, pair-swap arithmetic, and reported verifier/control predicates from
the emitted evidence alone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
N = 1024
PAIR_COUNT = 254
PROFILE = "eprint-2025-1174-v2-bn254-babyjubjub-mimc91-n1024-m1024"
MESSAGE = "ePrintAuditV4/lrs-2025-1174/exp-0001/fresh-message"
SCOPE = "ePrintAuditV4/lrs-2025-1174/exp-0001/scope"
MIMC_SHA256 = "511bf6471eadfc7c4c17a96820bb6902f2262acfad7d285421d428db3b3c71c8"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def decimal(value: object, name: str) -> int:
    require(isinstance(value, str), f"{name}: expected decimal string")
    require(re.fullmatch(r"0|[1-9][0-9]*", value) is not None, f"{name}: noncanonical decimal")
    result = int(value)
    require(0 <= result < Q, f"{name}: outside BN254 scalar field")
    return result


def load_constants(path: Path) -> list[int]:
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == MIMC_SHA256, "MiMC source hash mismatch")
    match = re.search(rb"var c\[91\]\s*=\s*\[(.*?)\];", raw, re.S)
    require(match is not None, "MiMC constants not found")
    constants = [int(x) for x in re.findall(rb"\d+", match.group(1))]
    require(len(constants) == 91 and constants[0] == 0, "unexpected MiMC constants")
    return constants


def mimc7(x: int, key: int, constants: list[int]) -> int:
    state = 0
    for index, constant in enumerate(constants):
        term = (key + x) % Q if index == 0 else (key + state + constant) % Q
        state = pow(term, 7, Q)
    return (state + key) % Q


def multi_mimc(a: int, b: int, constants: list[int]) -> int:
    state = 1
    for value in (a, b):
        state = (state + value + mimc7(value, state, constants)) % Q
    return state


def expected_predicates() -> dict[str, dict[str, bool]]:
    return {
        "positive": {
            "CPlink_honest_common_opening": True,
            "ccGro16_honest_relation": True,
            "ordinary_accept": True,
            "sma": True,
            "sma_eq15": True,
            "sma_kzg": True,
        },
        "pre_challenge_baseline": {
            "CPlink_honest_common_opening": True,
            "ccGro16_honest_relation": True,
            "ordinary_accept": False,
            "sma": False,
            "sma_eq15": False,
            "sma_kzg": True,
        },
        "flip_pair_0": {
            "CPlink_honest_common_opening": True,
            "ccGro16_honest_relation": True,
            "ordinary_accept": False,
            "sma": False,
            "sma_eq15": True,
            "sma_kzg": False,
        },
        "changed_message": {
            "CPlink_honest_common_opening": True,
            "ccGro16_honest_relation": True,
            "ordinary_accept": False,
            "sma": False,
            "sma_eq15": False,
            "sma_kzg": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("mimc_source", type=Path)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()

    raw = args.evidence.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if args.expected_sha256 is not None:
        require(digest == args.expected_sha256, "evidence SHA-256 mismatch")
    document = json.loads(raw)
    require(document.get("schema") == "eprint-audit-v4-lrs-1174-pair-swap-evidence-v1", "schema")
    require(document.get("profile") == PROFILE, "profile")
    require(document.get("message") == MESSAGE, "message")
    require(document.get("scope") == SCOPE, "scope")
    require(document.get("ring_size") == N, "ring size")
    require(document.get("attack_reproduction_pass") is True, "attack verdict")
    require(document.get("phi_star_absent") is True, "phi-star absence flag")
    require(document.get("nonzero_support_uncorrupted") is True, "support provenance flag")
    require(document.get("accepted_missing_coefficient") == "0", "accepted missing coefficient")
    require(decimal(document.get("baseline_missing_coefficient"), "baseline missing") != 0, "baseline unexpectedly zero")
    require(decimal(document.get("flip_pair_0_missing_coefficient"), "flipped missing") != 0, "flip unexpectedly zero")

    for name, expected in expected_predicates().items():
        require(document.get(name) == expected, f"{name}: predicate mismatch")

    attacker = document.get("attacker_public_key")
    require(isinstance(attacker, dict), "attacker public key")
    attacker_phi = decimal(attacker.get("phi"), "attacker phi")
    decimal(attacker.get("x"), "attacker x")
    decimal(attacker.get("y"), "attacker y")

    ring = document.get("ring")
    require(isinstance(ring, list) and len(ring) == N, "ring vector length")
    constants = load_constants(args.mimc_source)
    phis: list[int] = []
    coefficients: list[int] = []
    triples: set[tuple[int, int, int]] = set()
    for index, entry in enumerate(ring):
        require(isinstance(entry, dict), f"ring[{index}]")
        require(entry.get("position") == index + 1, f"ring[{index}] position")
        x = decimal(entry.get("pk_x"), f"ring[{index}].x")
        y = decimal(entry.get("pk_y"), f"ring[{index}].y")
        phi = decimal(entry.get("phi"), f"ring[{index}].phi")
        coefficient = decimal(entry.get("b"), f"ring[{index}].b")
        left = (168700 * x * x + y * y) % Q
        right = (1 + 168696 * x * x * y * y) % Q
        require(left == right, f"ring[{index}]: point is not on BabyJubJub")
        require(multi_mimc(x, y, constants) == phi, f"ring[{index}]: H_phi mismatch")
        require((x, y, phi) not in triples, f"ring[{index}]: duplicate public triple")
        triples.add((x, y, phi))
        phis.append(phi)
        coefficients.append(coefficient)

    require(len(set(phis)) == N, "ring phi values are not distinct")
    require(attacker_phi not in set(phis), "attacker phi is in ring")
    require(sum(value != 0 for value in coefficients) == PAIR_COUNT, "nonzero support count")
    require(all(coefficients[i] == 0 for i in range(2 * PAIR_COUNT, N)), "nonpair padding coefficient")

    bits = document.get("swap_bits_little_endian")
    require(isinstance(bits, str) and re.fullmatch(r"[01]{254}", bits) is not None, "swap bits")
    d_value = decimal(document.get("canonical_d"), "canonical d")
    require(sum((ord(bit) - 48) << j for j, bit in enumerate(bits)) == d_value, "canonical d bits")

    baseline_weighted = 0
    final_weighted = 0
    for j, bit in enumerate(bits):
        left_index, right_index = 2 * j, 2 * j + 1
        require(coefficients[right_index] == 0, f"pair {j}: partner coefficient")
        if bit == "0":
            a, c = phis[left_index], phis[right_index]
        else:
            a, c = phis[right_index], phis[left_index]
        require(a != c, f"pair {j}: equal hashes")
        expected_b = ((1 << j) * pow((a - c) % Q, Q - 2, Q)) % Q
        require(coefficients[left_index] == expected_b, f"pair {j}: coefficient formula")
        baseline_weighted = (baseline_weighted + expected_b * a) % Q
        final_weighted = (final_weighted + coefficients[left_index] * phis[left_index]) % Q
    require((baseline_weighted - final_weighted) % Q == d_value, "pair-swap residue")

    print(f"EVIDENCE_SHA256={digest}")
    print("RING_SIZE=1024")
    print("KGO_PUBLIC_MAPPING=PASS")
    print("PHI_VALUES_DISTINCT=PASS")
    print("PHI_STAR_ABSENT=PASS")
    print("PAIR_SWAP_ARITHMETIC=PASS")
    print("VERIFIER_PREDICATES=PASS")
    print("INDEPENDENT_EVIDENCE_VALIDATION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
