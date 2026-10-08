#!/usr/bin/env python3
"""Sanitized Bittersweet Level-I d=32 attack reproduction core.

This module implements the fixed S16/r160/plain-LLL/Babai attack against the
canonical expanded-matrix realization used in the reviewed experiments.  It
contains no stored candidate or secret key.  Quick mode consumes only a
public interval instance; full mode creates its own private truth locally.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import resource
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import strict_verify as verifier


PDF_SHA256 = "eefe27b903cb61fa50fecc33eef3fa99b121bece1c9831a4b3cab7bdebba5dbb"
REFERENCE_INTERVALS_SHA256 = "a45b63145c113df534eb553ef3c4df6ae4d83d4181eed923d101be25f4a94092"
Q_BITS, P_PRIME_BITS, ALPHA = 96, 3, 90
N, M, D, T = 11, 747, 32, 26
P_BITS = Q_BITS - P_PRIME_BITS
MODULUS = 1 << Q_BITS
MASK = MODULUS - 1
BUFFER_MASK = (1 << ALPHA) - 1
QUERY_COUNT = 16
SELECTED_ROWS = 160
FPYLLL_SEED = 20260412
LLL_DELTA = 0.99
LLL_ETA = 0.501
MODEL_SCOPE = (
    "Canonical random-oracle/XOF realization of exact ePrint 2026/397 v1 "
    "mathematics; no normative v1 wire format or public implementation exists."
)

FORBIDDEN_PUBLIC_NAMES = {
    "candidate_key_hex",
    "master_seed_hex",
    "oracle_randomness_hex",
    "private_state",
    "recovered_key_hex",
    "secret_k_hex",
    "secret_key_hex",
    "true_buffers",
    "unrounded_products_hex",
}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    state = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            state.update(block)
    return state.hexdigest()


def dependency_record() -> dict[str, Any]:
    """Import and pin the non-stdlib dependencies used by the attack."""
    try:
        import fpylll  # type: ignore
        fpylll_version = importlib.metadata.version("fpylll")
        cysignals_version = importlib.metadata.version("cysignals")
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:  # pragma: no cover
        raise RuntimeError(
            "missing fpylll/cysignals lock; install reproducer/requirements.txt "
            "with the same Python"
        ) from exc
    if fpylll_version != "0.6.4" or cysignals_version != "1.12.6":
        raise RuntimeError(
            "dependency mismatch: require fpylll==0.6.4 and cysignals==1.12.6; "
            f"found fpylll=={fpylll_version}, cysignals=={cysignals_version}"
        )
    return {
        "cysignals": cysignals_version,
        "fpylll": fpylll_version,
        "machine": platform.machine(),
        "os": platform.system(),
        "os_release": platform.release(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "python_implementation": platform.python_implementation(),
        "sage_required": False,
        "singular_required": False,
    }


def parameter_record() -> dict[str, Any]:
    return {
        "name": "Bittersweet-L1-d32",
        "q": Q_BITS,
        "p_prime": P_PRIME_BITS,
        "alpha": ALPHA,
        "p": P_BITS,
        "n": N,
        "m": M,
        "d": D,
        "t": T,
    }


def reject_secret_fields(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_PUBLIC_NAMES:
                raise ValueError(f"secret-bearing field {key!r} at {location}")
            reject_secret_fields(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{location}[{index}]")


def derive_root(
    key: Sequence[int], message: bytes, binding: bytes, salt: bytes, repetition: int
) -> bytes:
    return verifier.shake(
        b"G1-repetition-root",
        (verifier.vector(key, 12), message, binding, salt, verifier.word(repetition, 2)),
        16,
    )


def open_path(root: bytes, hidden: int) -> list[bytes]:
    seed, node = root, 0
    path: list[bytes] = []
    for depth in range(5):
        left, right = verifier.split_node(seed, depth, node)
        bit = (hidden >> (4 - depth)) & 1
        path.append(right if bit == 0 else left)
        seed = left if bit == 0 else right
        node = 2 * node + bit
    return path


def pack_bits(bits: Sequence[int]) -> str:
    packed = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit not in (0, 1):
            raise ValueError("non-binary reconstruction error")
        packed[index // 8] |= bit << (7 - index % 8)
    return packed.hex()


def public_y(public: dict[str, Any]) -> list[int]:
    if public.get("schema") == "bittersweet-l1-public-interval-instance-v1":
        return [int(row["public_y"]) for row in public["rows"]]
    return [int(value) for value in public["public_y"]]


def public_matrix(public: dict[str, Any]) -> list[list[int]]:
    return [[int(word, 16) for word in row] for row in public["matrix_X_hex"]]


def make_public_key(master: bytes) -> tuple[dict[str, Any], bytes, list[int]]:
    context = b"Bittersweet-public-reproducer-full-v1"
    public_x = verifier.shake(b"fresh-key-public-x", (master, context), 16)
    key_bytes = verifier.shake(b"fresh-key-secret-k", (master, context), N * 12)
    secret = [int.from_bytes(key_bytes[i : i + 12], "big") for i in range(0, len(key_bytes), 12)]
    matrix = verifier.expand_public_matrix(public_x)
    y = verifier.rounded(verifier.multiply(matrix, secret))
    binding = verifier.bind_matrix(matrix)
    public = {
        "schema": "bittersweet-v1-full-signature-public-key-v1",
        "target": {"eprint": "2026/397 v1", "pdf_sha256": PDF_SHA256},
        "parameters": parameter_record(),
        "model_scope": MODEL_SCOPE,
        "public_x_hex": public_x.hex(),
        "matrix_encoding": (
            "G(public_x) under the package canonical SHAKE256 domain; "
            "fixed-width 24-hex-digit residues modulo 2^96."
        ),
        "matrix_X_hex": [[f"{value:024x}" for value in row] for row in matrix],
        "public_y": y,
        "public_matrix_binding_hex": binding.hex(),
    }
    raw = canonical(public)
    reject_secret_fields(public)
    return public, raw, secret


def sign(
    public: dict[str, Any],
    public_raw: bytes,
    key: Sequence[int],
    message: bytes,
    randomness: bytes,
    *,
    query_index: int | None = None,
    recovery_commitment_sha256: str | None = None,
) -> dict[str, Any]:
    """Create one ordinary optimized signature, retrying only paper aborts."""
    matrix = public_matrix(public)
    y = public_y(public)
    products = verifier.multiply(matrix, key)
    if verifier.rounded(products) != y:
        raise ValueError("signing key does not match the public LWR output")
    binding = verifier.bind_matrix(matrix)
    secret_buffer = [(value >> 3) & BUFFER_MASK for value in products]
    context = verifier.word(query_index if query_index is not None else 0xFFFFFFFF, 4)
    aborts = 0
    for attempt in range(1, 1001):
        salt = verifier.shake(
            b"public-reproducer-signing-salt",
            (randomness, message, binding, context, verifier.word(attempt, 8)),
            16,
        )
        all_outputs: list[list[list[int]]] = []
        all_commitments: list[list[bytes]] = []
        states: list[tuple[bytes, list[list[int]]]] = []
        for repetition in range(T):
            root = derive_root(key, message, binding, salt, repetition)
            leaf_seeds = verifier.expand_root(root)
            keys = [
                verifier.share_from_leaf(leaf_seeds[party], party, repetition, salt)
                for party in range(D - 1)
            ]
            correction = [
                (key[column] - sum(keys[party][column] for party in range(D - 1))) & MASK
                for column in range(N)
            ]
            keys.append(correction)
            all_outputs.append([verifier.rounded(verifier.multiply(matrix, share)) for share in keys])
            all_commitments.append(
                [verifier.key_commitment(share, party, repetition, salt) for party, share in enumerate(keys)]
            )
            states.append((root, keys))
        first_hash = verifier.hash_first_message(
            all_outputs, all_commitments, message, binding, y, salt
        )
        challenge = verifier.derive_challenge(first_hash)
        opened_products: list[list[int]] = []
        aborted = False
        for repetition, hidden in enumerate(challenge):
            keys = states[repetition][1]
            aggregate = [
                sum(keys[party][column] for party in range(D) if party != hidden) & MASK
                for column in range(N)
            ]
            opened = verifier.multiply(matrix, aggregate)
            if any(
                ((value >> 3) & BUFFER_MASK) == fixed
                for value, fixed in zip(opened, secret_buffer)
            ):
                aborted = True
                break
            opened_products.append(opened)
        if aborted:
            aborts += 1
            continue

        responses: list[dict[str, Any]] = []
        error_ones = 0
        for repetition, hidden in enumerate(challenge):
            root, keys = states[repetition]
            rounded_opened = verifier.rounded(opened_products[repetition])
            errors = [
                (y[row] - rounded_opened[row] - all_outputs[repetition][hidden][row])
                % (1 << P_PRIME_BITS)
                for row in range(M)
            ]
            if any(bit not in (0, 1) for bit in errors):
                raise AssertionError("honest response contains a non-bit error")
            error_ones += sum(errors)
            response: dict[str, Any] = {
                "hidden_commitment_hex": all_commitments[repetition][hidden].hex(),
                "errors_msb_packed_hex": pack_bits(errors),
            }
            if hidden == D - 1:
                response.update({"case": "root", "root_hex": root.hex()})
            else:
                response.update(
                    {
                        "case": "path",
                        "path_hex": [seed.hex() for seed in open_path(root, hidden)],
                        "last_key_hex": [f"{value:024x}" for value in keys[D - 1]],
                    }
                )
            responses.append(response)

        root_cases = sum(hidden == D - 1 for hidden in challenge)
        payload_bits = 128 + 130
        for hidden in challenge:
            payload_bits += M + 8 * 32
            payload_bits += 8 * 16 if hidden == D - 1 else 5 * 8 * 16 + N * Q_BITS
        common = {
            "target_pdf_sha256": PDF_SHA256,
            "model_scope": MODEL_SCOPE,
            "parameters": {
                "q": Q_BITS,
                "p_prime": P_PRIME_BITS,
                "alpha": ALPHA,
                "p": P_BITS,
                "n": N,
                "m": M,
                "d": D,
                "t": T,
            },
            "public_instance": "public-key.json" if query_index is not None else "public-intervals.json",
            "public_instance_sha256": sha256(public_raw),
            "public_matrix_binding_hex": binding.hex(),
            "message_sha256": sha256(message),
            "message_length": len(message),
            "sign_attempts": attempt,
            "abort_count": aborts,
            "root_case_count": root_cases,
            "path_case_count": T - root_cases,
            "error_zero_count": T * M - error_ones,
            "error_one_count": error_ones,
            "mathematical_payload_bits": payload_bits,
            "mathematical_payload_bytes_ceiling": (payload_bits + 7) // 8,
            "first_message_hash_hex": first_hash.hex(),
            "signature": {"salt_hex": salt.hex(), "challenge": challenge, "responses": responses},
        }
        if query_index is not None:
            common.update(
                {
                    "schema": "bittersweet-v1-full-l1-oracle-signature-v1",
                    "oracle_signature_index": query_index,
                }
            )
        else:
            if recovery_commitment_sha256 is None:
                raise ValueError("recovery signature requires a candidate commitment")
            common.update(
                {
                    "schema": "bittersweet-v1-full-l1-signature-reproduction-v1",
                    "public_freeze": "candidate-commitment.json",
                    "public_freeze_sha256": recovery_commitment_sha256,
                    "recovered_key_sha256": sha256(
                        b"".join(int(value).to_bytes(12, "big") for value in key)
                    ),
                }
            )
        return common
    raise RuntimeError("1000 consecutive signing attempts aborted")


def aggregate_verified_signatures(
    public: dict[str, Any], public_raw: bytes, records: Sequence[tuple[bytes, dict[str, Any]]]
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    if len(records) != QUERY_COUNT:
        raise ValueError(f"expected {QUERY_COUNT} signatures")
    lower = [0] * M
    upper = [BUFFER_MASK] * M
    evidence: list[dict[str, Any]] = []
    message_hashes: set[str] = set()
    for index, (message, envelope) in enumerate(records):
        if envelope.get("schema") != "bittersweet-v1-full-l1-oracle-signature-v1":
            raise ValueError(f"query signature {index} has the wrong schema")
        if envelope.get("oracle_signature_index") != index:
            raise ValueError(f"query signature {index} has the wrong oracle index")
        outcome = verifier.verify(public, public_raw, message, envelope, collect_observations=True)
        observations = outcome.pop("_oracle_observations", None)
        if not outcome.get("accepted") or observations is None:
            raise ValueError(f"query signature {index} failed strict verification: {outcome['reason']}")
        message_hashes.add(sha256(message))
        for row, bounds in enumerate(observations["derived_bracket_rows"]):
            if bounds["row"] != row:
                raise ValueError("strict-verifier bracket order mismatch")
            lower[row] = max(lower[row], int(bounds["buffer_lower_inclusive"]))
            upper[row] = min(upper[row], int(bounds["buffer_upper_inclusive"]))
            if lower[row] > upper[row]:
                raise ValueError(f"empty aggregate interval at row {row}")
        evidence.append(
            {
                "query_index": index,
                "message_sha256": sha256(message),
                "observations_sha256": sha256(canonical(observations)),
                "signature_sha256": sha256(canonical(envelope)),
                "verification_sha256": sha256(canonical(outcome)),
            }
        )
    if len(message_hashes) != QUERY_COUNT:
        raise ValueError("query messages are not distinct")
    matrix = public_matrix(public)
    y = public_y(public)
    rows = []
    for row, (lo, hi, output) in enumerate(zip(lower, upper, y)):
        product_lo = (output << P_BITS) + 8 * lo
        product_hi = (output << P_BITS) + 8 * (hi + 1) - 1
        if not 0 <= product_lo <= product_hi <= MASK:
            raise ValueError(f"invalid product interval at row {row}")
        rows.append(
            {
                "row": row,
                "buffer_lower_inclusive": lo,
                "buffer_upper_inclusive": hi,
                "buffer_midpoint_floor": (lo + hi) // 2,
                "buffer_width": hi - lo + 1,
                "product_lower_inclusive": product_lo,
                "product_upper_inclusive": product_hi,
                "product_midpoint_floor": (product_lo + product_hi) // 2,
                "product_interval_width": product_hi - product_lo + 1,
                "public_y": output,
            }
        )
    result = {
        "schema": "bittersweet-l1-public-interval-instance-v1",
        "campaign": "local-full-reproduction",
        "target": public["target"],
        "parameters": public["parameters"],
        "model_scope": public["model_scope"],
        "public_x_hex": public["public_x_hex"],
        "matrix_encoding": public["matrix_encoding"],
        "matrix_X_hex": public["matrix_X_hex"],
        "rows": rows,
        "observation_count": {
            "accepted_signatures": QUERY_COUNT,
            "comparisons_per_signature_per_row": T,
            "comparisons_per_row": QUERY_COUNT * T,
            "total_comparisons": QUERY_COUNT * T * M,
        },
        "strict_verification_evidence": evidence,
        "solver_boundary": (
            "PUBLIC INPUT derived only from 16 locally generated, independently "
            "strict-verified complete optimized signatures."
        ),
        "private_truth_read": False,
    }
    reject_secret_fields(result)
    raw = canonical(result)
    return result, raw, {
        "accepted_signatures": QUERY_COUNT,
        "distinct_messages": len(message_hashes),
        "comparisons_per_row": QUERY_COUNT * T,
        "total_comparisons": QUERY_COUNT * T * M,
    }


def validate_public_intervals(
    public: dict[str, Any],
    raw: bytes,
    *,
    expected_fresh_message: bytes | None = None,
) -> dict[str, Any]:
    if canonical(public) != raw:
        raise ValueError("public interval object does not match canonical input bytes")
    reject_secret_fields(public)
    if public.get("schema") != "bittersweet-l1-public-interval-instance-v1":
        raise ValueError("wrong public interval schema")
    params = public.get("parameters", {})
    observed = tuple(
        int(params.get(name, -1))
        for name in ("q", "p_prime", "alpha", "p", "n", "m", "d", "t")
    )
    if observed != (Q_BITS, P_PRIME_BITS, ALPHA, P_BITS, N, M, D, T):
        raise ValueError(f"wrong target parameters: {observed}")
    if public.get("target", {}).get("pdf_sha256") != PDF_SHA256:
        raise ValueError("wrong target PDF hash")
    matrix = public_matrix(public)
    if len(matrix) != M or any(len(row) != N for row in matrix):
        raise ValueError("wrong public matrix dimensions")
    public_x = bytes.fromhex(public["public_x_hex"])
    if len(public_x) != 16 or matrix != verifier.expand_public_matrix(public_x):
        raise ValueError("public matrix/XOF seed mismatch")
    rows = public.get("rows")
    if not isinstance(rows, list) or len(rows) != M:
        raise ValueError("wrong interval row count")
    widths: list[int] = []
    for index, row in enumerate(rows):
        if int(row.get("row", -1)) != index:
            raise ValueError("interval row order mismatch")
        lo, hi, y = (
            int(row["buffer_lower_inclusive"]),
            int(row["buffer_upper_inclusive"]),
            int(row["public_y"]),
        )
        product_lo, product_hi = int(row["product_lower_inclusive"]), int(row["product_upper_inclusive"])
        expected_lo = (y << P_BITS) + 8 * lo
        expected_hi = (y << P_BITS) + 8 * (hi + 1) - 1
        if not 0 <= lo <= hi <= BUFFER_MASK or not 0 <= y < (1 << P_PRIME_BITS):
            raise ValueError(f"invalid interval values at row {index}")
        if (product_lo, product_hi) != (expected_lo, expected_hi):
            raise ValueError(f"interval encoding mismatch at row {index}")
        if int(row["buffer_width"]) != hi - lo + 1:
            raise ValueError(f"buffer width mismatch at row {index}")
        if int(row["buffer_midpoint_floor"]) != (lo + hi) // 2:
            raise ValueError(f"buffer midpoint mismatch at row {index}")
        if int(row["product_interval_width"]) != product_hi - product_lo + 1:
            raise ValueError(f"interval width mismatch at row {index}")
        if int(row["product_midpoint_floor"]) != (product_lo + product_hi) // 2:
            raise ValueError(f"product midpoint mismatch at row {index}")
        widths.append(product_hi - product_lo + 1)
    counts = public.get("observation_count", {})
    if (
        int(counts.get("accepted_signatures", -1)) != QUERY_COUNT
        or int(counts.get("comparisons_per_signature_per_row", -1)) != T
        or int(counts.get("comparisons_per_row", -1)) != QUERY_COUNT * T
        or int(counts.get("total_comparisons", -1)) != QUERY_COUNT * T * M
    ):
        raise ValueError("public instance does not encode the fixed S16 evidence count")
    evidence = public.get("strict_verification_evidence")
    if not isinstance(evidence, list) or len(evidence) != QUERY_COUNT:
        raise ValueError("wrong strict-verification evidence count")
    message_hashes: list[str] = []
    for expected_index, item in enumerate(evidence):
        if not isinstance(item, dict) or type(item.get("query_index")) is not int:
            raise ValueError(f"bad strict-verification evidence row {expected_index}")
        if item["query_index"] != expected_index:
            raise ValueError("strict-verification evidence indices are not 0..15")
        for field in (
            "message_sha256",
            "observations_sha256",
            "signature_sha256",
            "verification_sha256",
        ):
            value = item.get(field)
            if not isinstance(value, str) or len(value) != 64 or value.lower() != value:
                raise ValueError(f"bad {field} at query {expected_index}")
            try:
                bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError(f"bad {field} at query {expected_index}") from exc
        message_hashes.append(item["message_sha256"])
    if len(set(message_hashes)) != QUERY_COUNT:
        raise ValueError("query-message digests are not unique")
    if expected_fresh_message is not None and sha256(expected_fresh_message) in set(message_hashes):
        raise ValueError("expected fresh message collides with a query")
    return {
        "sha256": sha256(raw),
        "rows": len(rows),
        "matrix_rows": len(matrix),
        "matrix_columns": N,
        "accepted_signatures": QUERY_COUNT,
        "comparisons_per_row": QUERY_COUNT * T,
        "total_comparisons": QUERY_COUNT * T * M,
        "minimum_interval_width": min(widths),
        "maximum_interval_width": max(widths),
    }


def _add_binary_row(mask: int, pivots: dict[int, int]) -> bool:
    while mask:
        pivot = mask.bit_length() - 1
        if pivot in pivots:
            mask ^= pivots[pivot]
        else:
            pivots[pivot] = mask
            return True
    return False


def choose_pivots(matrix: list[list[int]], candidates: list[int]) -> list[int]:
    pivots: dict[int, int] = {}
    selected: list[int] = []
    for row in candidates:
        mask = sum((matrix[row][column] & 1) << column for column in range(N))
        if _add_binary_row(mask, pivots):
            selected.append(row)
            if len(selected) == N:
                return selected
    raise ValueError("selected rows do not span modulo two")


def inverse_mod(matrix: list[list[int]], modulus: int) -> list[list[int]]:
    size = len(matrix)
    work = [
        [value % modulus for value in row]
        + [int(column == row_index) for column in range(size)]
        for row_index, row in enumerate(matrix)
    ]
    for column in range(size):
        pivot = next((row for row in range(column, size) if work[row][column] & 1), None)
        if pivot is None:
            raise ValueError("matrix is not invertible over Z/(2^96)")
        work[column], work[pivot] = work[pivot], work[column]
        scale = pow(work[column][column], -1, modulus)
        work[column] = [(value * scale) % modulus for value in work[column]]
        for row in range(size):
            if row == column:
                continue
            factor = work[row][column]
            if factor:
                work[row] = [
                    (left - factor * right) % modulus
                    for left, right in zip(work[row], work[column])
                ]
    return [row[size:] for row in work]


def matrix_product(left: Sequence[Sequence[int]], right: Sequence[Sequence[int]], modulus: int) -> list[list[int]]:
    transposed = list(zip(*right))
    return [
        [sum(a * b for a, b in zip(row, column)) % modulus for column in transposed]
        for row in left
    ]


def centered(value: int) -> int:
    value %= MODULUS
    return value - MODULUS if value >= MODULUS // 2 else value


@dataclass
class Recovery:
    key: list[int]
    report: dict[str, Any]


def recover(public: dict[str, Any], raw: bytes) -> Recovery:
    from fpylll import CVP, FPLLL, IntegerMatrix, LLL  # type: ignore

    matrix = public_matrix(public)
    rows = public["rows"]
    selected = sorted(range(M), key=lambda row: int(rows[row]["product_interval_width"]))[:SELECTED_ROWS]
    systematic = choose_pivots(
        matrix,
        sorted(selected, key=lambda row: int(rows[row]["product_interval_width"]), reverse=True),
    )
    systematic_set = set(systematic)
    ordered = systematic + [row for row in selected if row not in systematic_set]
    a0 = [matrix[row] for row in ordered[:N]]
    inverse = inverse_mod(a0, MODULUS)
    identity = matrix_product(a0, inverse, MODULUS)
    if identity != [[int(i == j) for j in range(N)] for i in range(N)]:
        raise AssertionError("modular inverse self-check failed")
    a1 = [matrix[row] for row in ordered[N:]]
    coupling = matrix_product(a1, inverse, MODULUS)
    coupling_checks = sum(
        all(
            sum(coupling[row][column] * a0[column][target] for column in range(N)) % MODULUS
            == a1[row][target]
            for target in range(N)
        )
        for row in range(len(a1))
    )
    if coupling_checks != SELECTED_ROWS - N:
        raise AssertionError("basis coupling self-check failed")

    basis = [[0] * SELECTED_ROWS for _ in range(SELECTED_ROWS)]
    for column in range(N):
        basis[column][column] = 1
        for row in range(SELECTED_ROWS - N):
            basis[column][N + row] = centered(coupling[row][column])
    for row in range(SELECTED_ROWS - N):
        basis[N + row][N + row] = MODULUS
    widths = [int(rows[row]["product_interval_width"]) for row in ordered]
    reference_width = max(widths)
    weights = [max(1, int(round(reference_width / width))) for width in widths]
    for row in range(SELECTED_ROWS):
        for column in range(SELECTED_ROWS):
            basis[row][column] *= weights[column]
    target = [
        int(rows[row]["product_midpoint_floor"]) * weights[column]
        for column, row in enumerate(ordered)
    ]
    basis_target_digest = sha256(canonical({"basis": basis, "target": target}))
    integer_basis = IntegerMatrix(SELECTED_ROWS, SELECTED_ROWS)
    for row in range(SELECTED_ROWS):
        for column in range(SELECTED_ROWS):
            integer_basis[row, column] = int(basis[row][column])

    FPLLL.set_random_seed(FPYLLL_SEED)
    start = time.monotonic()
    lll_start = time.monotonic()
    LLL.reduction(integer_basis, delta=LLL_DELTA, eta=LLL_ETA)
    lll_seconds = time.monotonic() - lll_start
    babai_start = time.monotonic()
    nearest_scaled = CVP.babai(integer_basis, tuple(target))
    babai_seconds = time.monotonic() - babai_start
    if any(int(value) % weights[index] for index, value in enumerate(nearest_scaled)):
        raise ValueError("Babai output is not in the scaled coordinate lattice")
    nearest = [int(value) // weights[index] for index, value in enumerate(nearest_scaled)]
    v0 = [nearest[index] % MODULUS for index in range(N)]
    key = [sum(inverse[row][column] * v0[column] for column in range(N)) % MODULUS for row in range(N)]
    fits = []
    normalized_residuals = []
    for coefficients, interval in zip(matrix, rows):
        product = sum(a * b for a, b in zip(coefficients, key)) % MODULUS
        lo, hi = int(interval["product_lower_inclusive"]), int(interval["product_upper_inclusive"])
        fits.append(lo <= product <= hi)
        half_width = max(1.0, int(interval["product_interval_width"]) / 2.0)
        normalized_residuals.append(abs(product - int(interval["product_midpoint_floor"])) / half_width)
    y_fit = sum(
        ((sum(a * b for a, b in zip(coefficients, key)) % MODULUS) >> P_BITS)
        == int(interval["public_y"])
        for coefficients, interval in zip(matrix, rows)
    )
    selected_fit = sum(fits[row] for row in ordered)
    if sum(fits) != M or y_fit != M or selected_fit != SELECTED_ROWS:
        raise ValueError(
            f"public recovery failed: intervals {sum(fits)}/{M}, outputs {y_fit}/{M}, "
            f"selected {selected_fit}/{SELECTED_ROWS}"
        )
    key_bytes = b"".join(value.to_bytes(12, "big") for value in key)
    report = {
        "status": "PUBLIC_CONSTRAINTS_SATISFIED",
        "family": "B",
        "accepted_signatures": QUERY_COUNT,
        "selected_row_count": SELECTED_ROWS,
        "selected_rows_sha256": sha256(canonical(ordered)),
        "systematic_rows_sha256": sha256(canonical(systematic)),
        "basis_target_sha256": basis_target_digest,
        "basis_consistency": {
            "modular_inverse": True,
            "coupling_rows_checked": coupling_checks,
            "coupling_rows_total": SELECTED_ROWS - N,
        },
        "weighting": {
            "rule": "round(max selected width / row width), minimum 1",
            "reference_width": reference_width,
            "minimum": min(weights),
            "maximum": max(weights),
        },
        "reduction": "plain LLL(delta=0.99, eta=0.501)",
        "nearest_plane": "fpylll CVP.babai",
        "block_schedule": [0],
        "configured_loops": 2,
        "fpylll_seed": FPYLLL_SEED,
        "attempts": 1,
        "selected_intervals_satisfied": selected_fit,
        "all_intervals_satisfied": sum(fits),
        "public_outputs_satisfied": y_fit,
        "candidate_key_sha256": sha256(key_bytes),
        "maximum_selected_normalized_midpoint_residual": max(normalized_residuals[row] for row in ordered),
        "lll_seconds": lll_seconds,
        "babai_seconds": babai_seconds,
        "solver_seconds": time.monotonic() - start,
        "input_sha256": sha256(raw),
        "private_truth_read": False,
        "candidate_words_emitted": False,
    }
    return Recovery(key=key, report=report)


def controls_pass(controls: dict[str, Any]) -> bool:
    values = controls.get("controls", {})
    required = {
        "changed_message",
        "flipped_error_bit",
        "flipped_hidden_commitment",
        "flipped_salt",
        "changed_challenge_index",
        "flipped_ggm_path",
        "flipped_correction_key",
        "nonzero_error_padding_mask_0x1f",
        "changed_public_y",
        "changed_public_matrix",
    }
    return (
        controls.get("status") == "PASS"
        and required <= set(values)
        and all(item.get("rejected") is True for item in values.values())
    )


def fresh_signing_check(
    public: dict[str, Any],
    public_raw: bytes,
    recovery: Recovery,
    message: bytes,
) -> dict[str, Any]:
    commitment = {
        "schema": "bittersweet-ephemeral-public-candidate-commitment-v1",
        "candidate_key_sha256": recovery.report["candidate_key_sha256"],
        "public_instance_sha256": sha256(public_raw),
        "public_intervals_satisfied": recovery.report["all_intervals_satisfied"],
        "public_outputs_satisfied": recovery.report["public_outputs_satisfied"],
        "candidate_words_in_commitment": False,
    }
    commitment_raw = canonical(commitment)
    commitment_sha256 = sha256(commitment_raw)
    signature = sign(
        public,
        public_raw,
        recovery.key,
        message,
        bytes.fromhex(commitment_sha256),
        recovery_commitment_sha256=commitment_sha256,
    )
    if signature["public_freeze_sha256"] != commitment_sha256:
        raise AssertionError("fresh signature does not bind the candidate commitment")
    if signature["recovered_key_sha256"] != recovery.report["candidate_key_sha256"]:
        raise AssertionError("fresh signature does not bind the recovered-key digest")
    signature_raw = canonical(signature)
    outcome = verifier.verify(public, public_raw, message, signature)
    controls = verifier.mutation_controls(public, public_raw, message, signature)
    if not outcome.get("accepted") or not controls_pass(controls):
        raise ValueError("fresh recovered-key signature or its negative controls failed")
    return {
        "message_sha256": sha256(message),
        "message_length": len(message),
        "candidate_commitment_sha256": commitment_sha256,
        "signature_sha256": sha256(signature_raw),
        "signature_accepted": True,
        "sign_attempts": signature["sign_attempts"],
        "abort_count": signature["abort_count"],
        "negative_controls": {
            "status": controls["status"],
            "rejected": sum(item["rejected"] for item in controls["controls"].values()),
            "total": len(controls["controls"]),
            "names": sorted(controls["controls"]),
        },
        "signature_words_emitted": False,
    }


def peak_rss_kib() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
