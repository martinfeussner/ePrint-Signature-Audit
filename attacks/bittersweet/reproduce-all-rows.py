#!/usr/bin/env python3
"""Independent public recovery evaluator for every affected parameter row.

Bittersweet has one affected advertised row here: Level I with d=32. This
file independently rebuilds the weighted modular-CVP basis and target rather
than dispatching to reproduce.py's recovery routine. It shares only the
canonical signer and strict verifier used to test the recovered key's fresh
signing consequence.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from reproducer import core
from reproducer import strict_verify as verifier


Q = 1 << 96
N, M, ROWS = 11, 747, 160
SEED = 20260412
INSTANCE_SHA256 = "a45b63145c113df534eb553ef3c4df6ae4d83d4181eed923d101be25f4a94092"


def canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def add_binary_row(mask: int, pivots: dict[int, int]) -> bool:
    while mask:
        pivot = mask.bit_length() - 1
        if pivot in pivots:
            mask ^= pivots[pivot]
        else:
            pivots[pivot] = mask
            return True
    return False


def choose_systematic(matrix: list[list[int]], candidates: list[int]) -> list[int]:
    pivots: dict[int, int] = {}
    chosen: list[int] = []
    for index in candidates:
        mask = sum((matrix[index][column] & 1) << column for column in range(N))
        if add_binary_row(mask, pivots):
            chosen.append(index)
            if len(chosen) == N:
                return chosen
    raise ValueError("selected rows are singular modulo two")


def invert(matrix: list[list[int]]) -> list[list[int]]:
    work = [
        [value % Q for value in row] + [int(i == j) for j in range(N)]
        for i, row in enumerate(matrix)
    ]
    for column in range(N):
        pivot = next((row for row in range(column, N) if work[row][column] & 1), None)
        if pivot is None:
            raise ValueError("systematic matrix is not invertible modulo 2^96")
        work[column], work[pivot] = work[pivot], work[column]
        inverse = pow(work[column][column], -1, Q)
        work[column] = [(value * inverse) % Q for value in work[column]]
        for row in range(N):
            if row != column and work[row][column]:
                factor = work[row][column]
                work[row] = [
                    (left - factor * right) % Q
                    for left, right in zip(work[row], work[column])
                ]
    return [row[N:] for row in work]


def multiply(left: Sequence[Sequence[int]], right: Sequence[Sequence[int]]) -> list[list[int]]:
    columns = list(zip(*right))
    return [
        [sum(a * b for a, b in zip(row, column)) % Q for column in columns]
        for row in left
    ]


def centered(value: int) -> int:
    value %= Q
    return value - Q if value >= Q // 2 else value


def load_instance() -> tuple[dict[str, Any], bytes, list[list[int]]]:
    path = Path(__file__).resolve().parent / "reproducer" / "reference" / "public-intervals.json"
    raw = path.read_bytes()
    if digest(raw) != INSTANCE_SHA256:
        raise ValueError("pinned public interval instance changed")
    public = json.loads(raw)
    if canonical(public) != raw:
        raise ValueError("public interval object does not match canonical input bytes")
    if public.get("schema") != "bittersweet-l1-public-interval-instance-v1":
        raise ValueError("wrong public schema")
    params = public.get("parameters", {})
    observed = tuple(
        int(params.get(name, -1))
        for name in ("q", "p_prime", "alpha", "p", "n", "m", "d", "t")
    )
    if observed != (96, 3, 90, 93, 11, 747, 32, 26):
        raise ValueError(f"wrong parameter row: {observed}")
    if public.get("target", {}).get("pdf_sha256") != core.PDF_SHA256:
        raise ValueError("wrong target PDF")
    matrix = [[int(value, 16) for value in row] for row in public.get("matrix_X_hex", [])]
    if len(matrix) != M or any(len(row) != N for row in matrix):
        raise ValueError("wrong public matrix dimensions")
    public_x = bytes.fromhex(public.get("public_x_hex", ""))
    if matrix != verifier.expand_public_matrix(public_x):
        raise ValueError("public XOF seed/matrix mismatch")
    rows = public.get("rows", [])
    if len(rows) != M:
        raise ValueError("wrong interval count")
    for index, row in enumerate(rows):
        lo = int(row["buffer_lower_inclusive"])
        hi = int(row["buffer_upper_inclusive"])
        y = int(row["public_y"])
        if row.get("row") != index or not 0 <= lo <= hi < (1 << 90) or not 0 <= y < 8:
            raise ValueError(f"bad interval row {index}")
        expected_lo = (y << 93) + 8 * lo
        expected_hi = (y << 93) + 8 * (hi + 1) - 1
        if (
            int(row["product_lower_inclusive"]),
            int(row["product_upper_inclusive"]),
        ) != (expected_lo, expected_hi):
            raise ValueError(f"bad interval encoding at row {index}")
        if int(row["buffer_width"]) != hi - lo + 1:
            raise ValueError(f"bad buffer width at row {index}")
        if int(row["buffer_midpoint_floor"]) != (lo + hi) // 2:
            raise ValueError(f"bad buffer midpoint at row {index}")
        if int(row["product_interval_width"]) != expected_hi - expected_lo + 1:
            raise ValueError(f"bad product width at row {index}")
        if int(row["product_midpoint_floor"]) != (expected_lo + expected_hi) // 2:
            raise ValueError(f"bad product midpoint at row {index}")
    counts = public.get("observation_count", {})
    if (
        counts.get("accepted_signatures") != 16
        or counts.get("comparisons_per_signature_per_row") != 26
        or counts.get("comparisons_per_row") != 416
        or counts.get("total_comparisons") != 310752
    ):
        raise ValueError("wrong S16 evidence accounting")
    evidence = public.get("strict_verification_evidence")
    if not isinstance(evidence, list) or len(evidence) != 16:
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
    if len(set(message_hashes)) != 16:
        raise ValueError("query-message digests are not unique")
    reference_fresh_message = (
        b"Bittersweet public reproducer / distinct fresh message / "
        + bytes.fromhex(digest(raw))
    )
    if digest(reference_fresh_message) in set(message_hashes):
        raise ValueError("deterministic fresh message collides with a query")
    return public, raw, matrix


def independent_recover(
    public: dict[str, Any], raw: bytes, matrix: list[list[int]]
) -> tuple[list[int], dict[str, Any]]:
    from fpylll import CVP, FPLLL, IntegerMatrix, LLL

    rows = public["rows"]
    selected = sorted(range(M), key=lambda i: int(rows[i]["product_interval_width"]))[:ROWS]
    systematic = choose_systematic(
        matrix,
        sorted(selected, key=lambda i: int(rows[i]["product_interval_width"]), reverse=True),
    )
    systematic_set = set(systematic)
    ordered = systematic + [index for index in selected if index not in systematic_set]
    a0 = [matrix[index] for index in ordered[:N]]
    inverse = invert(a0)
    if multiply(a0, inverse) != [[int(i == j) for j in range(N)] for i in range(N)]:
        raise AssertionError("independent inverse check failed")
    a1 = [matrix[index] for index in ordered[N:]]
    coupling = multiply(a1, inverse)
    basis = [[0] * ROWS for _ in range(ROWS)]
    for column in range(N):
        basis[column][column] = 1
        for row in range(ROWS - N):
            basis[column][N + row] = centered(coupling[row][column])
    for row in range(ROWS - N):
        basis[N + row][N + row] = Q
    widths = [int(rows[index]["product_interval_width"]) for index in ordered]
    widest = max(widths)
    weights = [max(1, int(round(widest / width))) for width in widths]
    for row in range(ROWS):
        for column in range(ROWS):
            basis[row][column] *= weights[column]
    target = [
        int(rows[index]["product_midpoint_floor"]) * weights[column]
        for column, index in enumerate(ordered)
    ]
    lattice = IntegerMatrix(ROWS, ROWS)
    for row in range(ROWS):
        for column in range(ROWS):
            lattice[row, column] = basis[row][column]
    FPLLL.set_random_seed(SEED)
    LLL.reduction(lattice, delta=0.99, eta=0.501)
    nearest_scaled = CVP.babai(lattice, tuple(target))
    if any(int(value) % weights[index] for index, value in enumerate(nearest_scaled)):
        raise ValueError("nearest vector violates coordinate scaling")
    nearest = [int(value) // weights[index] for index, value in enumerate(nearest_scaled)]
    leading = [nearest[index] % Q for index in range(N)]
    key = [
        sum(inverse[row][column] * leading[column] for column in range(N)) % Q
        for row in range(N)
    ]
    interval_fits = []
    output_fits = []
    for coefficients, row in zip(matrix, rows):
        product = sum(a * b for a, b in zip(coefficients, key)) % Q
        interval_fits.append(
            int(row["product_lower_inclusive"])
            <= product
            <= int(row["product_upper_inclusive"])
        )
        output_fits.append((product >> 93) == int(row["public_y"]))
    selected_fit = sum(interval_fits[index] for index in ordered)
    if selected_fit != ROWS or sum(interval_fits) != M or sum(output_fits) != M:
        raise ValueError("independent public recovery failed")
    report = {
        "candidate_key_sha256": digest(b"".join(value.to_bytes(12, "big") for value in key)),
        "selected_intervals_satisfied": selected_fit,
        "all_intervals_satisfied": sum(interval_fits),
        "public_outputs_satisfied": sum(output_fits),
        "selected_rows_sha256": digest(canonical(ordered)),
        "input_sha256": digest(raw),
        "private_truth_read": False,
        "candidate_words_emitted": False,
    }
    return key, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if (
            importlib.metadata.version("fpylll") != "0.6.4"
            or importlib.metadata.version("cysignals") != "1.12.6"
        ):
            raise RuntimeError("require fpylll==0.6.4 and cysignals==1.12.6")
        public, raw, matrix = load_instance()
        key, solver = independent_recover(public, raw, matrix)
        recovery = core.Recovery(key=key, report=solver)
        fresh_message = (
            b"Bittersweet public reproducer / distinct fresh message / "
            + bytes.fromhex(INSTANCE_SHA256)
        )
        fresh = core.fresh_signing_check(public, raw, recovery, fresh_message)
        row = {
            "all_expected_checks_pass": True,
            "candidate_words_emitted": False,
            "counts": {
                "comparisons_per_row": 416,
                "fresh_negative_controls_rejected": fresh["negative_controls"]["rejected"],
                "fresh_negative_controls_total": fresh["negative_controls"]["total"],
                "public_intervals_satisfied": solver["all_intervals_satisfied"],
                "public_outputs_satisfied": solver["public_outputs_satisfied"],
                "selected_intervals_satisfied": solver["selected_intervals_satisfied"],
                "total_comparisons": 310752,
            },
            "digests": {
                "candidate_key_sha256": solver["candidate_key_sha256"],
                "fresh_message_sha256": fresh["message_sha256"],
                "fresh_signature_sha256": fresh["signature_sha256"],
                "public_interval_instance_sha256": INSTANCE_SHA256,
                "selected_rows_sha256": solver["selected_rows_sha256"],
            },
            "fresh_message_signature_accepted": fresh["signature_accepted"],
            "fresh_message_was_not_a_query": True,
            "negative_controls_pass": fresh["negative_controls"]["status"] == "PASS",
            "parameter_row": "Level-I-d32",
            "parameters": core.parameter_record(),
            "public_only_recovery": True,
        }
        row["all_expected_checks_pass"] = (
            row["fresh_message_signature_accepted"]
            and row["fresh_message_was_not_a_query"]
            and row["negative_controls_pass"]
            and row["counts"]["selected_intervals_satisfied"] == ROWS
            and row["counts"]["public_intervals_satisfied"] == M
            and row["counts"]["public_outputs_satisfied"] == M
            and not row["candidate_words_emitted"]
        )
        result = {
            "all_rows_pass": row["all_expected_checks_pass"],
            "description": "independent fixed S16/r160/plain-LLL/Babai evaluator for every affected row",
            "experiment_id": "BTS-PUBLIC-INDEPENDENT-REPRODUCER-V1",
            "results": [row],
            "trials": {
                "campaign_cryptanalytic_trials_added": 0,
                "fresh_keys": 0,
                "local_cryptanalytic_recoveries": 0,
                "local_cryptanalytic_trials": 0,
                "public_replay_attempts": 1,
                "public_replay_recoveries": 1,
            },
        }
        encoded = canonical(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(encoded)
    except (
        AssertionError,
        ImportError,
        KeyError,
        OSError,
        RuntimeError,
        ValueError,
        importlib.metadata.PackageNotFoundError,
    ) as exc:
        print("ALL PARAMETER ROWS: FAIL", file=sys.stderr)
        print(f"Reason: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(encoded.decode(), end="")
    print("ALL PARAMETER ROWS: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
