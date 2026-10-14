#!/usr/bin/env python3
"""Public-only one-query forgery against FDSD Level I (ePrint 2023/1956).

The program deliberately has no dependency on the faithful implementation.
Its only cryptanalytic inputs are the retained public key and exactly the
first ordinary-signature record in the public transcript.  The attacker-
chosen target is a source-level constant, fixed before any search begins.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Iterable, Sequence


N = 1600
ROWS = 1200
L = 125
THETA = 25
D = 343

# This message is distinct from the queried message and is fixed in the
# immutable attack input before column recovery or Gray-code enumeration.
TARGET_MESSAGE = (
    b"FDSD ePrint 2023/1956: independent public-only one-query forgery "
    b"target, 2026-10-14"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_set_bits(value: int) -> Iterable[int]:
    while value:
        low = value & -value
        yield low.bit_length() - 1
        value ^= low


def xor_selected(columns: Sequence[int], selector: int) -> int:
    result = 0
    while selector:
        low = selector & -selector
        result ^= columns[low.bit_length() - 1]
        selector ^= low
    return result


def unpack_vector(data: bytes, length: int) -> int:
    if len(data) != (length + 7) // 8:
        raise ValueError(f"wrong {length}-bit vector encoding length")
    if length % 8:
        unused = 8 - (length % 8)
        if data[-1] & ((1 << unused) - 1):
            raise ValueError(f"nonzero padding in {length}-bit vector")
    value = 0
    for index in range(length):
        if (data[index // 8] >> (7 - (index % 8))) & 1:
            value |= 1 << index
    return value


def pack_vector(value: int, length: int) -> bytes:
    if value < 0 or value >> length:
        raise ValueError("vector does not fit")
    result = bytearray((length + 7) // 8)
    for index in iter_set_bits(value):
        result[index // 8] |= 1 << (7 - (index % 8))
    return bytes(result)


def unpack_matrix_row_major(data: bytes, rows: int, columns: int) -> list[int]:
    bit_count = rows * columns
    if len(data) != (bit_count + 7) // 8:
        raise ValueError("wrong matrix encoding length")
    result = [0] * columns
    flat = 0
    for row in range(rows):
        row_bit = 1 << row
        for column in range(columns):
            if (data[flat // 8] >> (7 - (flat % 8))) & 1:
                result[column] |= row_bit
            flat += 1
    return result


def hash_message(message: bytes) -> int:
    raw = hashlib.shake_256(message).digest(16)
    value = 0
    for index in range(L):
        if (raw[index // 8] >> (7 - (index % 8))) & 1:
            value |= 1 << index
    return value


class ColumnBasis:
    """GF(2) column basis carrying coefficient witnesses."""

    def __init__(self) -> None:
        self._vectors: dict[int, int] = {}
        self._coefficients: dict[int, int] = {}

    @property
    def rank(self) -> int:
        return len(self._vectors)

    def reduce(self, value: int, coefficient: int = 0) -> tuple[int, int]:
        while value:
            pivot = value.bit_length() - 1
            basis_value = self._vectors.get(pivot)
            if basis_value is None:
                break
            value ^= basis_value
            coefficient ^= self._coefficients[pivot]
        return value, coefficient

    def insert(self, value: int, coefficient: int) -> bool:
        value, coefficient = self.reduce(value, coefficient)
        if value == 0:
            return False
        pivot = value.bit_length() - 1
        self._vectors[pivot] = value
        self._coefficients[pivot] = coefficient
        return True

    def solve(self, value: int) -> int | None:
        residual, coefficient = self.reduce(value, 0)
        return coefficient if residual == 0 else None


def verify_hash(
    hstar_columns: Sequence[int],
    r_columns: Sequence[int],
    message_hash: int,
    sigma: int,
    zeta: int,
) -> bool:
    if message_hash < 0 or message_hash >> L:
        return False
    if sigma < 0 or sigma >> N or sigma.bit_count() != D:
        return False
    if zeta < 0 or zeta >> THETA:
        return False
    left = xor_selected(hstar_columns, sigma)
    right = xor_selected(r_columns, message_hash)
    right ^= xor_selected(r_columns[:THETA], zeta)
    return left == right


def read_exactly_first_record(path: Path) -> tuple[dict[str, object], int]:
    """Read one JSONL record without buffering or touching the second record."""

    data = bytearray()
    with path.open("rb", buffering=0) as handle:
        while True:
            octet = handle.read(1)
            if octet == b"":
                raise ValueError("signature transcript ended before newline")
            data.extend(octet)
            if octet == b"\n":
                break
    record = json.loads(data)
    if record.get("index") != 0:
        raise ValueError("the exactly-one-record reader requires record index zero")
    return record, len(data)


def run(public_dir: Path, output: Path) -> dict[str, object]:
    process_started = time.monotonic()
    public_dir = public_dir.resolve()

    # Freeze the target, including both ordinary and SHA-256 commitments,
    # before reading the query or beginning any search.
    target_message = TARGET_MESSAGE
    target_hash = hash_message(target_message)
    target_sha256 = sha256_bytes(target_message)
    target_frozen_at_elapsed = time.monotonic() - process_started

    metadata_path = public_dir / "public-key.json"
    hstar_path = public_dir / "Hstar.bin"
    r_path = public_dir / "R.bin"
    signatures_path = public_dir / "signatures.jsonl"

    # Enforce the claimed input boundary inside the interpreter.  Imports have
    # already completed; from this point forward, any attempt to read a path
    # outside these four public inputs aborts the experiment.  The only
    # permitted write is the declared result file.
    allowed_reads = {
        str(path.resolve())
        for path in (metadata_path, hstar_path, r_path, signatures_path)
    }
    allowed_write = str(output.resolve())
    audited_read_opens: list[str] = []

    def enforce_file_boundary(event: str, args: tuple[object, ...]) -> None:
        if event != "open" or not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        raw_path = os.fsdecode(args[0])
        resolved = str(Path(raw_path).resolve())
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else 0
        writing = (
            isinstance(mode, str) and any(marker in mode for marker in "wax+")
        ) or (
            mode is None
            and isinstance(flags, int)
            and bool(flags & (os.O_WRONLY | os.O_RDWR))
        )
        if writing:
            if resolved != allowed_write:
                raise PermissionError(f"write outside attack result boundary: {resolved}")
        else:
            if resolved not in allowed_reads:
                raise PermissionError(f"read outside public-input boundary: {resolved}")
            audited_read_opens.append(resolved)

    sys.addaudithook(enforce_file_boundary)

    metadata_bytes = metadata_path.read_bytes()
    metadata = json.loads(metadata_bytes)
    parameters = metadata["parameters"]
    expected = {
        "n": N,
        "k": 400,
        "rows": ROWS,
        "L": L,
        "epsilon": 5,
        "theta": THETA,
        "d": D,
        "ell": 800,
    }
    for key, value in expected.items():
        if parameters.get(key) != value:
            raise AssertionError(f"public parameter mismatch for {key}")

    hstar_bytes = hstar_path.read_bytes()
    r_bytes = r_path.read_bytes()
    if sha256_bytes(hstar_bytes) != metadata["Hstar"]["sha256"]:
        raise AssertionError("Hstar digest mismatch")
    if sha256_bytes(r_bytes) != metadata["R"]["sha256"]:
        raise AssertionError("R digest mismatch")
    fingerprint = hashlib.sha256(
        hstar_bytes + r_bytes + bytes((THETA,)) + D.to_bytes(2, "big")
    ).hexdigest()
    if fingerprint != metadata["public_key_fingerprint_sha256"]:
        raise AssertionError("public-key fingerprint mismatch")

    hstar_columns = unpack_matrix_row_major(hstar_bytes, ROWS, N)
    r_columns = unpack_matrix_row_major(r_bytes, ROWS, L)

    query_record, query_bytes_read = read_exactly_first_record(signatures_path)
    query_message = bytes.fromhex(str(query_record["message_hex"]))
    query_hash = unpack_vector(bytes.fromhex(str(query_record["hash_125_hex"])), L)
    query_sigma = unpack_vector(bytes.fromhex(str(query_record["sigma_hex"])), N)
    query_zeta = unpack_vector(bytes.fromhex(str(query_record["zeta_hex"])), THETA)
    if query_hash != hash_message(query_message):
        raise AssertionError("queried record hash mismatch")
    if not verify_hash(
        hstar_columns, r_columns, query_hash, query_sigma, query_zeta
    ):
        raise AssertionError("queried ordinary signature does not verify")
    if target_message == query_message or target_hash == query_hash:
        raise AssertionError("target is not fresh relative to the sole query")

    recovery_started = time.monotonic()
    r_basis = ColumnBasis()
    for index, column in enumerate(r_columns):
        if not r_basis.insert(column, 1 << index):
            raise AssertionError(f"R is rank-deficient at column {index}")
    if r_basis.rank != L:
        raise AssertionError("R does not have full column rank")

    te_coordinates = [
        index
        for index, column in enumerate(hstar_columns)
        if r_basis.solve(column) is not None
    ]
    if len(te_coordinates) != L:
        raise AssertionError(
            f"expected exactly {L} public columns in Col(R), found "
            f"{len(te_coordinates)}"
        )

    te_basis = ColumnBasis()
    for local_index, coordinate in enumerate(te_coordinates):
        if not te_basis.insert(hstar_columns[coordinate], 1 << local_index):
            raise AssertionError("the recovered Col(R) coordinates are dependent")
    if te_basis.rank != L:
        raise AssertionError("recovered Col(R) coordinate rank is not 125")

    # Each solution gives a column of U restricted to the recovered T_e,
    # then embeds that 125-bit coefficient vector in the 1,600 coordinates.
    u_columns: list[int] = []
    for column_index, r_column in enumerate(r_columns):
        local = te_basis.solve(r_column)
        if local is None:
            raise AssertionError(f"could not solve U column {column_index}")
        embedded = 0
        for local_index in iter_set_bits(local):
            embedded |= 1 << te_coordinates[local_index]
        if xor_selected(hstar_columns, embedded) != r_column:
            raise AssertionError(f"recovered U column {column_index} failed")
        u_columns.append(embedded)
    recovery_seconds = time.monotonic() - recovery_started

    # For arbitrary a in F_2^25, take
    # delta=(a, h0_tail+h1_tail), sigma=sigma0+U delta, and
    # zeta=zeta0+h0_head+h1_head+a.  The verifier equation then holds
    # identically; only the exact-weight condition remains to search.
    head_mask = (1 << THETA) - 1
    fixed_delta = (query_hash ^ target_hash) & ~head_mask
    candidate_sigma = query_sigma ^ xor_selected(u_columns, fixed_delta)
    fixed_zeta = query_zeta ^ ((query_hash ^ target_hash) & head_mask)

    search_started = time.monotonic()
    maximum_candidates = 1 << THETA
    candidates_tested = 0
    accepted_a: int | None = None
    forged_sigma: int | None = None
    forged_zeta: int | None = None
    previous_gray = 0
    weight_hits = 0
    for counter in range(maximum_candidates):
        gray = counter ^ (counter >> 1)
        if counter:
            changed = gray ^ previous_gray
            bit = changed.bit_length() - 1
            candidate_sigma ^= u_columns[bit]
        previous_gray = gray
        candidates_tested += 1
        if candidate_sigma.bit_count() != D:
            continue
        weight_hits += 1
        candidate_zeta = fixed_zeta ^ gray
        if verify_hash(
            hstar_columns,
            r_columns,
            target_hash,
            candidate_sigma,
            candidate_zeta,
        ):
            accepted_a = gray
            forged_sigma = candidate_sigma
            forged_zeta = candidate_zeta
            break
    search_seconds = time.monotonic() - search_started
    if accepted_a is None or forged_sigma is None or forged_zeta is None:
        raise AssertionError("exhausted all 2^25 head choices without a forgery")

    ordinary_accept = verify_hash(
        hstar_columns, r_columns, target_hash, forged_sigma, forged_zeta
    )
    unchanged_query_reject = not verify_hash(
        hstar_columns, r_columns, target_hash, query_sigma, query_zeta
    )
    changed_message = target_message + b"\x00"
    changed_message_reject = not verify_hash(
        hstar_columns,
        r_columns,
        hash_message(changed_message),
        forged_sigma,
        forged_zeta,
    )
    sigma_tamper_reject = not verify_hash(
        hstar_columns,
        r_columns,
        target_hash,
        forged_sigma ^ 1,
        forged_zeta,
    )
    zeta_tamper_reject = not verify_hash(
        hstar_columns,
        r_columns,
        target_hash,
        forged_sigma,
        forged_zeta ^ 1,
    )
    if not all(
        (
            ordinary_accept,
            unchanged_query_reject,
            changed_message_reject,
            sigma_tamper_reject,
            zeta_tamper_reject,
        )
    ):
        raise AssertionError("one or more final acceptance controls failed")

    result: dict[str, object] = {
        "schema_version": 1,
        "status": "PASS",
        "classification": "PUBLIC_ONLY_ONE_QUERY_FRESH_MESSAGE_FORGERY",
        "target": "Full-Distance Syndrome Decoding, ePrint 2023/1956",
        "profile": "Level I",
        "public_key_fingerprint_sha256": fingerprint,
        "attack_model": {
            "ordinary_signing_queries": 1,
            "queried_records_parsed": 1,
            "query_record_index": 0,
            "query_file_bytes_read_exactly": query_bytes_read,
            "target_message_queries": 0,
            "private_inputs_read": False,
            "secret_labels_read": False,
            "fresh_run_summary_read": False,
            "development_artifacts_read": False,
            "external_network_used": False,
            "workers": 1,
            "filesystem_read_allowlist_enforced": True,
            "audited_read_open_events": len(audited_read_opens),
            "audited_unique_read_paths": sorted(set(audited_read_opens)),
            "cryptanalytic_input_files": [
                str(metadata_path),
                str(hstar_path),
                str(r_path),
                str(signatures_path) + " (exactly first JSONL record)",
            ],
        },
        "target_freeze": {
            "message_hex": target_message.hex(),
            "message_sha256": target_sha256,
            "hash_125_hex": pack_vector(target_hash, L).hex(),
            "frozen_before_recovery_and_search": True,
            "frozen_at_elapsed_seconds": target_frozen_at_elapsed,
        },
        "query_transcript": {
            "index": 0,
            "message_hex": query_message.hex(),
            "hash_125_hex": pack_vector(query_hash, L).hex(),
            "sigma_hex": pack_vector(query_sigma, N).hex(),
            "zeta_hex": pack_vector(query_zeta, THETA).hex(),
            "ordinary_verify": "ACCEPT",
            "message_distinct_from_target": True,
            "hash_distinct_from_target": True,
        },
        "public_recovery": {
            "rank_R": r_basis.rank,
            "Hstar_columns_in_Col_R": len(te_coordinates),
            "selected_column_rank": te_basis.rank,
            "recovered_U_columns": len(u_columns),
            "all_Hstar_U_columns_equal_R": True,
            "coordinate_indices_sha256": sha256_bytes(
                b"".join(index.to_bytes(2, "big") for index in te_coordinates)
            ),
        },
        "search": {
            "method": "single-worker reflected Gray-code enumeration over a in F2^25",
            "maximum_candidates": maximum_candidates,
            "candidates_tested": candidates_tested,
            "weight_343_hits_tested": weight_hits,
            "accepted_a_hex": pack_vector(accepted_a, THETA).hex(),
            "exhaustive_bound_reached": candidates_tested == maximum_candidates,
        },
        "forgery": {
            "message_hex": target_message.hex(),
            "hash_125_hex": pack_vector(target_hash, L).hex(),
            "sigma_hex": pack_vector(forged_sigma, N).hex(),
            "sigma_weight": forged_sigma.bit_count(),
            "zeta_hex": pack_vector(forged_zeta, THETA).hex(),
            "ordinary_verify": "ACCEPT",
        },
        "controls": {
            "unchanged_query_signature_on_target": "REJECT",
            "forgery_on_changed_message": "REJECT",
            "one_bit_sigma_tamper": "REJECT",
            "one_bit_zeta_tamper": "REJECT",
        },
        "timing_seconds": {
            "public_recovery": recovery_seconds,
            "weight_search": search_seconds,
            "total": time.monotonic() - process_started,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


if __name__ == "__main__":
    arguments = parse_args(sys.argv[1:])
    result = run(arguments.public_dir, arguments.output)
    print("=" * 48)
    print("ATTACK REPRODUCTION: PASS")
    print("Scheme: Full-Distance Syndrome Decoding")
    print("Result: public trapdoor coordinates recovered")
    print("Signing queries: 1")
    print("Target-message queries: 0")
    print("Fresh-message forgery: ACCEPTED")
    print("Negative controls: REJECTED")
    print(f"Candidates tested: {result['search']['candidates_tested']}")
    print(f"Runtime: {result['timing_seconds']['total']:.6f} seconds")
    print("=" * 48)
