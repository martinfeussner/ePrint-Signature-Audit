#!/usr/bin/env python3
"""Standard-library model of the HPPK DS Eq. (28) zero forgery.

This module deliberately models the published mathematical verifier.  It is
not a row-exact implementation of the separate xtaci/hppk Go source.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any


TARGET_PDF_SHA256 = (
    "faa261feaf9e1f030273d311bfe642504a82d9f0759524446f9c86afbbc269c1"
)
BENCHMARK_PDF_SHA256 = (
    "1ee259abede8b393f26e021fccbd41774b212146717a63f646aee282273198a7"
)

# Table 1 does not print a prime or the (n, lambda, m) tuple.  The dimensions
# below are the contextual n=lambda=1,m=2 construction described around the
# table.  The probe modulus is taken from the later benchmark solely to execute
# the parameter-independent zero identity; it is not attributed to Table 1.
TARGET_ROWS: tuple[dict[str, Any], ...] = (
    {
        "parameter_row": "target-v2-I",
        "source": "ePrint 2023/1768 Table 1",
        "level": "I",
        "field_bits": 64,
        "prime_expression": None,
        "probe_prime": (1 << 64) - 59,
        "n": 1,
        "lambda": 1,
        "m": 2,
        "L": 128,
        "K": 160,
        "hash": "SHA-256",
        "signature_bytes": 128,
        "dimension_status": "contextual inference; not an exact table tuple",
    },
    {
        "parameter_row": "target-v2-III",
        "source": "ePrint 2023/1768 Table 1",
        "level": "III",
        "field_bits": 96,
        "prime_expression": None,
        "probe_prime": (1 << 96) - 17,
        "n": 1,
        "lambda": 1,
        "m": 2,
        "L": 192,
        "K": 224,
        "hash": "SHA-384",
        "signature_bytes": 192,
        "dimension_status": "contextual inference; not an exact table tuple",
    },
    {
        "parameter_row": "target-v2-V",
        "source": "ePrint 2023/1768 Table 1",
        "level": "V",
        "field_bits": 128,
        "prime_expression": None,
        "probe_prime": (1 << 128) - 159,
        "n": 1,
        "lambda": 1,
        "m": 2,
        "L": 256,
        "K": 288,
        "hash": "SHA-512",
        "signature_bytes": 256,
        "dimension_status": "contextual inference; not an exact table tuple",
    },
)


def _benchmark_row(
    label: str,
    level: str,
    field_bits: int,
    subtraction: int,
    m: int,
    ell: int,
    barrett_k: int,
    hash_name: str,
    signature_bytes: int,
) -> dict[str, Any]:
    return {
        "parameter_row": label,
        "source": "ePrint 2024/019 Table 2",
        "level": level,
        "field_bits": field_bits,
        "prime_expression": f"2^{field_bits}-{subtraction}",
        "probe_prime": (1 << field_bits) - subtraction,
        "n": 1,
        "lambda": 1,
        "m": m,
        "L": ell,
        "K": barrett_k,
        "hash": hash_name,
        "signature_bytes": signature_bytes,
        "dimension_status": "exact Table 2 transcription",
    }


BENCHMARK_ROWS: tuple[dict[str, Any], ...] = (
    _benchmark_row("bench-I-1", "I", 64, 59, 2, 144, 288, "SHA-256", 144),
    _benchmark_row("bench-I-2", "I", 64, 59, 2, 144, 208, "SHA-256", 144),
    _benchmark_row("bench-I-3", "I", 64, 59, 2, 144, 176, "SHA-256", 144),
    _benchmark_row("bench-I-4", "I", 64, 59, 1, 144, 208, "SHA-256", 144),
    _benchmark_row("bench-I-5", "I", 64, 59, 1, 144, 176, "SHA-256", 144),
    _benchmark_row("bench-III-1", "III", 96, 17, 2, 208, 416, "SHA-384", 208),
    _benchmark_row("bench-III-2", "III", 96, 17, 2, 208, 272, "SHA-384", 208),
    _benchmark_row("bench-III-3", "III", 96, 17, 2, 208, 240, "SHA-384", 208),
    _benchmark_row("bench-III-4", "III", 96, 17, 1, 208, 272, "SHA-384", 208),
    _benchmark_row("bench-III-5", "III", 96, 17, 1, 208, 240, "SHA-384", 208),
    _benchmark_row("bench-V-1", "V", 128, 159, 2, 272, 544, "SHA-512", 272),
    _benchmark_row("bench-V-2", "V", 128, 159, 2, 272, 336, "SHA-512", 272),
    _benchmark_row("bench-V-3", "V", 128, 159, 2, 272, 304, "SHA-512", 272),
    _benchmark_row("bench-V-4", "V", 128, 159, 1, 272, 336, "SHA-512", 272),
    _benchmark_row("bench-V-5", "V", 128, 159, 1, 272, 304, "SHA-512", 272),
)

ALL_ROWS = TARGET_ROWS + BENCHMARK_ROWS


def _nonzero(label: str, modulus: int) -> int:
    value = int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest(), "big")
    return 1 + value % (modulus - 1)


def _digest(name: str, message: bytes) -> bytes:
    constructors = {
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
    }
    return constructors[name](message).digest()


def _segments(row: dict[str, Any], message: bytes) -> list[int]:
    digest = _digest(row["hash"], message)
    width = row["field_bits"] // 8
    assert len(digest) == 4 * width
    return [
        int.from_bytes(digest[offset : offset + width], "big")
        for offset in range(0, len(digest), width)
    ]


def _coefficient(
    h_value: int,
    f_value: int,
    pprime: int,
    qprime: int,
    s1: int,
    s2: int,
    mu: int,
    nu: int,
    r_value: int,
    prime: int,
) -> tuple[int, int]:
    u_value = (h_value * pprime - s1 * ((h_value * mu) // r_value)) % prime
    v_value = (f_value * qprime - s2 * ((f_value * nu) // r_value)) % prime
    return u_value, v_value


def _fixture(row: dict[str, Any], *, balanced: bool = False) -> list[list[dict[str, int]]]:
    prime = row["probe_prime"]
    r_value = 1 << row["K"]
    fixture: list[list[dict[str, int]]] = []
    for j_value in range(1, row["m"] + 1):
        column = []
        for i_value in range(row["n"] + row["lambda"] + 1):
            prefix = f"{row['parameter_row']}:i={i_value}:j={j_value}"
            pprime = _nonzero(prefix + ":pprime", prime)
            s1 = _nonzero(prefix + ":s1", prime)
            mu = _nonzero(prefix + ":mu", r_value)
            if balanced:
                qprime, s2, nu = pprime, s1, mu
            else:
                qprime = _nonzero(prefix + ":qprime", prime)
                s2 = _nonzero(prefix + ":s2", prime)
                nu = _nonzero(prefix + ":nu", r_value)
            column.append(
                {
                    "pprime": pprime,
                    "qprime": qprime,
                    "s1": s1,
                    "s2": s2,
                    "mu": mu,
                    "nu": nu,
                }
            )
        fixture.append(column)
    return fixture


def _live_fixture(row: dict[str, Any]) -> list[list[dict[str, int]]]:
    # At i=0 this makes U=H and V=F exactly; all other coefficients vanish.
    result: list[list[dict[str, int]]] = []
    for _j_value in range(row["m"]):
        column = []
        for i_value in range(row["n"] + row["lambda"] + 1):
            nonzero = int(i_value == 0)
            column.append(
                {
                    "pprime": nonzero,
                    "qprime": nonzero,
                    "s1": 0,
                    "s2": 0,
                    "mu": 0,
                    "nu": 0,
                }
            )
        result.append(column)
    return result


def _verify_segment(
    row: dict[str, Any],
    x_value: int,
    pair: tuple[int, int] | list[int],
    fixture: list[list[dict[str, int]]],
) -> bool:
    f_value, h_value = pair
    prime = row["probe_prime"]
    r_value = 1 << row["K"]
    left_by_j: list[int] = []
    right_by_j: list[int] = []
    for column in fixture:
        left = 0
        right = 0
        for i_value, coefficient in enumerate(column):
            u_value, v_value = _coefficient(
                h_value,
                f_value,
                coefficient["pprime"],
                coefficient["qprime"],
                coefficient["s1"],
                coefficient["s2"],
                coefficient["mu"],
                coefficient["nu"],
                r_value,
                prime,
            )
            power = pow(x_value % prime, i_value, prime)
            left = (left + u_value * power) % prime
            right = (right + v_value * power) % prime
        left_by_j.append(left)
        right_by_j.append(right)

    # Check both the benchmark's per-j form and target Eq. (25) under three
    # deterministic choices of the verifier noise vector.
    if left_by_j != right_by_j:
        return False
    noise_vectors = (
        [0] * row["m"],
        list(range(1, row["m"] + 1)),
        [prime - index for index in range(1, row["m"] + 1)],
    )
    for noises in noise_vectors:
        left = sum(value * noise for value, noise in zip(left_by_j, noises)) % prime
        right = sum(value * noise for value, noise in zip(right_by_j, noises)) % prime
        if left != right:
            return False
    return True


def _verify_complete(
    row: dict[str, Any],
    message: bytes,
    signature: list[list[int]],
    fixture: list[list[dict[str, int]]],
) -> bool:
    if len(signature) != 4:
        return False
    if any(not isinstance(pair, list) or len(pair) != 2 for pair in signature):
        return False
    return all(
        _verify_segment(row, x_value, pair, fixture)
        for x_value, pair in zip(_segments(row, message), signature)
    )


def _repair_verify(
    row: dict[str, Any],
    message: bytes,
    signature: list[list[int]],
    fixture: list[list[dict[str, int]]],
) -> bool:
    if any(pair == [0, 0] for pair in signature):
        return False
    return _verify_complete(row, message, signature, fixture)


def _row_result(row: dict[str, Any], messages: list[bytes]) -> dict[str, Any]:
    zero_signature = [[0, 0] for _ in range(4)]
    fixture = _fixture(row)
    live_fixture = _live_fixture(row)
    balanced_fixture = _fixture(row, balanced=True)
    attack_accepts = [
        _verify_complete(row, message, zero_signature, fixture) for message in messages
    ]
    control_message = messages[0]
    controls = {
        "four_pair_zero_signature_accepts": all(attack_accepts),
        "three_pair_truncation_rejects": not _verify_complete(
            row, control_message, zero_signature[:3], fixture
        ),
        "five_pair_extension_rejects": not _verify_complete(
            row, control_message, zero_signature + [[0, 0]], fixture
        ),
        "f_only_nonzero_rejects": not _verify_complete(
            row, control_message, [[1, 0]] * 4, live_fixture
        ),
        "h_only_nonzero_rejects": not _verify_complete(
            row, control_message, [[0, 1]] * 4, live_fixture
        ),
        "test_only_repair_rejects_zero_pair": not _repair_verify(
            row, control_message, zero_signature, fixture
        ),
        "test_only_repair_accepts_balanced_nonzero_fixture": _repair_verify(
            row, control_message, [[1, 1]] * 4, balanced_fixture
        ),
    }
    passed = all(attack_accepts) and all(controls.values())
    return {
        "parameter_row": row["parameter_row"],
        "source": row["source"],
        "level": row["level"],
        "field_bits": row["field_bits"],
        "prime_expression": row["prime_expression"],
        "probe_prime": str(row["probe_prime"]),
        "probe_prime_status": (
            "exact Table 2 prime"
            if row["prime_expression"] is not None
            else "audit arithmetic fixture; Table 1 does not publish a prime"
        ),
        "configuration": {
            "n": row["n"],
            "lambda": row["lambda"],
            "m": row["m"],
            "L": row["L"],
            "K": row["K"],
            "dimension_status": row["dimension_status"],
        },
        "hash": row["hash"],
        "complete_hash_segments": 4,
        "forged_signature_pairs": zero_signature,
        "message_trials": len(messages),
        "accepted_fresh_messages": sum(attack_accepts),
        "attack_signing_queries": 0,
        "secret_information_used": False,
        "controls": controls,
        "row_exact_implementation_claimed": False,
        "all_expected_checks_pass": passed,
    }


def run_rows(*, full: bool, reference: bool) -> dict[str, Any]:
    nonce = "public-reference-fixture" if reference else secrets.token_hex(16)
    message_count = 4 if full else 1
    results = []
    for row in ALL_ROWS:
        messages = [
            (
                "HPPK-DS public reproduction|"
                f"{nonce}|{row['parameter_row']}|message-{index}"
            ).encode("utf-8")
            for index in range(message_count)
        ]
        results.append(_row_result(row, messages))

    checks = {
        "three_target_rows_covered": sum(
            result["source"] == "ePrint 2023/1768 Table 1" for result in results
        )
        == 3,
        "fifteen_benchmark_rows_covered": sum(
            result["source"] == "ePrint 2024/019 Table 2" for result in results
        )
        == 15,
        "complete_hash_uses_four_zero_pairs": all(
            result["complete_hash_segments"] == 4
            and result["forged_signature_pairs"] == [[0, 0]] * 4
            for result in results
        ),
        "all_fresh_messages_accept": all(
            result["accepted_fresh_messages"] == result["message_trials"]
            for result in results
        ),
        "all_controls_pass": all(
            result["all_expected_checks_pass"] for result in results
        ),
        "zero_signing_queries": all(
            result["attack_signing_queries"] == 0 for result in results
        ),
        "no_row_exact_source_claim": all(
            result["row_exact_implementation_claimed"] is False for result in results
        ),
    }
    passed = len(results) == 18 and all(checks.values())
    total_trials = sum(result["message_trials"] for result in results)
    return {
        "schema": "eprint-audit.hppk-ds.paper-reproduction.v1",
        "mode": "full" if full else "quick",
        "seed_source": "public_reference_fixture" if reference else "operating_system",
        "scheme": "HPPK DS / IACR ePrint 2023/1768",
        "result": (
            "PASS: complete four-pair all-zero fresh-message forgery accepted "
            "for all 3 target and 15 benchmark rows at the published equation level"
            if passed
            else "FAIL: one or more registered equation-level checks failed"
        ),
        "status": "PASS" if passed else "FAIL",
        "banner": "ATTACK REPRODUCTION: PASS" if passed else "ATTACK REPRODUCTION: FAIL",
        "attack": {
            "classification": "zero-signing-query universal all-zero forgery",
            "ordinary_verifier_accepted": passed,
            "complete_signature_pairs_per_hash": 4,
            "fresh_message_trials": total_trials,
            "accepted_fresh_messages": sum(
                result["accepted_fresh_messages"] for result in results
            ),
            "signing_queries": 0,
            "secret_information_used": False,
        },
        "checks": checks,
        "digests": {
            "target_pdf_sha256": TARGET_PDF_SHA256,
            "benchmark_pdf_sha256": BENCHMARK_PDF_SHA256,
        },
        "environment": {"dependencies": "Python standard library", "workers": 1},
        "scope": {
            "paper_claim": "Eq. (28), Section 5.3, and four independently signed hash segments",
            "benchmark_claim": "Eq. (8) and all 15 Table 2 rows, with printed pseudocode ambiguities disclosed",
            "implementation_claim": "none; the separate pinned Go evidence is not row-exact",
            "wire_format_claim": "none; the paper does not define a canonical encoding",
        },
        "all_rows_pass": passed,
        "affected_rows_tested": len(results),
        "results": results,
        "workers": 1,
    }
