#!/usr/bin/env python3
"""Paper-level Construction 1 verifier and zero-vector reproduction.

Only Python's standard library is used.  The implementation intentionally
keeps the public matrix at its complete advertised dimensions and evaluates
the general matrix-vector product; it contains no zero-vector shortcut.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import sys
from array import array
from dataclasses import dataclass
from typing import Iterable


PAPER_SHA256 = "cbbbb33cacef911548d52de7990eff74479dbb2e4ab9467974770107458cabeb"
SCHEMA = "eprint-audit.higher-bit-approx-isis.public-reproduction.v1"


@dataclass(frozen=True)
class ParameterRow:
    row_id: str
    claimed_aisis_bits: str
    n: int
    b: int
    k: int
    ell: int
    d: int
    s_tenths: int
    m: int
    table_y_norm_tenths: int
    table_error_norm_tenths: int

    @property
    def q(self) -> int:
        return self.b**self.k

    @property
    def b_to_d(self) -> int:
        return self.b**self.d

    @property
    def coefficient_modulus(self) -> int:
        return self.q // self.b_to_d


ROWS = (
    ParameterRow(
        "TW-512-b2", "75.0", 512, 2, 16, 11, 11, 14530, 3584, 10722, 4288069
    ),
    ParameterRow(
        "TW-1024-b2",
        "155.4",
        1024,
        2,
        16,
        11,
        11,
        21639,
        7168,
        15355,
        6076016,
    ),
    ParameterRow(
        "TW-1024-b4",
        "153.9",
        1024,
        4,
        8,
        3,
        3,
        39893,
        7168,
        505337,
        5967045,
    ),
)


class ReproductionFailure(RuntimeError):
    """Raised when a checked reproduction invariant fails."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expand(seed: bytes, label: bytes, length: int) -> bytes:
    domain = b"ePrintAudit/HBAISIS-public-reproducer/v1\x00"
    framed = len(label).to_bytes(4, "little") + label
    return hashlib.shake_256(domain + framed + seed).digest(length)


def _u16_little_endian(raw: bytes) -> array:
    values = array("H")
    values.frombytes(raw)
    if sys.byteorder != "little":
        values.byteswap()
    return values


def _encode_u16_little_endian(values: array) -> bytes:
    if sys.byteorder == "little":
        return values.tobytes()
    copy = array("H", values)
    copy.byteswap()
    return copy.tobytes()


def generate_public_matrix(seed: bytes, row: ParameterRow) -> tuple[array, str]:
    """Generate a uniform full-size matrix in Z_(q/b^d)^(n x m)."""
    modulus = row.coefficient_modulus
    if modulus <= 0 or modulus & (modulus - 1):
        raise ReproductionFailure("the advertised matrix modulus is not a power of two")
    count = row.n * row.m
    raw = expand(seed, b"matrix/" + row.row_id.encode("ascii"), 2 * count)
    matrix = _u16_little_endian(raw)
    mask = modulus - 1
    for index in range(count):
        matrix[index] &= mask
    return matrix, sha256(_encode_u16_little_endian(matrix))


def matrix_vector_product_mod_q(
    matrix: array, row: ParameterRow, signature: list[int]
) -> list[int]:
    """Evaluate b^d A x mod q using the ordinary, general product path."""
    if len(matrix) != row.n * row.m:
        raise ReproductionFailure("public-matrix dimension mismatch")
    if len(signature) != row.m:
        raise ReproductionFailure("signature dimension mismatch")
    if any(value < 0 or value >= row.coefficient_modulus for value in signature):
        raise ReproductionFailure("signature coordinate is outside Z_(q/b^d)")

    result = [0] * row.n
    for matrix_row in range(row.n):
        offset = matrix_row * row.m
        accumulator = 0
        for column, coefficient in enumerate(signature):
            accumulator += matrix[offset + column] * coefficient
        result[matrix_row] = (row.b_to_d * accumulator) % row.q
    return result


def hash_to_vector(message: bytes, row: ParameterRow) -> tuple[list[int], str]:
    """An explicit uniform random-oracle adapter for q=2^16."""
    if row.q != 1 << 16:
        raise ReproductionFailure("the public adapter is defined only for q=2^16")
    domain = b"ePrintAudit/HBAISIS-public-random-oracle/v1\x00"
    raw = hashlib.shake_256(
        domain + len(message).to_bytes(8, "little") + message
    ).digest(2 * row.n)
    return list(_u16_little_endian(raw)), sha256(raw)


def message_for(seed: bytes, row: ParameterRow, trial: int) -> bytes:
    nonce = expand(
        seed,
        b"message/" + row.row_id.encode("ascii") + trial.to_bytes(4, "little"),
        32,
    )
    return (
        b"ePrintAudit/HBAISIS/fresh-message/v1/"
        + row.row_id.encode("ascii")
        + b"/"
        + trial.to_bytes(4, "little")
        + b"/"
        + nonce
    )


def residual_norm_squared(
    product: list[int], target: list[int], q: int, lift: str
) -> int:
    if len(product) != len(target):
        raise ReproductionFailure("product/target dimension mismatch")
    total = 0
    for left, right in zip(product, target, strict=True):
        residue = (left - right) % q
        if lift == "centered":
            if residue > q // 2:
                residue -= q
        elif lift != "canonical":
            raise ReproductionFailure(f"unknown lift: {lift}")
        total += residue * residue
    return total


def ordinary_verify_from_product(
    *,
    signature_norm_squared: int,
    product: list[int],
    target: list[int],
    q: int,
    lift: str,
    beta_squared_times_100: int,
    alpha_squared_times_100: int,
) -> tuple[bool, int]:
    """Construction 1's two ordinary verification inequalities.

    Threshold squares are scaled by 100 so the one-decimal table values can be
    compared exactly with integer arithmetic.
    """
    if 100 * signature_norm_squared > beta_squared_times_100:
        return False, -1
    norm_squared = residual_norm_squared(product, target, q, lift)
    return 100 * norm_squared <= alpha_squared_times_100, norm_squared


def _digest_hex_items(items: Iterable[str]) -> str:
    return sha256(b"".join(bytes.fromhex(item) for item in items))


def reproduce_row(seed: bytes, row: ParameterRow, trials: int) -> dict[str, object]:
    q = row.q
    bd = row.b_to_d

    # beta=s and alpha=sqrt(n)b^d s are conservative lower endpoints of the
    # paper's Section 6.4 prescription.  Scaling by 100 avoids float rounding.
    beta_squared_times_100 = row.s_tenths**2
    alpha_floor_squared_times_100 = row.n * (bd * row.s_tenths) ** 2
    table_error_squared_times_100 = row.table_error_norm_tenths**2
    canonical_max_squared = row.n * (q - 1) ** 2
    centered_max_squared = row.n * (q // 2) ** 2

    if bd * row.s_tenths <= 10 * (q - 1):
        raise ReproductionFailure(f"analytic domination failed for {row.row_id}")
    if 100 * canonical_max_squared > alpha_floor_squared_times_100:
        raise ReproductionFailure(f"canonical target space is not covered for {row.row_id}")
    if 100 * centered_max_squared > alpha_floor_squared_times_100:
        raise ReproductionFailure(f"centered target space is not covered for {row.row_id}")

    matrix, matrix_digest = generate_public_matrix(seed, row)
    zero_signature = [0] * row.m
    unit_signature = [0] * row.m
    unit_signature[0] = 1

    # Both products use the same general routine.  Reuse across messages is a
    # deterministic optimization for an unchanged public key and signature.
    zero_product = matrix_vector_product_mod_q(matrix, row, zero_signature)
    unit_product = matrix_vector_product_mod_q(matrix, row, unit_signature)
    if any(zero_product):
        raise ReproductionFailure("ordinary matrix path did not map zero to zero")
    if unit_product == zero_product:
        raise ReproductionFailure("in-domain unit-vector matrix diagnostic failed")

    counts = {
        lift: {
            "section_6_4_accept": 0,
            "section_6_4_reject": 0,
            "table_radius_accept": 0,
            "table_radius_reject": 0,
        }
        for lift in ("canonical", "centered")
    }
    message_hashes: list[str] = []
    oracle_hashes: list[str] = []
    residual_hashes: dict[str, list[str]] = {"canonical": [], "centered": []}
    distinct_norms: dict[str, set[int]] = {"canonical": set(), "centered": set()}

    for trial in range(trials):
        message = message_for(seed, row, trial)
        target, oracle_digest = hash_to_vector(message, row)
        message_hashes.append(sha256(message))
        oracle_hashes.append(oracle_digest)
        for lift in ("canonical", "centered"):
            accepts, norm_squared = ordinary_verify_from_product(
                signature_norm_squared=0,
                product=zero_product,
                target=target,
                q=q,
                lift=lift,
                beta_squared_times_100=beta_squared_times_100,
                alpha_squared_times_100=alpha_floor_squared_times_100,
            )
            table_accepts, table_norm_squared = ordinary_verify_from_product(
                signature_norm_squared=0,
                product=zero_product,
                target=target,
                q=q,
                lift=lift,
                beta_squared_times_100=beta_squared_times_100,
                alpha_squared_times_100=table_error_squared_times_100,
            )
            if table_norm_squared != norm_squared:
                raise ReproductionFailure("ordinary verifier paths disagree")
            counts[lift]["section_6_4_accept" if accepts else "section_6_4_reject"] += 1
            counts[lift]["table_radius_accept" if table_accepts else "table_radius_reject"] += 1
            distinct_norms[lift].add(norm_squared)
            residual_hashes[lift].append(
                sha256(norm_squared.to_bytes((norm_squared.bit_length() + 7) // 8 or 1, "big"))
            )

    if len(set(message_hashes)) != trials or len(set(oracle_hashes)) != trials:
        raise ReproductionFailure("fresh-message/hash distinctness diagnostic failed")
    for lift in ("canonical", "centered"):
        if counts[lift]["section_6_4_accept"] != trials:
            raise ReproductionFailure(f"target forgery rejected under {lift} lift")
        if len(distinct_norms[lift]) < 2:
            raise ReproductionFailure(f"message-dependent norm diagnostic failed for {lift}")

    # A precommitted, well-formed target-space diagnostic.  It uses x=0 and a
    # vector in Z_q^n, and tests the same norm/comparison path against Figure
    # 3's printed empirical ||e|| value.  That printed value is *not* treated
    # as alpha.  This avoids an out-of-domain x or a post-selected threshold.
    diagnostic_target = [q // 2] * row.n
    boundary_diagnostic: dict[str, object] = {}
    for lift in ("canonical", "centered"):
        accepts, norm_squared = ordinary_verify_from_product(
            signature_norm_squared=0,
            product=zero_product,
            target=diagnostic_target,
            q=q,
            lift=lift,
            beta_squared_times_100=beta_squared_times_100,
            alpha_squared_times_100=table_error_squared_times_100,
        )
        if accepts:
            raise ReproductionFailure(f"precommitted {lift} rejection diagnostic failed")
        boundary_diagnostic[lift] = {
            "accepts": accepts,
            "residual_norm_squared": norm_squared,
        }

    first_target, _ = hash_to_vector(message_for(seed, row, 0), row)
    unit_results: dict[str, object] = {}
    for lift in ("canonical", "centered"):
        accepts, norm_squared = ordinary_verify_from_product(
            signature_norm_squared=1,
            product=unit_product,
            target=first_target,
            q=q,
            lift=lift,
            beta_squared_times_100=beta_squared_times_100,
            alpha_squared_times_100=alpha_floor_squared_times_100,
        )
        unit_results[lift] = {
            "section_6_4_accepts": accepts,
            "residual_norm_squared": norm_squared,
        }

    return {
        "id": row.row_id,
        "claimed_aisis_bits": row.claimed_aisis_bits,
        "paper_parameters": {
            "n": row.n,
            "m": row.m,
            "b": row.b,
            "k": row.k,
            "l": row.ell,
            "d": row.d,
            "s": f"{row.s_tenths / 10:.1f}",
            "table_y_norm": f"{row.table_y_norm_tenths / 10:.1f}",
            "table_error_norm": f"{row.table_error_norm_tenths / 10:.1f}",
        },
        "instantiation": {
            "q": q,
            "q_rule": "q=b^k",
            "b_to_d": bd,
            "matrix_coefficient_modulus": row.coefficient_modulus,
            "matrix_dimensions": [row.n, row.m],
            "matrix_entries": row.n * row.m,
            "matrix_sha256": matrix_digest,
        },
        "analytic": {
            "b_to_d_times_s": f"{bd * row.s_tenths / 10:.1f}",
            "q_minus_one": q - 1,
            "domination_ratio_numerator_tenths": bd * row.s_tenths,
            "domination_ratio_denominator_tenths": 10 * (q - 1),
            "domination_ratio_decimal": f"{(bd * row.s_tenths) / (10 * (q - 1)):.6f}",
            "alpha_floor_squared_times_100": alpha_floor_squared_times_100,
            "canonical_max_squared": canonical_max_squared,
            "centered_max_squared": centered_max_squared,
            "universal_for_both_lifts": True,
        },
        "target_checks": counts,
        "message_evidence": {
            "messages": trials,
            "distinct_message_hashes": len(set(message_hashes)),
            "distinct_oracle_hashes": len(set(oracle_hashes)),
            "message_set_sha256": _digest_hex_items(message_hashes),
            "oracle_set_sha256": _digest_hex_items(oracle_hashes),
            "residual_norm_set_sha256": {
                lift: _digest_hex_items(values) for lift, values in residual_hashes.items()
            },
            "distinct_residual_norms": {
                lift: len(values) for lift, values in distinct_norms.items()
            },
        },
        "diagnostics": {
            "matrix_path": {
                "zero_product_is_zero": not any(zero_product),
                "unit_signature_in_domain": True,
                "unit_product_differs": unit_product != zero_product,
                "unit_signature_results": unit_results,
            },
            "precommitted_target_vector": {
                "definition": "the constant vector (q/2,...,q/2) in Z_q^n",
                "purpose": "in-domain norm/comparator rejection diagnostic only",
                "comparison_radius": "Figure 3 printed empirical ||e||; not alpha",
                "results": boundary_diagnostic,
            },
            "sampled_table_radius_counts": {
                "purpose": "diagnostic only; Figure 3's printed ||e|| is not alpha",
                "counts": counts,
            },
        },
        "status": "PASS",
    }


def build_report(seed: bytes, trials: int, seed_source: str) -> dict[str, object]:
    if len(seed) != 32:
        raise ReproductionFailure("seed must contain exactly 32 bytes")
    if trials < 2 or trials > 256:
        raise ReproductionFailure("trials must be in 2..256")
    rows = [reproduce_row(seed, row, trials) for row in ROWS]
    target_accepts = sum(
        int(row["target_checks"][lift]["section_6_4_accept"])
        for row in rows
        for lift in ("canonical", "centered")
    )
    expected = len(rows) * 2 * trials
    if target_accepts != expected:
        raise ReproductionFailure("aggregate target count mismatch")
    rows_passed = sum(row["status"] == "PASS" for row in rows)
    compatibility_results: list[dict[str, object]] = []
    for row in rows:
        lift_checks = row["target_checks"]
        diagnostics = row["diagnostics"]["precommitted_target_vector"]["results"]
        checks = {
            "both_residue_lifts_accept_all_targets": all(
                lift_checks[lift]["section_6_4_accept"] == trials
                for lift in ("canonical", "centered")
            ),
            "full_advertised_matrix_dimensions": (
                row["instantiation"]["matrix_dimensions"]
                == [row["paper_parameters"]["n"], row["paper_parameters"]["m"]]
            ),
            "general_matrix_path_is_live": (
                row["diagnostics"]["matrix_path"]["zero_product_is_zero"]
                and row["diagnostics"]["matrix_path"]["unit_product_differs"]
            ),
            "precommitted_in_domain_diagnostics_reject": all(
                diagnostics[lift]["accepts"] is False
                for lift in ("canonical", "centered")
            ),
            "universal_target_space_bound": row["analytic"][
                "universal_for_both_lifts"
            ],
        }
        compatibility_results.append(
            {
                "all_expected_checks_pass": all(checks.values()),
                "checks": checks,
                "messages_tested": trials,
                "parameter_row": row["id"],
                "signing_queries": 0,
                "target_checks_accepted": sum(
                    lift_checks[lift]["section_6_4_accept"]
                    for lift in ("canonical", "centered")
                ),
            }
        )

    all_rows_pass = rows_passed == len(rows) and all(
        result["all_expected_checks_pass"] for result in compatibility_results
    )
    checks = {
        "all_affected_parameter_rows_pass": all_rows_pass,
        "all_target_checks_accept": target_accepts == expected,
        "fresh_message_forgery": True,
        "ordinary_verifier_equations_used": True,
        "precommitted_in_domain_diagnostics_reject": all(
            result["checks"]["precommitted_in_domain_diagnostics_reject"]
            for result in compatibility_results
        ),
        "zero_signing_queries": True,
    }
    digests = {
        "matrix_set_sha256": _digest_hex_items(
            row["instantiation"]["matrix_sha256"] for row in rows
        ),
        "message_set_sha256": _digest_hex_items(
            row["message_evidence"]["message_set_sha256"] for row in rows
        ),
        "oracle_set_sha256": _digest_hex_items(
            row["message_evidence"]["oracle_set_sha256"] for row in rows
        ),
        "target_pdf_sha256": PAPER_SHA256,
    }
    return {
        "all_rows_pass": all_rows_pass,
        "attack": {
            "fresh_message": True,
            "message_scope": "every fresh attacker-chosen message",
            "public_inputs_only": True,
            "result": "universal zero-vector fresh-message forgery",
            "signing_queries": 0,
        },
        "schema": SCHEMA,
        "status": "PASS",
        "banner": "ATTACK REPRODUCTION: PASS",
        "checks": checks,
        "conclusion": "ZERO_VECTOR_UNIVERSAL_FORGERY_UNDER_SECTION_6_4_BOUNDS",
        "digests": digests,
        "environment": {
            "dependencies": "Python 3.10+ standard library",
            "workers": 1,
        },
        "paper_sha256": PAPER_SHA256,
        "seed_hex": seed.hex(),
        "seed_source": seed_source,
        "workers": 1,
        "rows_tested": len(rows),
        "rows_passed": rows_passed,
        "trials_per_row": trials,
        "messages_tested": len(rows) * trials,
        "lifts": ["canonical", "centered"],
        "target_checks": expected,
        "accepted_target_checks": target_accepts,
        "rejected_target_checks": expected - target_accepts,
        "result": "ZERO_VECTOR_UNIVERSAL_FORGERY_UNDER_SECTION_6_4_BOUNDS",
        "results": compatibility_results,
        "signing_queries": 0,
        "secret_key_used": False,
        "fresh_message_forgery": True,
        "ordinary_verifier_equations_used": True,
        "matrix_vector_implementation": "general full-dimension product; no zero shortcut",
        "honest_acceptance_attempted": False,
        "honest_acceptance_omission_reason": (
            "The paper omits concrete alpha, beta, sigma, lift, hash/serialization "
            "rules, and a complete public honest-signing instantiation."
        ),
        "scope": {
            "claim": "Construction 1 under every alpha,beta completion obeying Section 6.4",
            "rows": "all three Figure 3 columns labelled This work",
            "q_execution": "q=b^k",
            "q_proof": "uses only q<=b^k",
            "hash_adapter": "explicit SHAKE256 uniform random-oracle instantiation",
            "implementation_replay_claimed": False,
        },
        "rows": rows,
    }


def fresh_seed() -> bytes:
    return secrets.token_bytes(32)


def reference_seed(label: str) -> bytes:
    return hashlib.sha256(
        b"ePrintAudit/HBAISIS/public-reference/2026-10-14/" + label.encode("ascii")
    ).digest()

