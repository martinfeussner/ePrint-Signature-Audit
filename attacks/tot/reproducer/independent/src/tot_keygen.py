#!/usr/bin/env python3
"""Generate one full-row TOT public map without persisting its secret key."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tot_public import (  # noqa: E402
    PublicKey,
    evaluate_public,
    expected_coefficient_count,
    load_public_key,
    sha256_file,
    write_public_key,
)


Q = 2
N = 128
D = 6
T_EXPONENT = 64
MASK = (1 << N) - 1
# x^128 + x^7 + x^2 + x + 1, the standard irreducible GCM polynomial.
MODULUS_LOW = (1 << 7) | (1 << 2) | (1 << 1) | 1


def gf_mul(left: int, right: int) -> int:
    result = 0
    left &= MASK
    right &= MASK
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        carry = (left >> (N - 1)) & 1
        left = (left << 1) & MASK
        if carry:
            left ^= MODULUS_LOW
    return result


def gf_pow_64(value: int) -> int:
    # t=64=2^6, so Frobenius powering is six field squarings.
    for _ in range(6):
        value = gf_mul(value, value)
    return value


def insert_basis_vector(basis: list[int], vector: int) -> bool:
    reduced = vector
    while reduced:
        pivot = reduced.bit_length() - 1
        if basis[pivot]:
            reduced ^= basis[pivot]
        else:
            basis[pivot] = reduced
            return True
    return False


def random_invertible_columns() -> tuple[int, ...]:
    basis = [0] * N
    columns: list[int] = []
    while len(columns) < N:
        candidate = secrets.randbits(N)
        if insert_basis_vector(basis, candidate):
            columns.append(candidate)
    return tuple(columns)


def apply_affine(columns: tuple[int, ...], offset: int, vector: int) -> int:
    result = offset
    remaining = vector
    while remaining:
        bit = remaining & -remaining
        result ^= columns[bit.bit_length() - 1]
        remaining ^= bit
    return result


def central_map(value: int, roots: tuple[int, ...]) -> int:
    product = 1
    for root in roots:
        product = gf_mul(product, value ^ root)
    return gf_pow_64(product)


def generate_distinct_roots() -> tuple[int, ...]:
    roots: set[int] = set()
    while len(roots) < D:
        roots.add(secrets.randbits(N))
    return tuple(sorted(roots))


def third_derivative(
    function, point: int, direction_a: int, direction_b: int, direction_c: int
) -> int:
    result = 0
    directions = (direction_a, direction_b, direction_c)
    for subset in range(8):
        value = point
        for i, direction in enumerate(directions):
            if (subset >> i) & 1:
                value ^= direction
        result ^= function(value)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    if args.public_key.exists():
        raise SystemExit("refusing to overwrite an existing public key")

    if __import__("math").gcd(T_EXPONENT, (1 << N) - 1) != 1:
        raise AssertionError("paper's gcd(t,q^n-1)=1 condition failed")

    roots = generate_distinct_roots()
    s_columns = random_invertible_columns()
    t_columns = random_invertible_columns()
    s_offset = secrets.randbits(N)
    t_offset = secrets.randbits(N)

    direct_evaluations = 0

    def secret_map(vector: int) -> int:
        nonlocal direct_evaluations
        direct_evaluations += 1
        after_s = apply_affine(s_columns, s_offset, vector)
        after_g = central_map(after_s, roots)
        return apply_affine(t_columns, t_offset, after_g)

    constant = secret_map(0)
    basis_values = tuple(secret_map(1 << i) for i in range(N))
    linear = tuple(value ^ constant for value in basis_values)

    cross: list[int] = []
    for i in range(N):
        for j in range(i + 1, N):
            pair_value = secret_map((1 << i) ^ (1 << j))
            cross.append(pair_value ^ basis_values[i] ^ basis_values[j] ^ constant)

    # Over F_2, use the canonical Boolean representative x_i^2 -> x_i.
    diagonal = (0,) * N
    public_key = PublicKey(
        q=Q,
        n=N,
        d=D,
        t=T_EXPONENT,
        modulus_low=MODULUS_LOW,
        constant=constant,
        linear=linear,
        diagonal=diagonal,
        cross=tuple(cross),
    )
    args.public_key.parent.mkdir(parents=True, exist_ok=True)
    write_public_key(args.public_key, public_key)

    # Key-generation conformance checks occur before this process exits.  They
    # are not available to the separately launched attacker or verifier.
    loaded = load_public_key(args.public_key)
    public_match_trials = 32
    for _ in range(public_match_trials):
        vector = secrets.randbits(N)
        if evaluate_public(loaded, vector) != secret_map(vector):
            raise AssertionError("public expansion does not match the secret composition")

    derivative_trials = 16
    for _ in range(derivative_trials):
        point = secrets.randbits(N)
        directions = tuple(secrets.randbits(N) for _ in range(3))
        if third_derivative(secret_map, point, *directions) != 0:
            raise AssertionError("central composition is not quadratic on F_2^128")

    coefficient_count = expected_coefficient_count(N)
    report = {
        "stage": "keygen_and_public_expansion",
        "status": "PASS",
        "parameters": {"q": Q, "n": N, "d": D, "t": T_EXPONENT},
        "field_modulus": "x^128 + x^7 + x^2 + x + 1",
        "g_definition": "product_{i=1}^6 (X-h_i)",
        "G_definition": "g(X)^64",
        "gcd_t_qn_minus_1": 1,
        "formal_coefficients_per_output": coefficient_count,
        "formal_public_key_bits": N * coefficient_count,
        "serialized_public_key_bytes": args.public_key.stat().st_size,
        "canonical_boolean_square_coefficients": "all_zero_folded_into_linear",
        "public_direct_match_trials": public_match_trials,
        "third_derivative_zero_trials": derivative_trials,
        "direct_secret_map_evaluations_inside_keygen_only": direct_evaluations,
        "secret_artifact_written": False,
        "public_key_sha256": sha256_file(args.public_key),
        "public_key_path": str(args.public_key),
    }
    print(json.dumps(report, sort_keys=True))

    # Do not serialize roots, affine maps, offsets, or an RNG seed.  Process
    # termination is the isolation boundary before the attacker is launched.
    del roots, s_columns, t_columns, s_offset, t_offset
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
