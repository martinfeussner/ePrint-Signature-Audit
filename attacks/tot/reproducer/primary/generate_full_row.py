#!/usr/bin/env python3
"""Generate and validate one conformant full-row TOT public-key fixture."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from tot_public import (
    AffineMap,
    BLOCK_BYTES,
    N,
    StableRng,
    frobenius_64,
    gf_mul,
    gf_pow,
    interpolate_public_map,
    poly_from_roots,
    random_invertible_columns,
    sha256_file,
    write_json,
    write_public_key,
)


V = 1 << 122  # 64^{-1} modulo 2^128-1.


def make_key():
    # The fixture is generated only after the prospective experiment seal.
    # Keep its seed ephemeral so the public-only attack process cannot obtain
    # the signing trapdoor from a deterministic seed embedded in its bundle.
    rng = StableRng(os.urandom(32))
    roots: list[int] = []
    while len(roots) < 6:
        candidate = rng.bits(N)
        if candidate not in roots:
            roots.append(candidate)
    source = AffineMap(tuple(random_invertible_columns(rng)), rng.bits(N))
    target = AffineMap(tuple(random_invertible_columns(rng)), rng.bits(N))
    return rng, tuple(roots), source, target


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()

    started = time.perf_counter()
    rng, roots, source, target = make_key()
    source_inverse = source.inverse()
    target_inverse = target.inverse()
    roots_tilde = tuple(frobenius_64(root) for root in roots)

    def central_original(value: int) -> int:
        return frobenius_64(poly_from_roots(value, roots))

    def central_normalized(value: int) -> int:
        return poly_from_roots(value, roots_tilde)

    def secret_public_map(signature: int) -> int:
        return target(central_original(source(signature)))

    inverse_checks = 0
    normalization_checks = 0
    signing_equation_checks = 0
    for _ in range(64):
        value = rng.bits(N)
        assert source_inverse(source(value)) == value
        assert target_inverse(target(value)) == value
        inverse_checks += 2

        source_value = source(value)
        assert central_original(source_value) == central_normalized(
            frobenius_64(source_value)
        )
        normalization_checks += 1

        message = secret_public_map(value)
        central_image = target_inverse(message)
        recovered_g_value = gf_pow(central_image, V)
        assert recovered_g_value == poly_from_roots(source_value, roots)
        # This known root is one of the roots that the specified Sign
        # procedure may select for this image-supported message.
        assert gf_pow(recovered_g_value, 64) == central_image
        signing_equation_checks += 2

    interpolation_started = time.perf_counter()
    public_key = interpolate_public_map(secret_public_map)
    interpolation_seconds = time.perf_counter() - interpolation_started
    write_public_key(args.public_key, public_key)

    public_map_checks = 0
    for fixed in (0, 1, (1 << N) - 1):
        assert public_key.evaluate(fixed) == secret_public_map(fixed)
        public_map_checks += 1
    for _ in range(512):
        value = rng.bits(N)
        assert public_key.evaluate(value) == secret_public_map(value)
        public_map_checks += 1

    # The first three values exercise the field implementation independently
    # of the public-map interpolation.
    field_checks = 0
    for _ in range(32):
        a = rng.bits(N)
        b = rng.bits(N)
        assert gf_mul(a, b) == gf_mul(b, a)
        assert gf_mul(a, 1) == a
        assert gf_mul(a, 0) == 0
        field_checks += 3

    elapsed = time.perf_counter() - started
    payload_bytes = public_key.coefficient_blocks * BLOCK_BYTES
    write_json(
        args.results,
        {
            "status": "PASS",
            "scheme": "TOT ePrint 2013/771",
            "parameter_row": {"q": 2, "n": 128, "d": 6, "t": 64},
            "field_modulus": "x^128+x^7+x^2+x+1",
            "inverse_exponent_v": str(V),
            "inverse_exponent_identity": (64 * V) % ((1 << N) - 1),
            "root_count": len(roots),
            "roots_distinct": len(set(roots)) == len(roots),
            "private_material_serialized": False,
            "public_coefficient_blocks": public_key.coefficient_blocks,
            "public_payload_bits": payload_bytes * 8,
            "public_payload_bytes": payload_bytes,
            "public_file_bytes": args.public_key.stat().st_size,
            "public_key_sha256": sha256_file(args.public_key),
            "canonical_diagonal_slots": N,
            "canonical_diagonal_nonzero": sum(
                public_key.quadratic[
                    i * N - i * (i - 1) // 2
                ]
                != 0
                for i in range(N)
            ),
            "checks": {
                "field": field_checks,
                "affine_inverse": inverse_checks,
                "frobenius_normalization": normalization_checks,
                "signing_equation": signing_equation_checks,
                "public_vs_secret_map": public_map_checks,
            },
            "interpolation_seconds": interpolation_seconds,
            "generator_wall_seconds": elapsed,
        },
    )


if __name__ == "__main__":
    main()
