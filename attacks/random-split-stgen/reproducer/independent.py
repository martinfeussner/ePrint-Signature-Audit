#!/usr/bin/env python3
"""Separately structured deterministic reproduction for ePrint 2016/391.

This implementation follows the audit's sealed independent reconstruction:
it derives Algorithm 3 directly, samples a dense full-rank scrambler, builds
fresh full-row Algorithm 2 public keys, constructs forgeries from public data,
and invokes an ordinary Algorithm 6 verifier.  Fixed seeds make the public
package output stable; the algebraic attack does not depend on them.
"""

from __future__ import annotations

import hashlib
import itertools
import random
from dataclasses import dataclass
from typing import Any, Sequence


TARGET_PDF_SHA256 = "b2bdf97bcef5dfec9928749d0d3fad0a97956494fc81989c52cd4472dec5755e"
TARGET_TEXT_SHA256 = "69fafe4ab6f7bb2fad7dfd6687f66dd19c5d86e738163ac5bdf75cb7fbd06d6f"

PROFILES: tuple[dict[str, Any], ...] = (
    {
        "name": "PS1",
        "n": 2142,
        "k": 465,
        "ell": 3,
        "s": 2,
        "w": 27,
        "K": [75] + [15] * 26,
        "N": [60] * 26 + [117],
        "expected_valid_split_count": 24,
        "seed": 0x391_51A_0001,
    },
    {
        "name": "PS2",
        "n": 2244,
        "k": 508,
        "ell": 4,
        "s": 2,
        "w": 28,
        "K": [76] + [16] * 27,
        "N": [60] * 27 + [116],
        "expected_valid_split_count": 40,
        "seed": 0x391_51A_0002,
    },
)


@dataclass(frozen=True)
class Vector:
    value: int
    bits: int


@dataclass(frozen=True)
class PublicKey:
    profile: dict[str, Any]
    matrices: tuple[tuple[int, ...], tuple[int, ...]]


def validate_profile(profile: dict[str, Any]) -> None:
    assert profile["s"] == 2
    assert len(profile["K"]) == profile["w"]
    assert len(profile["N"]) == profile["w"]
    assert sum(profile["K"]) == profile["k"]
    assert profile["k"] + sum(profile["N"]) == profile["n"]
    assert profile["n"] % profile["ell"] == 0


def error_set(ell: int) -> frozenset[int]:
    return frozenset(x for x in range(1 << ell) if x.bit_count() in (1, 2))


def permute_chunk(value: int, output_to_input: Sequence[int]) -> int:
    result = 0
    for output_bit, input_bit in enumerate(output_to_input):
        result |= ((value >> input_bit) & 1) << output_bit
    return result


def valid_error_splits(profile: dict[str, Any]) -> tuple[tuple[int, int], ...]:
    """Enumerate Algorithm 3's universal-permutation condition."""
    ell = profile["ell"]
    permutations = tuple(itertools.permutations(range(ell)))
    images = {
        value: tuple(permute_chunk(value, p) for p in permutations)
        for value in range(1 << ell)
    }
    errors = error_set(ell)
    valid = tuple(
        (left, right)
        for left in range(1 << ell)
        for right in range(1 << ell)
        if all(
            (left_image ^ right_image) in errors
            for left_image in images[left]
            for right_image in images[right]
        )
    )
    assert len(valid) == profile["expected_valid_split_count"]
    return valid


def row_combine(coefficients: int, rows: Sequence[int]) -> int:
    result = 0
    while coefficients:
        low = coefficients & -coefficients
        result ^= rows[low.bit_length() - 1]
        coefficients ^= low
    return result


def gf2_rank(rows: Sequence[int], columns: int) -> int:
    work = list(rows)
    rank = 0
    for column in range(columns - 1, -1, -1):
        pivot = next(
            (index for index in range(rank, len(work)) if (work[index] >> column) & 1),
            None,
        )
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        pivot_row = work[rank]
        for index in range(len(work)):
            if index != rank and ((work[index] >> column) & 1):
                work[index] ^= pivot_row
        rank += 1
        if rank == len(work):
            break
    return rank


def dense_invertible_matrix(size: int, rng: random.Random) -> tuple[tuple[int, ...], int]:
    attempts = 0
    while True:
        attempts += 1
        rows = tuple(rng.getrandbits(size) for _ in range(size))
        if gf2_rank(rows, size) == size:
            return rows, attempts


def staircase_generator(profile: dict[str, Any], rng: random.Random) -> tuple[int, ...]:
    rows = [1 << row for row in range(profile["k"])]
    coordinate = profile["k"]
    active_rows = 0
    for new_rows, columns in zip(profile["K"], profile["N"]):
        active_rows += new_rows
        for row in range(active_rows):
            rows[row] |= rng.getrandbits(columns) << coordinate
        coordinate += columns
    assert coordinate == profile["n"]
    return tuple(rows)


def left_multiply(left_rows: Sequence[int], right_rows: Sequence[int]) -> tuple[int, ...]:
    return tuple(row_combine(coefficients, right_rows) for coefficients in left_rows)


def shuffled(size: int, rng: random.Random) -> tuple[int, ...]:
    result = list(range(size))
    rng.shuffle(result)
    return tuple(result)


def apply_structured_permutation(
    rows: Sequence[int],
    ell: int,
    outer: Sequence[int],
    inner: Sequence[Sequence[int]],
) -> tuple[int, ...]:
    mask = (1 << ell) - 1
    output_rows = []
    for row in rows:
        output = 0
        for output_block, source_block in enumerate(outer):
            source = (row >> (source_block * ell)) & mask
            output |= permute_chunk(source, inner[output_block]) << (output_block * ell)
        output_rows.append(output)
    return tuple(output_rows)


def keygen(profile: dict[str, Any]) -> tuple[PublicKey, dict[str, Any]]:
    """Build a deterministic fresh-looking full-row Algorithm 2 key."""
    rng = random.Random(profile["seed"])
    base = staircase_generator(profile, rng)
    first_split = tuple(rng.getrandbits(profile["n"]) for _ in range(profile["k"]))
    second_split = tuple(a ^ b for a, b in zip(base, first_split))
    assert all(a ^ b == g for a, b, g in zip(first_split, second_split, base))
    scrambler, attempts = dense_invertible_matrix(profile["k"], rng)
    scrambled = (
        left_multiply(scrambler, first_split),
        left_multiply(scrambler, second_split),
    )
    blocks = profile["n"] // profile["ell"]
    common_outer = shuffled(blocks, rng)
    matrices = []
    for split in range(2):
        local = tuple(shuffled(profile["ell"], rng) for _ in range(blocks))
        matrices.append(
            apply_structured_permutation(
                scrambled[split], profile["ell"], common_outer, local
            )
        )
    public = PublicKey(profile, (matrices[0], matrices[1]))
    return public, {
        "deterministic_seed": profile["seed"],
        "full_rank_scrambler": True,
        "scrambler_draw_attempts": attempts,
        "staircase_shape_checked": True,
        "uniform_first_split": True,
        "split_relation_checked": True,
        "shared_outer_permutation": True,
        "independent_inner_permutations": True,
    }


def object_hash(values: Sequence[int], bits: int) -> str:
    digest = hashlib.sha256()
    width = (bits + 7) // 8
    for value in values:
        digest.update(value.to_bytes(width, "little"))
    return digest.hexdigest()


def public_key_hash(public: PublicKey) -> str:
    flattened = tuple(row for matrix in public.matrices for row in matrix)
    return object_hash(flattened, public.profile["n"])


def message_hash(message: Sequence[Vector]) -> str:
    digest = hashlib.sha256()
    for vector in message:
        digest.update(vector.bits.to_bytes(4, "little"))
        digest.update(vector.value.to_bytes((vector.bits + 7) // 8, "little"))
    return digest.hexdigest()


def vector_ok(candidate: object, bits: int) -> bool:
    return (
        isinstance(candidate, Vector)
        and candidate.bits == bits
        and isinstance(candidate.value, int)
        and 0 <= candidate.value < (1 << bits)
    )


def verify(
    public: PublicKey,
    message: object,
    signature: object,
    valid: frozenset[tuple[int, int]],
) -> dict[str, Any]:
    profile = public.profile
    if not isinstance(message, tuple) or len(message) != 2:
        return {"accepted": False, "checked_blocks": 0, "reason": "message arity"}
    if not all(vector_ok(component, profile["n"]) for component in message):
        return {"accepted": False, "checked_blocks": 0, "reason": "message format"}
    if not vector_ok(signature, profile["k"]):
        return {"accepted": False, "checked_blocks": 0, "reason": "signature format"}
    assert isinstance(signature, Vector)
    assert isinstance(message[0], Vector) and isinstance(message[1], Vector)
    recovered = tuple(
        row_combine(signature.value, public.matrices[index]) ^ message[index].value
        for index in range(2)
    )
    mask = (1 << profile["ell"]) - 1
    for block in range(profile["n"] // profile["ell"]):
        split = tuple(
            (component >> (block * profile["ell"])) & mask
            for component in recovered
        )
        if split not in valid:
            return {
                "accepted": False,
                "checked_blocks": block + 1,
                "first_invalid_block": block,
                "reason": "invalid error split",
            }
    return {
        "accepted": True,
        "checked_blocks": profile["n"] // profile["ell"],
        "reason": "accepted",
    }


def assembled_errors(
    profile: dict[str, Any], valid: Sequence[tuple[int, int]], offset: int
) -> tuple[int, int]:
    components = [0, 0]
    for block in range(profile["n"] // profile["ell"]):
        selected = valid[(block + offset) % len(valid)]
        for index in range(2):
            components[index] |= selected[index] << (block * profile["ell"])
    return components[0], components[1]


def forge(
    public: PublicKey,
    sigma: int,
    valid: Sequence[tuple[int, int]],
    offset: int,
) -> tuple[tuple[Vector, Vector], Vector]:
    profile = public.profile
    errors = assembled_errors(profile, valid, offset)
    z = tuple(
        Vector(row_combine(sigma, public.matrices[index]) ^ errors[index], profile["n"])
        for index in range(2)
    )
    assert len(z) == 2
    return (z[0], z[1]), Vector(sigma, profile["k"])


def invalid_block_control(
    public: PublicKey,
    message: tuple[Vector, Vector],
    signature: Vector,
    valid: frozenset[tuple[int, int]],
) -> dict[str, Any]:
    profile = public.profile
    mask = (1 << profile["ell"]) - 1
    changed = []
    for index in range(2):
        product = row_combine(signature.value, public.matrices[index])
        # Put z=product in block zero, so Algorithm 6 recovers (0,0).
        changed.append(Vector((message[index].value & ~mask) | (product & mask), profile["n"]))
    return verify(public, (changed[0], changed[1]), signature, valid)


def changed_signature_control(
    public: PublicKey,
    message: tuple[Vector, Vector],
    signature: Vector,
    valid: frozenset[tuple[int, int]],
) -> dict[str, Any]:
    for bit in range(public.profile["k"]):
        changed = Vector(signature.value ^ (1 << bit), public.profile["k"])
        result = verify(public, message, changed, valid)
        if not result["accepted"]:
            result["flipped_signature_bit"] = bit
            return result
    raise RuntimeError("could not construct a rejecting signature control")


def format_controls(
    public: PublicKey,
    message: tuple[Vector, Vector],
    signature: Vector,
    valid: frozenset[tuple[int, int]],
) -> dict[str, dict[str, Any]]:
    n = public.profile["n"]
    k = public.profile["k"]
    return {
        "wrong_message_arity": verify(public, (message[0],), signature, valid),
        "wrong_message_width": verify(
            public, (Vector(message[0].value, n - 1), message[1]), signature, valid
        ),
        "wrong_signature_width": verify(public, message, Vector(signature.value, k - 1), valid),
        "out_of_space_message": verify(
            public, (Vector(1 << n, n), message[1]), signature, valid
        ),
    }


def run_profile(profile: dict[str, Any]) -> dict[str, Any]:
    validate_profile(profile)
    valid_sequence = valid_error_splits(profile)
    valid = frozenset(valid_sequence)
    assert (0, 0) not in valid
    public, key_checks = keygen(profile)
    nonzero_rng = random.Random(profile["seed"] ^ 0xF0A6E)
    nonzero_sigma = nonzero_rng.getrandbits(profile["k"])
    assert nonzero_sigma != 0
    variants = []
    for name, sigma, offset in (
        ("zero_sigma", 0, 0),
        ("deterministic_nonzero_sigma", nonzero_sigma, 7),
    ):
        message, signature = forge(public, sigma, valid_sequence, offset)
        accepted = verify(public, message, signature, valid)
        invalid = invalid_block_control(public, message, signature, valid)
        changed_signature = changed_signature_control(public, message, signature, valid)
        formats = format_controls(public, message, signature, valid)
        assert accepted["accepted"]
        assert not invalid["accepted"] and not changed_signature["accepted"]
        assert all(not item["accepted"] for item in formats.values())
        variants.append(
            {
                "name": name,
                "message_sha256": message_hash(message),
                "sigma_weight": sigma.bit_count(),
                "signing_queries": 0,
                "ordinary_verifier": accepted,
                "one_invalid_block_control": invalid,
                "changed_signature_control": changed_signature,
                "format_controls": formats,
            }
        )
    return {
        "profile": profile["name"],
        "dimensions": {
            key: profile[key] for key in ("n", "k", "ell", "s", "w", "K", "N")
        },
        "valid_error_splits": len(valid_sequence),
        "algorithm3_exact": len(valid_sequence) == profile["expected_valid_split_count"],
        "public_key_sha256": public_key_hash(public),
        "key_checks": key_checks,
        "private_material_passed_to_forge": False,
        "variants": variants,
    }


def run_audit() -> dict[str, Any]:
    rows = [run_profile(profile) for profile in PROFILES]
    return {
        "target": {
            "eprint": "2016/391",
            "pdf_sha256": TARGET_PDF_SHA256,
            "text_sha256": TARGET_TEXT_SHA256,
            "interface": "literal raw z tuple in Algorithms 5-6",
        },
        "attack_model": {
            "public_key_only": True,
            "signing_queries": 0,
            "secret_inputs": 0,
        },
        "rows": rows,
        "scope_exclusion": (
            "No arbitrary-document claim and no claim against an unspecified "
            "external document-to-z hash wrapper."
        ),
    }
