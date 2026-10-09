#!/usr/bin/env python3
"""Deterministic Algorithms 2, 3, and 6 reconstruction for ePrint 2016/391.

This is an independent implementation from the target paper.  It represents
binary row vectors as Python integers; bit i is coordinate i.  Deterministic
PRNG seeds make the public-package run reproducible and are not used by the
attack.  This source was derived from the audit's sealed primary reproducer.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import platform
import random
import resource
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


TARGET_PDF_SHA256 = "b2bdf97bcef5dfec9928749d0d3fad0a97956494fc81989c52cd4472dec5755e"
TARGET_TEXT_SHA256 = "69fafe4ab6f7bb2fad7dfd6687f66dd19c5d86e738163ac5bdf75cb7fbd06d6f"


@dataclass(frozen=True)
class Params:
    name: str
    n: int
    k: int
    ell: int
    K: tuple[int, ...]
    N: tuple[int, ...]

    @property
    def blocks(self) -> int:
        return self.n // self.ell


PARAMS = (
    Params("PS1", 2142, 465, 3, (75,) + (15,) * 26, (60,) * 26 + (117,)),
    Params("PS2", 2244, 508, 4, (76,) + (16,) * 27, (60,) * 27 + (116,)),
)


@dataclass(frozen=True)
class Bits:
    value: int
    nbits: int


@dataclass(frozen=True)
class Permutation:
    block_order: tuple[int, ...]
    inner: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class PublicKey:
    params: Params
    matrices: tuple[tuple[int, ...], tuple[int, ...]]


@dataclass(frozen=True)
class PrivateKey:
    # Retained only for the separate key-consistency/correctness control.
    G: tuple[int, ...]
    split_G: tuple[tuple[int, ...], tuple[int, ...]]
    S: tuple[int, ...]
    permutations: tuple[Permutation, Permutation]


def popcount(x: int) -> int:
    return x.bit_count()


def error_set(ell: int) -> frozenset[int]:
    # The two printed sets E_3 and E_4 consist exactly of all words of
    # Hamming weight one or two.
    return frozenset(x for x in range(1 << ell) if popcount(x) in (1, 2))


def permute_small(x: int, permutation: Sequence[int]) -> int:
    out = 0
    for output_position, input_position in enumerate(permutation):
        out |= ((x >> input_position) & 1) << output_position
    return out


def valid_error_splits(ell: int) -> tuple[tuple[int, int], ...]:
    """Algorithm 3 for s=2, exhaustively checking all inner permutations."""
    permutations = tuple(itertools.permutations(range(ell)))
    E = error_set(ell)
    images = {
        x: frozenset(permute_small(x, p) for p in permutations)
        for x in range(1 << ell)
    }
    valid: list[tuple[int, int]] = []
    for a in range(1 << ell):
        for b in range(1 << ell):
            if all((pa ^ pb) in E for pa in images[a] for pb in images[b]):
                valid.append((a, b))
    return tuple(valid)


def matrix_product(vector: int, rows: Sequence[int]) -> int:
    out = 0
    remaining = vector
    while remaining:
        low = remaining & -remaining
        out ^= rows[low.bit_length() - 1]
        remaining ^= low
    return out


def apply_permutation(vector: int, spec: Permutation, ell: int) -> int:
    mask = (1 << ell) - 1
    out = 0
    for output_block, source_block in enumerate(spec.block_order):
        block = (vector >> (source_block * ell)) & mask
        block = permute_small(block, spec.inner[output_block])
        out |= block << (output_block * ell)
    return out


def build_staircase_generator(params: Params, rng: random.Random) -> tuple[int, ...]:
    assert sum(params.K) == params.k
    assert params.k + sum(params.N) == params.n
    assert len(params.K) == len(params.N)
    rows = [1 << r for r in range(params.k)]
    cumulative_k = 0
    column_offset = params.k
    for ki, ni in zip(params.K, params.N):
        cumulative_k += ki
        for r in range(cumulative_k):
            rows[r] |= rng.getrandbits(ni) << column_offset
        column_offset += ni
    assert column_offset == params.n
    return tuple(rows)


def random_unit_lower_triangular(k: int, rng: random.Random) -> tuple[int, ...]:
    # Every such matrix is invertible over F_2.
    return tuple((1 << r) | rng.getrandbits(r) for r in range(k))


def left_multiply(S: Sequence[int], matrix: Sequence[int]) -> tuple[int, ...]:
    return tuple(matrix_product(row, matrix) for row in S)


def make_permutations(params: Params, rng: random.Random) -> tuple[Permutation, Permutation]:
    common_order = list(range(params.blocks))
    rng.shuffle(common_order)
    specs: list[Permutation] = []
    for _ in range(2):
        inner = []
        for _j in range(params.blocks):
            p = list(range(params.ell))
            rng.shuffle(p)
            inner.append(tuple(p))
        specs.append(Permutation(tuple(common_order), tuple(inner)))
    return specs[0], specs[1]


def keygen(params: Params, seed: int) -> tuple[PublicKey, PrivateKey, dict]:
    """Algorithm 2 at a printed full row, with a fresh legitimate keypair."""
    started = time.perf_counter()
    rng = random.Random(seed)
    G = build_staircase_generator(params, rng)
    G1 = tuple(rng.getrandbits(params.n) for _ in range(params.k))
    G2 = tuple(g ^ a for g, a in zip(G, G1))
    assert all((a ^ b) == g for a, b, g in zip(G1, G2, G))
    S = random_unit_lower_triangular(params.k, rng)
    permutations = make_permutations(params, rng)
    SG1 = left_multiply(S, G1)
    SG2 = left_multiply(S, G2)
    pub1 = tuple(apply_permutation(row, permutations[0], params.ell) for row in SG1)
    pub2 = tuple(apply_permutation(row, permutations[1], params.ell) for row in SG2)
    public = PublicKey(params, (pub1, pub2))
    private = PrivateKey(G, (G1, G2), S, permutations)
    return public, private, {
        "seconds": time.perf_counter() - started,
        "seed": seed,
        "S_form": "unit lower triangular (invertible over F_2)",
        "G_form": "literal staircase generator of Equation (1)",
        "split_relation_checked": True,
        "shared_outer_block_permutation_checked": permutations[0].block_order
        == permutations[1].block_order,
    }


def key_fingerprint(public: PublicKey) -> str:
    h = hashlib.sha256()
    width = (public.params.n + 7) // 8
    for matrix in public.matrices:
        for row in matrix:
            h.update(row.to_bytes(width, "little"))
    return h.hexdigest()


def message_fingerprint(message: tuple[Bits, Bits]) -> str:
    h = hashlib.sha256()
    for component in message:
        h.update(component.nbits.to_bytes(4, "little"))
        width = (component.nbits + 7) // 8
        h.update(component.value.to_bytes(width, "little"))
    return h.hexdigest()


def check_bitvector(value: object, expected_bits: int) -> bool:
    return (
        isinstance(value, Bits)
        and value.nbits == expected_bits
        and isinstance(value.value, int)
        and 0 <= value.value < (1 << expected_bits)
    )


def ordinary_verify(
    public: PublicKey,
    message: object,
    signature: object,
    valid_splits: frozenset[tuple[int, int]],
) -> dict:
    """Literal Algorithm 6 plus unambiguous fixed-length format checks."""
    params = public.params
    if not isinstance(message, tuple) or len(message) != 2:
        return {"accepted": False, "checked_blocks": 0, "reason": "message arity"}
    if not all(check_bitvector(z, params.n) for z in message):
        return {"accepted": False, "checked_blocks": 0, "reason": "message format"}
    if not check_bitvector(signature, params.k):
        return {"accepted": False, "checked_blocks": 0, "reason": "signature format"}
    assert isinstance(signature, Bits)
    assert isinstance(message[0], Bits) and isinstance(message[1], Bits)
    e1 = matrix_product(signature.value, public.matrices[0]) ^ message[0].value
    e2 = matrix_product(signature.value, public.matrices[1]) ^ message[1].value
    mask = (1 << params.ell) - 1
    for j in range(params.blocks):
        pair = ((e1 >> (j * params.ell)) & mask, (e2 >> (j * params.ell)) & mask)
        if pair not in valid_splits:
            return {
                "accepted": False,
                "checked_blocks": j + 1,
                "first_invalid_block": j,
                "reason": "invalid error split",
            }
    return {"accepted": True, "checked_blocks": params.blocks, "reason": "accepted"}


def assemble_errors(
    params: Params, splits: Sequence[tuple[int, int]], offset: int
) -> tuple[int, int, list[tuple[int, int]]]:
    e1 = 0
    e2 = 0
    used = []
    for j in range(params.blocks):
        a, b = splits[(j + offset) % len(splits)]
        e1 |= a << (j * params.ell)
        e2 |= b << (j * params.ell)
        used.append((a, b))
    return e1, e2, used


def fixed_nonzero_sigma(k: int) -> int:
    sigma = 0
    for i in range(k):
        if ((7 * i + 3) % 19) in (0, 1, 5):
            sigma |= 1 << i
    assert sigma != 0
    return sigma


def forge(
    public: PublicKey,
    sigma_value: int,
    splits: Sequence[tuple[int, int]],
    split_offset: int,
) -> tuple[tuple[Bits, Bits], Bits, dict]:
    """Verification-first zero-query forgery using public data only."""
    started = time.perf_counter_ns()
    params = public.params
    e1, e2, used = assemble_errors(params, splits, split_offset)
    product1 = matrix_product(sigma_value, public.matrices[0])
    product2 = matrix_product(sigma_value, public.matrices[1])
    # Addition and subtraction coincide in characteristic two.
    z1 = product1 ^ e1
    z2 = product2 ^ e2
    message = (Bits(z1, params.n), Bits(z2, params.n))
    signature = Bits(sigma_value, params.k)
    elapsed_ns = time.perf_counter_ns() - started
    return message, signature, {
        "attack_ns_excluding_verification": elapsed_ns,
        "sigma_weight": popcount(sigma_value),
        "used_unique_valid_splits": len(set(used)),
        "all_public_valid_splits_covered": len(set(used)) == len(splits),
        "constructed_blocks": len(used),
        "private_inputs_used": [],
        "public_inputs_used": ["G1_pub", "G2_pub", "ValidErrorSplits", "printed dimensions"],
    }


def invalid_block_control(
    public: PublicKey,
    message: tuple[Bits, Bits],
    signature: Bits,
    block: int,
    valid_splits: frozenset[tuple[int, int]],
) -> dict:
    params = public.params
    mask = ((1 << params.ell) - 1) << (block * params.ell)
    product1 = matrix_product(signature.value, public.matrices[0])
    product2 = matrix_product(signature.value, public.matrices[1])
    # Force the recovered pair to (0,0), which Algorithm 3 excludes for both rows.
    z1 = (message[0].value & ~mask) | (product1 & mask)
    z2 = (message[1].value & ~mask) | (product2 & mask)
    result = ordinary_verify(
        public,
        (Bits(z1, params.n), Bits(z2, params.n)),
        signature,
        valid_splits,
    )
    result["forced_block"] = block
    result["forced_recovered_pair"] = [0, 0]
    return result


def format_controls(
    public: PublicKey,
    message: tuple[Bits, Bits],
    signature: Bits,
    valid_splits: frozenset[tuple[int, int]],
) -> dict:
    p = public.params
    controls = {
        "wrong_message_arity": ordinary_verify(public, (message[0],), signature, valid_splits),
        "wrong_message_bit_length": ordinary_verify(
            public, (Bits(message[0].value, p.n - 1), message[1]), signature, valid_splits
        ),
        "wrong_signature_bit_length": ordinary_verify(
            public, message, Bits(signature.value, p.k - 1), valid_splits
        ),
        "overwide_message_value": ordinary_verify(
            public, (Bits(1 << p.n, p.n), message[1]), signature, valid_splits
        ),
    }
    assert all(not item["accepted"] for item in controls.values())
    return controls


def signer_correctness_counterexample(
    public: PublicKey,
    private: PrivateKey,
    valid_splits: frozenset[tuple[int, int]],
) -> dict:
    """Exhibit the gap between Algorithm 5's decoder contract and Algorithm 6.

    Each unpermuted local pair is (unit_0, unit_1), so its sum has weight two
    and lies in E_l.  The pair is nevertheless not in ValidErrorSplits: an
    independent permutation can align the two units and make their sum zero.
    """
    p = public.params
    sigma = fixed_nonzero_sigma(p.k)
    s = matrix_product(sigma, private.S)  # sigma*S = s
    source_a = 1
    source_b = 2
    assert (source_a ^ source_b) in error_set(p.ell)
    assert (source_a, source_b) not in valid_splits
    a_vector = sum(source_a << (j * p.ell) for j in range(p.blocks))
    b_vector = sum(source_b << (j * p.ell) for j in range(p.blocks))
    y1 = matrix_product(s, private.split_G[0]) ^ a_vector
    y2 = matrix_product(s, private.split_G[1]) ^ b_vector
    aggregate_error = matrix_product(s, private.G) ^ y1 ^ y2
    expected_aggregate = a_vector ^ b_vector
    assert aggregate_error == expected_aggregate
    z1 = apply_permutation(y1, private.permutations[0], p.ell)
    z2 = apply_permutation(y2, private.permutations[1], p.ell)
    message = (Bits(z1, p.n), Bits(z2, p.n))
    signature = Bits(sigma, p.k)
    verification = ordinary_verify(public, message, signature, valid_splits)

    recovered1 = matrix_product(sigma, public.matrices[0]) ^ z1
    recovered2 = matrix_product(sigma, public.matrices[1]) ^ z2
    mask = (1 << p.ell) - 1
    invalid = 0
    for j in range(p.blocks):
        pair = (
            (recovered1 >> (j * p.ell)) & mask,
            (recovered2 >> (j * p.ell)) & mask,
        )
        invalid += pair not in valid_splits
    assert not verification["accepted"] and invalid == p.blocks
    return {
        "classification": "SEPARATE_SIGNER_CORRECTNESS_FAILURE_NOT_THE_FORGERY",
        "decoder_contract_witness": "s*G + y is in E_l for every block",
        "aggregate_error_blocks_valid": p.blocks,
        "verifier_invalid_blocks": invalid,
        "ordinary_verifier": verification,
        "local_witness": {
            "a": format(source_a, f"0{p.ell}b"),
            "b": format(source_b, f"0{p.ell}b"),
            "a_xor_b_weight": popcount(source_a ^ source_b),
            "aligned_by_independent_permutation_can_yield_zero": True,
        },
        "scope": (
            "Algorithm 5 only obtains an aggregate E_l decoding; this does not imply "
            "Algorithm 6's universal-permutation ValidErrorSplits predicate."
        ),
    }


def peak_rss_kib() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; macOS reports bytes.
    if sys.platform == "darwin":
        value //= 1024
    return int(value)


def run_parameter_set(params: Params, seed: int) -> dict:
    assert params.n % params.ell == 0
    expected_split_count = {3: 24, 4: 40}[params.ell]
    splits = valid_error_splits(params.ell)
    assert len(splits) == expected_split_count
    split_set = frozenset(splits)

    public, private, keygen_metrics = keygen(params, seed)
    public_fingerprint = key_fingerprint(public)
    no_signing_queries: set[str] = set()
    forged_message_ids: set[str] = set()
    variants = []
    for variant_name, sigma, offset, bad_block in (
        ("zero_sigma", 0, 0, 0),
        ("fixed_nonzero_sigma", fixed_nonzero_sigma(params.k), 1, params.blocks - 1),
    ):
        message, signature, metrics = forge(public, sigma, splits, offset)
        message_id = message_fingerprint(message)
        assert message_id not in no_signing_queries
        assert message_id not in forged_message_ids
        forged_message_ids.add(message_id)
        verify_started = time.perf_counter_ns()
        verification = ordinary_verify(public, message, signature, split_set)
        verification_ns = time.perf_counter_ns() - verify_started
        assert verification["accepted"]
        assert verification["checked_blocks"] == params.blocks
        invalid = invalid_block_control(
            public, message, signature, bad_block, split_set
        )
        assert not invalid["accepted"]
        variants.append(
            {
                "name": variant_name,
                "fresh_raw_message_sha256": message_id,
                "signing_queries": 0,
                "ordinary_verifier": verification,
                "verification_ns": verification_ns,
                "one_invalid_block_control": invalid,
                "format_controls": format_controls(
                    public, message, signature, split_set
                ),
                **metrics,
            }
        )

    correctness = signer_correctness_counterexample(public, private, split_set)
    return {
        "parameter_set": params.name,
        "printed_dimensions": {
            "n": params.n,
            "k": params.k,
            "ell": params.ell,
            "s": 2,
            "w": len(params.K),
            "K": list(params.K),
            "N": list(params.N),
            "blocks_n_over_ell": params.blocks,
        },
        "algorithm3": {
            "derived_valid_error_splits": len(splits),
            "paper_stated_count": expected_split_count,
            "exact_count_matches": len(splits) == expected_split_count,
            "exhaustive_permutation_definition_used": True,
        },
        "fresh_key": keygen_metrics,
        "public_key_sha256": public_fingerprint,
        "private_key_passed_to_forge": False,
        "variants": variants,
        "separate_signer_correctness_issue": correctness,
        "peak_rss_kib_after_row": peak_rss_kib(),
    }


def run_audit() -> dict:
    started = time.perf_counter()
    rows = [
        run_parameter_set(PARAMS[0], 0x2016039101),
        run_parameter_set(PARAMS[1], 0x2016039102),
    ]
    all_accept = all(
        variant["ordinary_verifier"]["accepted"]
        for row in rows
        for variant in row["variants"]
    )
    all_invalid_reject = all(
        not variant["one_invalid_block_control"]["accepted"]
        for row in rows
        for variant in row["variants"]
    )
    all_format_reject = all(
        not control["accepted"]
        for row in rows
        for variant in row["variants"]
        for control in variant["format_controls"].values()
    )
    output = {
        "experiment": "random-split-stgen-primary",
        "target": {
            "eprint": "2016/391",
            "pdf_sha256": TARGET_PDF_SHA256,
            "text_sha256": TARGET_TEXT_SHA256,
            "interface": "literal raw tuple z=(z1,z2) in Algorithms 5 and 6",
        },
        "attack_model": {
            "signing_queries": 0,
            "message_choice": "fresh attacker-chosen raw tuple",
            "secret_inputs": 0,
            "ordinary_verifier": "independent literal Algorithm 6 reconstruction",
        },
        "classification": (
            "PRACTICAL FULL-PARAMETER ZERO-QUERY FRESH-RAW-MESSAGE FORGERY "
            "AGAINST THE LITERAL ALGORITHMS 5-6 INTERFACE"
        ),
        "scope_exclusion": (
            "No claim is made against an unspecified external document-to-z hash/preimage "
            "wrapper, the predecessor scheme, or arbitrary documents."
        ),
        "rows": rows,
        "summary_checks": {
            "accepted_forgery_variants": sum(
                int(v["ordinary_verifier"]["accepted"])
                for r in rows
                for v in r["variants"]
            ),
            "expected_accepted_forgery_variants": 4,
            "all_forgery_variants_accept": all_accept,
            "all_four_one_invalid_block_controls_reject": all_invalid_reject,
            "all_format_controls_reject": all_format_reject,
            "total_positive_blocks_checked": sum(
                v["ordinary_verifier"]["checked_blocks"]
                for r in rows
                for v in r["variants"]
            ),
            "positive_blocks_by_parameter_and_variant": {
                "PS1_zero": 714,
                "PS1_nonzero": 714,
                "PS2_zero": 561,
                "PS2_nonzero": 561,
            },
        },
        "runtime": {
            "total_seconds": time.perf_counter() - started,
            "peak_rss_kib": peak_rss_kib(),
            "pid": os.getpid(),
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
        },
    }
    if not (all_accept and all_invalid_reject and all_format_reject):
        raise RuntimeError("one or more primary reproduction checks failed")
    return output


def main() -> int:
    print(json.dumps(run_audit(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
