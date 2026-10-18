#!/usr/bin/env python3
"""Independent eight-seed DSS-MS full-profile public reproducer.

This is a standalone implementation of the relevant algorithms in IACR
ePrint 2026/041 and the frozen source snapshot.  It deliberately uses actual
BLS12-381 G1 arithmetic and the snapshot's SHA-256 transcript behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import resource
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


# BLS12-381 base field, prime subgroup order, and canonical G1 generator.
FIELD_P = int(
    "1a0111ea397fe69a4b1ba7b6434bacd7"
    "64774b84f38512bf6730d2a0f6b0f624"
    "1eabfffeb153ffffb9feffffffffaaab",
    16,
)
ORDER_Q = int(
    "73eda753299d7d483339d80809a1d805"
    "53bda402fffe5bfeffffffff00000001",
    16,
)
GENERATOR = (
    int(
        "17f1d3a73197d7942695638c4fa9ac0f"
        "c3688c4f9774b905a14e3a3f171bac58"
        "6c55e83ff97a1aeffb3af00adb22c6bb",
        16,
    ),
    int(
        "08b3f481e3aaa0f1a09e30ed741d8ae4"
        "fcf5e095d5d00af600db18cb2c04b3ed"
        "d03cc744a2888ae40caa232946c5e7e1",
        16,
    ),
)

Point = Optional[tuple[int, int]]
INF: Point = None

SEALED_SEEDS = [
    "01d2ee4d7ed3cde04ed71f758a74a60c6e94489875dc68022ff064fcdc275513",
    "4cc55c8c68abaebc98be05229c99a3c5ee206b35958047d49a11f62735cc18bd",
    "ee6c4c6c0f24229d627a219ffc2033780be6afaf905557cf7e8fd333eec98e45",
    "61f602e7b6be511cc5f4a68eeeb002ef260ff84285bc4278f2e28ca658525fb0",
    "2897cdf3d890ecccbd5eafa2bbe34647ece515a4493a67b24da97e60e2b98a5f",
    "8a5eeb3e49a15bae04c914a77a75636d71f929717a25d8ac93a803a3e01b0fcf",
    "e78bc7bf58e8272986941981fd6ad7d6f00a4cdd62388be6d0946e38d4d3d33a",
    "4009135f2b26d0c272feaf410046876248d6a8dee03faba04a24eac8bce73204",
]

INITIAL_N = 3000
JOIN_COUNT = 20
MAX_POST_KGEN_EPOCH = 4
WORKERS = 1


def point_on_curve(point: Point) -> bool:
    if point is INF:
        return True
    x, y = point
    if not (0 <= x < FIELD_P and 0 <= y < FIELD_P):
        return False
    return (y * y - (x * x * x + 4)) % FIELD_P == 0


def point_neg(point: Point) -> Point:
    if point is INF:
        return INF
    return (point[0], (-point[1]) % FIELD_P)


def point_add(left: Point, right: Point) -> Point:
    if left is INF:
        return right
    if right is INF:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % FIELD_P == 0:
            return INF
        if y1 == 0:
            return INF
        slope = (3 * x1 * x1) * pow(2 * y1, -1, FIELD_P) % FIELD_P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % FIELD_P, -1, FIELD_P) % FIELD_P
    x3 = (slope * slope - x1 - x2) % FIELD_P
    y3 = (slope * (x1 - x3) - y1) % FIELD_P
    return (x3, y3)


def point_mul_raw(scalar: int, point: Point) -> Point:
    """Multiply without reducing scalar; required for subgroup tests."""
    if scalar < 0:
        return point_mul_raw(-scalar, point_neg(point))
    result = INF
    addend = point
    k = scalar
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def point_mul(scalar: int, point: Point = GENERATOR) -> Point:
    """Prime-subgroup scalar multiplication, as used by DSS-MS."""
    return point_mul_raw(scalar % ORDER_Q, point)


def point_in_subgroup(point: Point) -> bool:
    return point_on_curve(point) and point_mul_raw(ORDER_Q, point) is INF


def point_to_miracl_compressed(point: Point) -> bytes:
    if point is INF:
        raise ValueError("DSS-MS transcript does not encode infinity")
    if not point_on_curve(point):
        raise ValueError("cannot encode off-curve point")
    x, y = point
    return bytes([0x02 | (y & 1)]) + x.to_bytes(48, "big")


def point_hex(point: Point) -> str:
    return point_to_miracl_compressed(point).hex()


def int_minimal_bytes(value: int) -> bytes:
    if value <= 0:
        raise ValueError("frozen mpz transcript requires a positive integer")
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def source_hash_to_scalar(transcript: bytes) -> int:
    # Frozen Tools.cpp zeroes a 48-byte buffer, writes SHA-256 into its first
    # 32 bytes, imports all 48 bytes, and reduces modulo CURVE_Order.
    digest = hashlib.sha256(transcript).digest()
    return int.from_bytes(digest + (b"\x00" * 16), "big") % ORDER_Q


def h_ch(message: int, point_t: Point) -> int:
    return source_hash_to_scalar(
        int_minimal_bytes(message) + point_to_miracl_compressed(point_t)
    )


def h_outer(message_0: int, point_r: Point, ch: Point) -> int:
    return source_hash_to_scalar(
        int_minimal_bytes(message_0)
        + point_to_miracl_compressed(point_r)
        + point_to_miracl_compressed(ch)
    )


class CounterDRBG:
    """Deterministic SHA-512 byte stream fixed in the prospective seal."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0
        self.buffer = b""

    def take(self, length: int) -> bytes:
        while len(self.buffer) < length:
            block = hashlib.sha512(
                self.seed + self.counter.to_bytes(16, "big")
            ).digest()
            self.counter += 1
            self.buffer += block
        result, self.buffer = self.buffer[:length], self.buffer[length:]
        return result

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError("upper must be positive")
        bits = upper.bit_length()
        count = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            candidate = int.from_bytes(self.take(count), "big") & mask
            if candidate < upper:
                return candidate

    def scalar(self) -> int:
        return self.randbelow(ORDER_Q - 1) + 1

    def bits(self, count: int) -> int:
        byte_count = (count + 7) // 8
        return int.from_bytes(self.take(byte_count), "big") & ((1 << count) - 1)


@dataclass(frozen=True)
class Signature:
    r_point: Point
    z: int
    s: int
    t_point: Point


def reconstruct_ch(message: int, signature: Signature, pk_s: Point) -> Point:
    e = h_ch(message, signature.t_point)
    return point_add(
        point_add(signature.t_point, point_mul(signature.s)),
        point_mul(e, pk_s),
    )


def ordinary_verify(
    message_0: int,
    message: int,
    signature: Signature,
    pk_s: Point,
    signer_pk: Point,
) -> bool:
    try:
        ch = reconstruct_ch(message, signature, pk_s)
        c = h_outer(message_0, signature.r_point, ch)
        left = point_mul(signature.z)
        right = point_add(signature.r_point, point_mul(c, signer_pk))
        return left == right
    except (ValueError, ZeroDivisionError):
        return False


def honest_sign(
    drbg: CounterDRBG,
    message_0: int,
    message: int,
    signer_sk: int,
    pk_s: Point,
) -> Signature:
    r = drbg.scalar()
    s = drbg.scalar()
    t = drbg.scalar()
    point_r = point_mul(r)
    point_t = point_mul(t)
    e = h_ch(message, point_t)
    ch = point_add(point_add(point_t, point_mul(s)), point_mul(e, pk_s))
    c = h_outer(message_0, point_r, ch)
    z = (r + signer_sk * c) % ORDER_Q
    return Signature(point_r, z, s, point_t)


def adapt_signature(
    source_message: int,
    source_signature: Signature,
    new_message: int,
    k: int,
    sanitization_scalar: int,
    pk_s: Point,
) -> Signature:
    ch = reconstruct_ch(source_message, source_signature, pk_s)
    new_t = point_add(ch, point_neg(point_mul(k)))
    new_e = h_ch(new_message, new_t)
    new_s = (k - new_e * sanitization_scalar) % ORDER_Q
    return Signature(source_signature.r_point, source_signature.z, new_s, new_t)


def public_recover_two_masks(mask_0: int, mask_1: int, pk_s: Point) -> dict[str, Any]:
    """Attack interface: all arguments are public; no hidden key is accepted."""
    candidate = math.gcd(mask_0, mask_1)
    return {
        "candidate": candidate,
        "public_key_valid": candidate > 0 and point_mul(candidate) == pk_s,
    }


def public_forge(
    message_0: int,
    source_message: int,
    source_signature: Signature,
    fresh_message: int,
    k: int,
    public_recovered_scalar: int,
    pk_s: Point,
) -> Signature:
    """Forge interface: key material is only the public GCD candidate."""
    return adapt_signature(
        source_message,
        source_signature,
        fresh_message,
        k,
        public_recovered_scalar,
        pk_s,
    )


def next_sanitizer(drbg: CounterDRBG, accumulated_product: int) -> int:
    while True:
        candidate = int.from_bytes(drbg.take(32), "big") | 1
        if candidate.bit_length() < 251:
            continue
        if math.gcd(candidate, accumulated_product) == 1:
            return candidate


def extend_sanitizers(
    drbg: CounterDRBG,
    keys: list[int],
    product: int,
    count: int,
) -> tuple[list[int], int, list[int]]:
    added: list[int] = []
    for _ in range(count):
        key = next_sanitizer(drbg, product)
        keys.append(key)
        added.append(key)
        product *= key
    return keys, product, added


def crt_coefficient_sum(keys: list[int], product: int) -> tuple[int, bool]:
    total = 0
    residues_ok = True
    for key in keys:
        partial = product // key
        inverse = pow(partial, -1, key)
        total += inverse * partial
        if (inverse * partial) % key != 1:
            residues_ok = False
    # The sum should be one modulo every pairwise-coprime sanitizer modulus.
    if residues_ok:
        residues_ok = all(total % key == 1 for key in keys)
    return total, residues_ok


def signature_json(signature: Signature) -> dict[str, Any]:
    return {
        "R_compressed_hex": point_hex(signature.r_point),
        "z_hex": hex(signature.z),
        "s_hex": hex(signature.s),
        "T_compressed_hex": point_hex(signature.t_point),
    }


def integer_evidence(value: int, include_value: bool = True) -> dict[str, Any]:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    result: dict[str, Any] = {
        "bit_length": value.bit_length(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if include_value:
        result["hex"] = hex(value)
    return result


def distinct_scalar(drbg: CounterDRBG, excluded: Iterable[int]) -> int:
    excluded_set = set(excluded)
    while True:
        value = drbg.scalar()
        if value not in excluded_set:
            return value


def memory_kib() -> int:
    # Linux ru_maxrss is KiB.  The sealed environment is Linux and the report
    # also retains /usr/bin/time -v output for an independent process peak.
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def host_facts() -> dict[str, Any]:
    mem_total_kib = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kib = int(line.split()[1])
                break
    except OSError:
        pass
    disk = shutil.disk_usage(Path.cwd())
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.replace("\n", " "),
        "logical_cpus_visible": os.cpu_count(),
        "physical_ram_kib": mem_total_kib,
        "disk_free_bytes_at_start": disk.free,
        "worker_count": WORKERS,
        "thread_environment": {
            name: os.environ.get(name)
            for name in (
                "OMP_NUM_THREADS",
                "OPENBLAS_NUM_THREADS",
                "MKL_NUM_THREADS",
                "NUMEXPR_NUM_THREADS",
            )
        },
    }


def point_check_map(points: dict[str, Point]) -> dict[str, dict[str, bool]]:
    return {
        name: {
            "on_curve": point_on_curve(point),
            "in_prime_order_subgroup": point_in_subgroup(point),
        }
        for name, point in points.items()
    }


def all_point_checks_pass(checks: dict[str, dict[str, bool]]) -> bool:
    return all(
        entry["on_curve"] and entry["in_prime_order_subgroup"]
        for entry in checks.values()
    )


def run_trial(seed_hex: str, trial_index: int) -> dict[str, Any]:
    started = time.perf_counter()
    phases: dict[str, float] = {}
    drbg = CounterDRBG(bytes.fromhex(seed_hex))

    phase = time.perf_counter()
    sanitizer_keys: list[int] = []
    sanitizer_keys, product, _ = extend_sanitizers(
        drbg, sanitizer_keys, 1, INITIAL_N
    )
    phases["generate_3000_sanitizers_seconds"] = time.perf_counter() - phase

    sk_s = 0
    while sk_s == 0:
        sk_s = drbg.bits(251)
    pk_s = point_mul(sk_s)
    signer_sk = drbg.scalar()
    signer_pk = point_mul(signer_sk)
    wrong_signer_sk = distinct_scalar(drbg, [signer_sk])
    wrong_signer_pk = point_mul(wrong_signer_sk)

    phase = time.perf_counter()
    coefficient_0, residues_0_ok = crt_coefficient_sum(sanitizer_keys, product)
    mask_0 = coefficient_0 * sk_s
    phases["crt_epoch_0_seconds"] = time.perf_counter() - phase

    eligible_old_indices = [
        index for index, key in enumerate(sanitizer_keys) if key > sk_s
    ]
    if not eligible_old_indices:
        raise RuntimeError("no initial sanitizer recovers the represented scalar exactly")
    old_index = eligible_old_indices[0]

    message_0 = drbg.scalar()
    message = drbg.scalar()
    original = honest_sign(drbg, message_0, message, signer_sk, pk_s)
    original_before_ok = ordinary_verify(
        message_0, message, original, pk_s, signer_pk
    )
    pre_sanitized_message = distinct_scalar(drbg, [message])
    pre_sanitized_k = drbg.scalar()
    recovered_by_old_before = mask_0 % sanitizer_keys[old_index]
    pre_sanitized = adapt_signature(
        message,
        original,
        pre_sanitized_message,
        pre_sanitized_k,
        recovered_by_old_before,
        pk_s,
    )
    pre_sanitized_ok = ordinary_verify(
        message_0, pre_sanitized_message, pre_sanitized, pk_s, signer_pk
    )

    phase = time.perf_counter()
    old_count = len(sanitizer_keys)
    sanitizer_keys, product, added_1 = extend_sanitizers(
        drbg, sanitizer_keys, product, JOIN_COUNT
    )
    coefficient_1, residues_1_ok = crt_coefficient_sum(sanitizer_keys, product)
    mask_1 = coefficient_1 * sk_s
    phases["join_1_and_crt_seconds"] = time.perf_counter() - phase

    eligible_new_indices = [
        old_count + index
        for index, key in enumerate(added_1)
        if key > sk_s
    ]
    if not eligible_new_indices:
        raise RuntimeError("no new sanitizer recovers the represented scalar exactly")
    new_index = eligible_new_indices[0]

    original_after_ok = ordinary_verify(
        message_0, message, original, pk_s, signer_pk
    )
    post_old_message = distinct_scalar(
        drbg, [message, pre_sanitized_message]
    )
    post_old = adapt_signature(
        message,
        original,
        post_old_message,
        drbg.scalar(),
        mask_1 % sanitizer_keys[old_index],
        pk_s,
    )
    post_old_ok = ordinary_verify(
        message_0, post_old_message, post_old, pk_s, signer_pk
    )
    post_new_message = distinct_scalar(
        drbg, [message, pre_sanitized_message, post_old_message]
    )
    post_new = adapt_signature(
        message,
        original,
        post_new_message,
        drbg.scalar(),
        mask_1 % sanitizer_keys[new_index],
        pk_s,
    )
    post_new_ok = ordinary_verify(
        message_0, post_new_message, post_new, pk_s, signer_pk
    )
    after_message_0 = distinct_scalar(drbg, [message_0])
    after_message = distinct_scalar(
        drbg,
        [message, pre_sanitized_message, post_old_message, post_new_message],
    )
    signed_after = honest_sign(
        drbg, after_message_0, after_message, signer_sk, pk_s
    )
    signed_after_ok = ordinary_verify(
        after_message_0, after_message, signed_after, pk_s, signer_pk
    )

    attack_inputs = {
        "interface": "public_recover_two_masks(mask_0, mask_1, pk_s)",
        "contains_hidden_key_material": False,
        "fields": [
            "q",
            "P",
            "PK_s",
            "signer_PK",
            "S_x_epoch_0",
            "S_x_epoch_1",
            "accepted_message",
            "accepted_signature",
            "attacker_chosen_fresh_message",
            "attacker_chosen_k",
        ],
        "q_hex": hex(ORDER_Q),
        "P_compressed_hex": point_hex(GENERATOR),
        "PK_s_compressed_hex": point_hex(pk_s),
        "signer_PK_compressed_hex": point_hex(signer_pk),
        "S_x_epoch_0": integer_evidence(mask_0, include_value=True),
        "S_x_epoch_1": integer_evidence(mask_1, include_value=True),
        "accepted_message": {
            "m0_hex": hex(message_0),
            "m_hex": hex(message),
        },
        "accepted_signature": signature_json(original),
    }

    phase = time.perf_counter()
    recovery = public_recover_two_masks(mask_0, mask_1, pk_s)
    candidate = int(recovery["candidate"])
    residual = candidate // sk_s
    exact_candidate = candidate == sk_s
    phases["one_join_public_recovery_seconds"] = time.perf_counter() - phase

    previous_full_messages = {
        (message_0, message),
        (message_0, pre_sanitized_message),
        (message_0, post_old_message),
        (message_0, post_new_message),
        (after_message_0, after_message),
    }
    fresh_message = distinct_scalar(
        drbg,
        [message, pre_sanitized_message, post_old_message, post_new_message, after_message],
    )
    forge_k = drbg.scalar()
    attack_inputs["attacker_chosen_fresh_message"] = hex(fresh_message)
    attack_inputs["attacker_chosen_k"] = hex(forge_k)

    one_join_forge: dict[str, Any]
    forged: Optional[Signature] = None
    if exact_candidate and bool(recovery["public_key_valid"]):
        forged = public_forge(
            message_0,
            message,
            original,
            fresh_message,
            forge_k,
            candidate,
            pk_s,
        )
        forge_accept = ordinary_verify(
            message_0, fresh_message, forged, pk_s, signer_pk
        )
        mutated_message = (fresh_message + 1) % ORDER_Q
        if mutated_message == 0:
            mutated_message = 1
        if mutated_message == fresh_message:
            mutated_message = 2
        mutation_rejected = not ordinary_verify(
            message_0, mutated_message, forged, pk_s, signer_pk
        )
        wrong_key_rejected = not ordinary_verify(
            message_0, fresh_message, forged, pk_s, wrong_signer_pk
        )
        full_message_fresh = (message_0, fresh_message) not in previous_full_messages
        one_join_forge = {
            "attempted": True,
            "full_message_fresh": full_message_fresh,
            "ordinary_verifier_accepts": forge_accept,
            "message_mutation_rejected": mutation_rejected,
            "wrong_key_rejected": wrong_key_rejected,
            "mutated_message_hex": hex(mutated_message),
            "signature": signature_json(forged),
        }
    else:
        one_join_forge = {
            "attempted": False,
            "reason": "non-unit residual/public candidate not validated",
            "full_message_fresh": (message_0, fresh_message) not in previous_full_messages,
            "ordinary_verifier_accepts": False,
            "message_mutation_rejected": None,
            "wrong_key_rejected": None,
        }

    multi_epochs: list[dict[str, Any]] = []
    cumulative_gcd = candidate
    multi_forge: Optional[dict[str, Any]] = None
    latest_mask = mask_1
    epoch = 1
    while residual != 1 and epoch < MAX_POST_KGEN_EPOCH:
        epoch += 1
        epoch_phase = time.perf_counter()
        sanitizer_keys, product, _ = extend_sanitizers(
            drbg, sanitizer_keys, product, JOIN_COUNT
        )
        coefficient, residues_ok = crt_coefficient_sum(sanitizer_keys, product)
        latest_mask = coefficient * sk_s
        cumulative_gcd = math.gcd(cumulative_gcd, latest_mask)
        residual = cumulative_gcd // sk_s
        public_valid = point_mul(cumulative_gcd) == pk_s
        multi_epochs.append(
            {
                "post_kgen_epoch": epoch,
                "sanitizer_count": len(sanitizer_keys),
                "join_added": JOIN_COUNT,
                "crt_residues_all_one": residues_ok,
                "public_mask": integer_evidence(latest_mask, include_value=True),
                "cumulative_gcd": integer_evidence(cumulative_gcd, include_value=True),
                "residual_cofactor_hex": hex(residual),
                "residual_cofactor_decimal": str(residual),
                "exact_ground_truth": cumulative_gcd == sk_s,
                "public_key_valid": public_valid,
                "elapsed_seconds": time.perf_counter() - epoch_phase,
            }
        )
        if residual == 1 and public_valid:
            multi_signature = public_forge(
                message_0,
                message,
                original,
                fresh_message,
                forge_k,
                cumulative_gcd,
                pk_s,
            )
            multi_mutated = (fresh_message + 1) % ORDER_Q or 1
            multi_forge = {
                "recovered_at_post_kgen_epoch": epoch,
                "attempted": True,
                "full_message_fresh": (message_0, fresh_message)
                not in previous_full_messages,
                "ordinary_verifier_accepts": ordinary_verify(
                    message_0, fresh_message, multi_signature, pk_s, signer_pk
                ),
                "message_mutation_rejected": not ordinary_verify(
                    message_0, multi_mutated, multi_signature, pk_s, signer_pk
                ),
                "wrong_key_rejected": not ordinary_verify(
                    message_0, fresh_message, multi_signature, pk_s, wrong_signer_pk
                ),
                "signature": signature_json(multi_signature),
            }
            forged = multi_signature
            break

    honest_checks = {
        "original_before_join": original_before_ok,
        "old_sanitizer_before_join": pre_sanitized_ok,
        "original_after_join": original_after_ok,
        "old_sanitizer_after_join": post_old_ok,
        "new_sanitizer_after_join": post_new_ok,
        "new_signature_after_join": signed_after_ok,
        "old_sanitizer_recovered_exact_before": recovered_by_old_before == sk_s,
        "old_sanitizer_recovered_exact_after": (
            mask_1 % sanitizer_keys[old_index]
        )
        == sk_s,
        "new_sanitizer_recovered_exact_after": (
            mask_1 % sanitizer_keys[new_index]
        )
        == sk_s,
    }

    points: dict[str, Point] = {
        "P": GENERATOR,
        "PK_s": pk_s,
        "signer_PK": signer_pk,
        "wrong_signer_PK": wrong_signer_pk,
        "original_R": original.r_point,
        "original_T": original.t_point,
        "original_CH": reconstruct_ch(message, original, pk_s),
        "pre_join_sanitized_T": pre_sanitized.t_point,
        "post_join_old_sanitized_T": post_old.t_point,
        "post_join_new_sanitized_T": post_new.t_point,
        "post_join_signature_R": signed_after.r_point,
        "post_join_signature_T": signed_after.t_point,
    }
    if forged is not None:
        points["forged_R"] = forged.r_point
        points["forged_T"] = forged.t_point
        points["forged_CH"] = reconstruct_ch(fresh_message, forged, pk_s)
    point_checks = point_check_map(points)

    honest_all = all(honest_checks.values())
    curve_all = all_point_checks_pass(point_checks)
    if exact_candidate:
        one_join_status = (
            "PASS_ONE_JOIN"
            if bool(recovery["public_key_valid"])
            and honest_all
            and curve_all
            and bool(one_join_forge["full_message_fresh"])
            and bool(one_join_forge["ordinary_verifier_accepts"])
            and bool(one_join_forge["message_mutation_rejected"])
            and bool(one_join_forge["wrong_key_rejected"])
            else "FAIL_CONTROL_OR_INVARIANT"
        )
    else:
        one_join_status = "FAIL_RESIDUAL_COFACTOR"

    if one_join_status == "PASS_ONE_JOIN":
        terminal_status = "PASS_ONE_JOIN"
    elif one_join_status == "FAIL_RESIDUAL_COFACTOR" and multi_forge is not None:
        multi_ok = (
            bool(multi_forge["full_message_fresh"])
            and bool(multi_forge["ordinary_verifier_accepts"])
            and bool(multi_forge["message_mutation_rejected"])
            and bool(multi_forge["wrong_key_rejected"])
            and honest_all
            and curve_all
        )
        terminal_status = "PASS_MULTI_EPOCH" if multi_ok else "FAIL_CONTROL_OR_INVARIANT"
    elif one_join_status == "FAIL_RESIDUAL_COFACTOR":
        terminal_status = "FAIL_MULTI_EPOCH_RESIDUAL_REMAINS"
    else:
        terminal_status = one_join_status

    phases["total_seconds"] = time.perf_counter() - started
    return {
        "record_type": "trial",
        "trial_index": trial_index,
        "seed_hex": seed_hex,
        "profile": {
            "initial_sanitizers": INITIAL_N,
            "first_join_adds": JOIN_COUNT,
            "first_post_join_sanitizers": INITIAL_N + JOIN_COUNT,
            "curve": "BLS12-381 G1",
            "hash": "frozen source SHA-256 transcript with digest||zero16 import",
            "workers": WORKERS,
        },
        "ground_truth_commitments": {
            "sk_s_sha256": hashlib.sha256(
                sk_s.to_bytes((sk_s.bit_length() + 7) // 8, "big")
            ).hexdigest(),
            "sk_s_hex_for_diagnostic_reproduction": hex(sk_s),
            "signer_sk_sha256": hashlib.sha256(
                signer_sk.to_bytes((signer_sk.bit_length() + 7) // 8, "big")
            ).hexdigest(),
        },
        "public_attacker_inputs": attack_inputs,
        "crt_checks": {
            "epoch_0_all_residues_one": residues_0_ok,
            "epoch_1_all_residues_one": residues_1_ok,
            "initial_pairwise_coprime_via_product_generation": True,
            "eligible_old_sanitizers_count": len(eligible_old_indices),
            "eligible_new_sanitizers_count": len(eligible_new_indices),
            "selected_old_index": old_index,
            "selected_new_index": new_index,
        },
        "honest_acceptance": honest_checks,
        "one_join_recovery": {
            "candidate": integer_evidence(candidate, include_value=True),
            "residual_cofactor_hex": hex(candidate // sk_s),
            "residual_cofactor_decimal": str(candidate // sk_s),
            "candidate_equals_ground_truth": exact_candidate,
            "candidate_public_key_valid": bool(recovery["public_key_valid"]),
            "status": one_join_status,
        },
        "one_join_forgery": one_join_forge,
        "multi_epoch_residual_analysis": {
            "epochs_attempted_after_first_join": multi_epochs,
            "forgery": multi_forge,
            "classification": (
                "NOT_NEEDED_ONE_JOIN_UNIT"
                if exact_candidate
                else (
                    "PASS_MULTI_EPOCH"
                    if multi_forge is not None
                    and terminal_status == "PASS_MULTI_EPOCH"
                    else "RESIDUAL_REMAINS_OR_CONTROL_FAILED"
                )
            ),
        },
        "curve_and_subgroup_checks": point_checks,
        "all_curve_and_subgroup_checks_pass": curve_all,
        "runtime": phases,
        "peak_rss_kib_at_trial_end": memory_kib(),
        "worker_count": WORKERS,
        "terminal_status": terminal_status,
    }


def self_test() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    checks["generator_on_curve"] = point_on_curve(GENERATOR)
    checks["generator_in_subgroup"] = point_in_subgroup(GENERATOR)
    checks["q_times_generator_is_infinity"] = point_mul_raw(ORDER_Q, GENERATOR) is INF
    checks["one_times_generator"] = point_mul_raw(1, GENERATOR) == GENERATOR
    checks["two_times_generator"] = point_mul_raw(2, GENERATOR) == point_add(
        GENERATOR, GENERATOR
    )
    encoded = point_to_miracl_compressed(GENERATOR)
    checks["compressed_generator_is_49_bytes"] = len(encoded) == 49
    checks["compressed_generator_prefix"] = encoded[0] == (0x02 | (GENERATOR[1] & 1))
    checks["compressed_generator_x"] = encoded[1:] == GENERATOR[0].to_bytes(48, "big")

    digest = hashlib.sha256(b"transcript-regression").digest()
    expected = (int.from_bytes(digest, "big") << 128) % ORDER_Q
    checks["hash_import_appends_16_zero_bytes"] = (
        source_hash_to_scalar(b"transcript-regression") == expected
    )

    drbg = CounterDRBG(b"DSS-MS self test")
    keys: list[int] = []
    keys, product, _ = extend_sanitizers(drbg, keys, 1, 12)
    coefficient_0, residues_0 = crt_coefficient_sum(keys, product)
    sk_s = min(keys) - 1
    if sk_s <= 0:
        raise AssertionError("impossible self-test key")
    mask_0 = coefficient_0 * sk_s
    keys, product, _ = extend_sanitizers(drbg, keys, product, 3)
    coefficient_1, residues_1 = crt_coefficient_sum(keys, product)
    mask_1 = coefficient_1 * sk_s
    checks["crt_residues"] = residues_0 and residues_1
    checks["all_self_test_sanitizers_recover"] = all(mask_1 % key == sk_s for key in keys)
    recovery = public_recover_two_masks(mask_0, mask_1, point_mul(sk_s))
    # A non-unit cofactor is possible even in this small deterministic test;
    # test the public validation implication rather than assuming it is one.
    checks["public_validation_consistent"] = bool(recovery["public_key_valid"]) == (
        point_mul(int(recovery["candidate"])) == point_mul(sk_s)
    )

    signer_sk = drbg.scalar()
    signer_pk = point_mul(signer_sk)
    m0, m = drbg.scalar(), drbg.scalar()
    signature = honest_sign(drbg, m0, m, signer_sk, point_mul(sk_s))
    checks["ordinary_honest_verification"] = ordinary_verify(
        m0, m, signature, point_mul(sk_s), signer_pk
    )
    m2 = distinct_scalar(drbg, [m])
    adapted = adapt_signature(m, signature, m2, drbg.scalar(), sk_s, point_mul(sk_s))
    checks["ordinary_adapted_verification"] = ordinary_verify(
        m0, m2, adapted, point_mul(sk_s), signer_pk
    )
    checks["adapted_message_mutation_rejected"] = not ordinary_verify(
        m0, m, adapted, point_mul(sk_s), signer_pk
    )

    result = {
        "record_type": "self_test",
        "checks": checks,
        "all_pass": all(checks.values()),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if not result["all_pass"]:
        raise AssertionError(json.dumps(result, indent=2))
    return result


def aggregate_status(trials: list[dict[str, Any]]) -> dict[str, Any]:
    one_join_passes = sum(
        trial["one_join_recovery"]["status"] == "PASS_ONE_JOIN" for trial in trials
    )
    residuals = sum(
        trial["one_join_recovery"]["status"] == "FAIL_RESIDUAL_COFACTOR"
        for trial in trials
    )
    multi_passes = sum(
        trial["terminal_status"] == "PASS_MULTI_EPOCH" for trial in trials
    )
    invariant_failures = [
        trial["trial_index"]
        for trial in trials
        if trial["one_join_recovery"]["status"] == "FAIL_CONTROL_OR_INVARIANT"
        or trial["terminal_status"] == "FAIL_CONTROL_OR_INVARIANT"
    ]
    unresolved = [
        trial["trial_index"]
        for trial in trials
        if trial["terminal_status"] == "FAIL_MULTI_EPOCH_RESIDUAL_REMAINS"
    ]
    pass_independent = (
        len(trials) == len(SEALED_SEEDS)
        and {trial["seed_hex"] for trial in trials} == set(SEALED_SEEDS)
        and one_join_passes >= 1
        and not invariant_failures
    )
    return {
        "sealed_trial_count": len(SEALED_SEEDS),
        "completed_trial_count": len(trials),
        "one_join_passes": one_join_passes,
        "one_join_residual_cofactor_trials": residuals,
        "multi_epoch_passes_among_one_join_residuals": multi_passes,
        "invariant_or_control_failure_trials": invariant_failures,
        "multi_epoch_unresolved_trials": unresolved,
        "pass_independent_reproduction": pass_independent,
    }


def run_all(output_path: Path) -> dict[str, Any]:
    for name in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
    ):
        if os.environ.get(name) != "1":
            raise RuntimeError(f"sealed one-worker environment missing {name}=1")

    self_result = self_test()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    trials: list[dict[str, Any]] = []
    meta = {
        "record_type": "meta",
        "format": "DSS-MS-independent-reproduction-v1",
        "sealed_seeds": SEALED_SEEDS,
        "host": host_facts(),
        "self_test_all_pass": self_result["all_pass"],
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(meta, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        for index, seed in enumerate(SEALED_SEEDS, start=1):
            trial = run_trial(seed, index)
            trials.append(trial)
            handle.write(json.dumps(trial, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            print(
                f"trial={index} seed={seed} "
                f"one_join={trial['one_join_recovery']['status']} "
                f"residual={trial['one_join_recovery']['residual_cofactor_decimal']} "
                f"terminal={trial['terminal_status']} "
                f"seconds={trial['runtime']['total_seconds']:.6f}",
                flush=True,
            )
        aggregate = aggregate_status(trials)
        footer = {
            "record_type": "aggregate",
            "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **aggregate,
            "peak_rss_kib": memory_kib(),
        }
        handle.write(json.dumps(footer, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps(footer, sort_keys=True), flush=True)
    if not aggregate["pass_independent_reproduction"]:
        raise RuntimeError("sealed aggregate did not meet PASS criteria")
    return footer


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at line {line_number}: {exc}") from exc
    return records


def verify_results(path: Path) -> dict[str, Any]:
    records = load_jsonl(path)
    if len(records) < 3:
        raise AssertionError("results file lacks meta/trials/aggregate")
    if records[0].get("record_type") != "meta":
        raise AssertionError("first record is not meta")
    if records[-1].get("record_type") != "aggregate":
        raise AssertionError("last record is not aggregate")
    trials = [record for record in records if record.get("record_type") == "trial"]
    if len(trials) != len(SEALED_SEEDS):
        raise AssertionError("not every sealed seed has a trial")
    if [trial["seed_hex"] for trial in trials] != SEALED_SEEDS:
        raise AssertionError("sealed seeds are missing, reordered, or replaced")
    if any(trial["profile"]["initial_sanitizers"] != INITIAL_N for trial in trials):
        raise AssertionError("a trial did not use n=3000")
    if any(trial["profile"]["first_join_adds"] != JOIN_COUNT for trial in trials):
        raise AssertionError("a trial did not use Join(+20)")
    if any(trial["worker_count"] != 1 for trial in trials):
        raise AssertionError("a trial did not report one worker")
    if any(
        trial["public_attacker_inputs"]["contains_hidden_key_material"]
        for trial in trials
    ):
        raise AssertionError("hidden key material marked as an attacker input")
    if any(not all(trial["honest_acceptance"].values()) for trial in trials):
        raise AssertionError("an honest acceptance/recovery check failed")
    if any(not trial["all_curve_and_subgroup_checks_pass"] for trial in trials):
        raise AssertionError("a curve or subgroup check failed")

    for trial in trials:
        status = trial["one_join_recovery"]["status"]
        residual = int(trial["one_join_recovery"]["residual_cofactor_decimal"])
        if status == "PASS_ONE_JOIN":
            if residual != 1:
                raise AssertionError("one-Join PASS has non-unit residual")
            forge = trial["one_join_forgery"]
            required = (
                forge["attempted"],
                forge["full_message_fresh"],
                forge["ordinary_verifier_accepts"],
                forge["message_mutation_rejected"],
                forge["wrong_key_rejected"],
            )
            if not all(required):
                raise AssertionError("one-Join PASS lacks a required forge/control")
        elif status == "FAIL_RESIDUAL_COFACTOR":
            if residual == 1:
                raise AssertionError("residual failure has unit residual")
        else:
            raise AssertionError(f"unexpected one-Join status {status}")

    computed = aggregate_status(trials)
    stored = records[-1]
    for key, value in computed.items():
        if stored.get(key) != value:
            raise AssertionError(f"aggregate mismatch for {key}")
    if not computed["pass_independent_reproduction"]:
        raise AssertionError("aggregate PASS criteria not met")
    result = {
        "verified": True,
        "path": str(path),
        **computed,
    }
    print(json.dumps(result, sort_keys=True))
    return result


def reference_report() -> dict[str, Any]:
    """Execute every prospectively sealed row and return stable public fields."""
    self_result = self_test()
    trials = [
        run_trial(seed, index)
        for index, seed in enumerate(SEALED_SEEDS, start=1)
    ]
    aggregate = aggregate_status(trials)
    results: list[dict[str, Any]] = []
    for trial in trials:
        one_status = trial["one_join_recovery"]["status"]
        if one_status == "PASS_ONE_JOIN":
            forge = trial["one_join_forgery"]
            recovery_sanitizers = INITIAL_N + JOIN_COUNT
            cumulative_residuals = [
                int(trial["one_join_recovery"]["residual_cofactor_decimal"])
            ]
        else:
            multi = trial["multi_epoch_residual_analysis"]
            forge = multi["forgery"]
            epochs = multi["epochs_attempted_after_first_join"]
            recovery_sanitizers = (
                epochs[-1]["sanitizer_count"] if forge is not None else None
            )
            cumulative_residuals = [
                int(trial["one_join_recovery"]["residual_cofactor_decimal"])
            ] + [int(epoch["residual_cofactor_decimal"]) for epoch in epochs]

        checks = {
            "attack_interface_public_only": not trial["public_attacker_inputs"][
                "contains_hidden_key_material"
            ],
            "all_honest_checks_pass": all(trial["honest_acceptance"].values()),
            "all_curve_and_subgroup_checks_pass": trial[
                "all_curve_and_subgroup_checks_pass"
            ],
            "candidate_publicly_valid_before_forgery": (
                trial["one_join_recovery"]["candidate_public_key_valid"]
                if one_status == "PASS_ONE_JOIN"
                else bool(
                    trial["multi_epoch_residual_analysis"]
                    ["epochs_attempted_after_first_join"][-1]["public_key_valid"]
                )
            ),
            "fresh_full_message": bool(forge and forge["full_message_fresh"]),
            "ordinary_verifier_accepts_forgery": bool(
                forge and forge["ordinary_verifier_accepts"]
            ),
            "message_mutation_rejected": bool(
                forge and forge["message_mutation_rejected"]
            ),
            "wrong_key_rejected": bool(forge and forge["wrong_key_rejected"]),
        }
        expected_terminal = trial["terminal_status"] in {
            "PASS_ONE_JOIN",
            "PASS_MULTI_EPOCH",
        }
        all_pass = expected_terminal and all(checks.values())
        results.append(
            {
                "all_expected_checks_pass": all_pass,
                "checks": checks,
                "cumulative_residuals": cumulative_residuals,
                "first_exact_recovery_sanitizer_count": recovery_sanitizers,
                "one_join_residual": int(
                    trial["one_join_recovery"]["residual_cofactor_decimal"]
                ),
                "one_join_status": one_status,
                "parameter_row": (
                    "DSS-MS BLS12-381/SHA-256 n=3000 Join(+20) "
                    f"sealed trial {trial['trial_index']}"
                ),
                "seed_hex": trial["seed_hex"],
                "terminal_status": trial["terminal_status"],
            }
        )

    all_rows_pass = (
        self_result["all_pass"]
        and aggregate["pass_independent_reproduction"]
        and all(row["all_expected_checks_pass"] for row in results)
    )
    return {
        "all_rows_pass": all_rows_pass,
        "result": "PASS_INDEPENDENT_REPRODUCTION" if all_rows_pass else "FAIL",
        "results": results,
        "scope": (
            "Eight prospectively sealed DSS-MS BLS12-381/SHA-256 full-profile "
            "trials at n=3000 with first Join(+20); cumulative ordinary public "
            "epochs retained for nonunit one-Join residuals"
        ),
        "summary": aggregate,
    }


def canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--all-seeds", action="store_true")
    mode.add_argument("--verify-results", type=Path)
    mode.add_argument("--reference", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        print(json.dumps(self_test(), sort_keys=True))
        return 0
    if args.all_seeds:
        if args.output is None:
            raise SystemExit("--all-seeds requires --output")
        run_all(args.output)
        return 0
    if args.verify_results is not None:
        verify_results(args.verify_results)
        return 0
    rendered = canonical(reference_report())
    if args.reference:
        expected_path = Path(__file__).with_name("all-rows-reference-output.json")
        if expected_path.is_file() and rendered != expected_path.read_text():
            raise SystemExit("all-rows-reference-output.json does not match")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
