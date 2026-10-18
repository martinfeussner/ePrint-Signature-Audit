#!/usr/bin/env python3
"""Deterministic public reproducer for DSS-MS ePrint 2026/041.

The integer portion follows DSS/src/DSS.cpp KeyGen and Join:

* 3000 initial odd 256-bit draws with bit length at least 251;
* pairwise coprimality enforced against the accumulated product;
* a 251-bit sanitization scalar;
* the unreduced CRT coefficient sum A and public S_x=A*sk_s;
* a legitimate Join of 20 newly generated values and recomputation of A'.

The signature portion implements actual BLS12-381 G1 arithmetic and mirrors
the author's SHA-256 transcript conversion, including MIRACL's 49-byte
compressed G1 form and the source wrapper's 48-byte BIG import of a 32-byte
SHA-256 digest followed by sixteen zero bytes.

``--mode quick`` runs the same attack and ordinary verifier at a smaller
sanitizer count for a fast regression check.  ``--mode exact`` runs the
claimed n=3000, Join(+20) profile used by the sealed primary experiment.
This is intentionally dependency-light: Python's standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import math
import random
import resource
import sys
import time
import json
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple


# BLS12-381 base field and prime subgroup order.
P_FIELD = int(
    "1a0111ea397fe69a4b1ba7b6434bacd7"
    "64774b84f38512bf6730d2a0f6b0f624"
    "1eabfffeb153ffffb9feffffffffaaab",
    16,
)
Q_ORDER = int(
    "73eda753299d7d483339d80809a1d805"
    "53bda402fffe5bfeffffffff00000001",
    16,
)

# Standard BLS12-381 G1 generator used by MIRACL Core.
G1 = (
    int(
        "17f1d3a73197d7942695638c4fa9ac0f"
        "c3688c4f9774b905a14e3a3f171bac5"
        "86c55e83ff97a1aeffb3af00adb22c6bb",
        16,
    ),
    int(
        "08b3f481e3aaa0f1a09e30ed741d8ae4"
        "fcf5e095d5d00af600db18cb2c04b3ed"
        "d03cc744a2888ae40caa232946c5e7e1",
        16,
    ),
)

Point = Optional[Tuple[int, int]]
EXACT_PROFILE = "DSSMS-BLS12381-SHA256-N3000-ADD20-CRT-INMEM-20260111"
QUICK_PROFILE = "DSSMS-BLS12381-SHA256-N96-ADD20-CRT-QUICK-V1"
RESULTS: list[tuple[str, object]] = []
REFERENCE_MODE = False


def point_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - 4) % P_FIELD == 0


def point_neg(point: Point) -> Point:
    if point is None:
        return None
    return point[0], (-point[1]) % P_FIELD


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, P_FIELD) % P_FIELD
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P_FIELD, -1, P_FIELD) % P_FIELD
    x3 = (slope * slope - x1 - x2) % P_FIELD
    y3 = (slope * (x1 - x3) - y1) % P_FIELD
    return x3, y3


def scalar_mul(
    scalar: int, point: Point = G1, *, reduce_scalar: bool = True
) -> Point:
    if scalar < 0:
        return scalar_mul(-scalar, point_neg(point), reduce_scalar=reduce_scalar)
    if reduce_scalar:
        scalar %= Q_ORDER
    acc = None
    addend = point
    while scalar:
        if scalar & 1:
            acc = point_add(acc, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return acc


def point_sub(left: Point, right: Point) -> Point:
    return point_add(left, point_neg(right))


def mpz_octets(value: int) -> bytes:
    """Match mpz_export(..., order=1, size=1) for positive integers."""
    if value <= 0:
        raise ValueError("the selected source-faithful transcript uses positive mpz values")
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def miracl_g1_octets(point: Point) -> bytes:
    """MIRACL standard compressed form: 02/03 || 48-byte affine x."""
    if point is None:
        raise ValueError("point at infinity is outside the selected profile")
    x, y = point
    return bytes([0x02 | (y & 1)]) + x.to_bytes(48, "big")


def source_hash_to_scalar(payload: bytes) -> int:
    """Mirror Tools.cpp hashZp256's SHA-256 -> zero-padded 48-byte BIG path."""
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest + bytes(16), "big") % Q_ORDER


def h_ch(message: int, t_point: Point) -> int:
    return source_hash_to_scalar(mpz_octets(message) + miracl_g1_octets(t_point))


def h_sig(message_fixed: int, r_point: Point, ch_point: Point) -> int:
    return source_hash_to_scalar(
        mpz_octets(message_fixed)
        + miracl_g1_octets(r_point)
        + miracl_g1_octets(ch_point)
    )


def labelled_scalar(label: str) -> int:
    raw = hashlib.sha256(("DSS-MS-2026-041:" + label).encode()).digest()
    return int.from_bytes(raw, "big") % (Q_ORDER - 1) + 1


def integer_digest(value: int) -> str:
    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return hashlib.sha256(data).hexdigest()


def generate_initial_moduli(
    rng: random.Random, count: int, bits: int
) -> Tuple[list[int], int, int]:
    moduli: list[int] = []
    product = 1
    attempts = 0
    while len(moduli) < count:
        candidate = rng.getrandbits(bits)
        attempts += 1
        if candidate.bit_length() < bits - 5:
            continue
        candidate |= 1
        if math.gcd(candidate, product) == 1:
            moduli.append(candidate)
            product *= candidate
    return moduli, product, attempts


def generate_join_moduli(
    rng: random.Random, old_product: int, count: int, bits: int
) -> Tuple[list[int], int, int]:
    additions: list[int] = []
    batch_product = 1
    attempts = 0
    while len(additions) < count:
        candidate = rng.getrandbits(bits)
        attempts += 1
        if candidate.bit_length() < bits - 5:
            continue
        candidate |= 1
        if (
            math.gcd(candidate, old_product) == 1
            and math.gcd(candidate, batch_product) == 1
        ):
            additions.append(candidate)
            batch_product *= candidate
    return additions, batch_product, attempts


def exact_crt_coefficient_sum(moduli: Sequence[int]) -> Tuple[int, int]:
    """Compute the exact unreduced sum used by KeyGen/Join in DSS.cpp."""
    product = math.prod(moduli)
    coefficient_sum = 0
    for modulus in moduli:
        quotient = product // modulus
        inverse = pow(quotient, -1, modulus)
        coefficient_sum += inverse * quotient
    if (coefficient_sum - 1) % product != 0:
        raise AssertionError("CRT coefficient sum is not 1 modulo the full product")
    return product, coefficient_sum


@dataclass(frozen=True)
class Signature:
    r_point: Point
    z: int
    s: int
    t_point: Point


def reconstruct_ch(message: int, signature: Signature, pk_s: Point) -> Point:
    e = h_ch(message, signature.t_point)
    return point_add(
        signature.t_point,
        point_add(scalar_mul(signature.s), scalar_mul(e, pk_s)),
    )


def sign(
    message_fixed: int,
    message_sanitizable: int,
    signing_secret: int,
    pk_s: Point,
) -> Signature:
    r = labelled_scalar("sign-r")
    s = labelled_scalar("sign-s")
    t = labelled_scalar("sign-t")
    r_point = scalar_mul(r)
    t_point = scalar_mul(t)
    provisional = Signature(r_point=r_point, z=0, s=s, t_point=t_point)
    ch_point = reconstruct_ch(message_sanitizable, provisional, pk_s)
    challenge = h_sig(message_fixed, r_point, ch_point)
    z = (r + signing_secret * challenge) % Q_ORDER
    return Signature(r_point=r_point, z=z, s=s, t_point=t_point)


def verify(
    message_fixed: int,
    message_sanitizable: int,
    signature: Signature,
    pk_s: Point,
    signer_pk: Point,
) -> bool:
    ch_point = reconstruct_ch(message_sanitizable, signature, pk_s)
    challenge = h_sig(message_fixed, signature.r_point, ch_point)
    return scalar_mul(signature.z) == point_add(
        signature.r_point, scalar_mul(challenge, signer_pk)
    )


def public_epoch_attacker(
    sx_old: int,
    sx_joined: int,
    pk_s: Point,
    message_fixed: int,
    message_old: int,
    honest_signature: Signature,
    signer_pk: Point,
    message_fresh: int,
    chosen_k: int,
) -> Tuple[int, Signature]:
    """Attack using public epochs only; no sk_i or hidden sk_s argument exists."""
    recovered = math.gcd(sx_old, sx_joined)
    if scalar_mul(recovered) != pk_s:
        raise RuntimeError("public GCD did not recover the scalar exactly")
    if not verify(
        message_fixed, message_old, honest_signature, pk_s, signer_pk
    ):
        raise RuntimeError("attack base signature is not honestly accepted")
    old_ch = reconstruct_ch(message_old, honest_signature, pk_s)
    t_fresh = point_sub(old_ch, scalar_mul(chosen_k))
    e_fresh = h_ch(message_fresh, t_fresh)
    s_fresh = (chosen_k - e_fresh * recovered) % Q_ORDER
    forged = Signature(
        r_point=honest_signature.r_point,
        z=honest_signature.z,
        s=s_fresh,
        t_point=t_fresh,
    )
    return recovered, forged


def proxy_cofactor_trials(seed: int, trials: int, n: int, add: int) -> Tuple[int, list[int]]:
    successes = 0
    cofactor_bits: list[int] = []
    for trial in range(trials):
        rng = random.Random((seed << 16) ^ trial ^ 0xD55A0041)
        moduli, old_product, _ = generate_initial_moduli(rng, n, 256)
        additions, _, _ = generate_join_moduli(rng, old_product, add, 256)
        _, a_old = exact_crt_coefficient_sum(moduli)
        _, a_joined = exact_crt_coefficient_sum(moduli + additions)
        residual = math.gcd(a_old, a_joined)
        cofactor_bits.append(residual.bit_length())
        successes += residual == 1
    return successes, cofactor_bits


def print_result(key: str, value: object) -> None:
    RESULTS.append((key, value))
    if REFERENCE_MODE:
        return
    if isinstance(value, bool):
        encoded = "true" if value else "false"
    else:
        encoded = str(value)
    print(f"{key}={encoded}")


def emit_reference() -> None:
    """Emit the validator-compatible deterministic exact-profile report."""
    volatile = {
        "PYTHON",
        "SECONDS_GENERATE_INITIAL",
        "SECONDS_CRT_INITIAL",
        "SECONDS_JOIN_AND_CRT",
        "SECONDS_PROXY",
        "SECONDS_TOTAL",
        "MAX_RSS_KIB",
    }
    stable = {key: value for key, value in RESULTS if key not in volatile}
    checks = {
        "all_sanitizers_odd": bool(stable["ALL_SANITIZERS_ODD"]),
        "attacker_receives_no_hidden_sanitizer_scalar": not bool(
            stable["ATTACKER_RECEIVES_HIDDEN_SK_S"]
        ),
        "attacker_receives_no_individual_sanitizer_secret": not bool(
            stable["ATTACKER_RECEIVES_SANITIZER_SK_I"]
        ),
        "bls12_381_generator_has_prime_subgroup_order": bool(
            stable["BLS12381_Q_TIMES_GENERATOR_INFINITY"]
        ),
        "bls12_381_generator_is_on_curve": bool(
            stable["BLS12381_GENERATOR_ON_CURVE"]
        ),
        "exact_full_profile": bool(stable["EXACT_FULL_PROFILE"]),
        "forged_fresh_message_accepts": bool(
            stable["FORGED_FRESH_MESSAGE_ACCEPTS"]
        ),
        "forgery_preserves_chameleon_hash": bool(
            stable["FORGERY_CH_EQUALS_ORIGINAL_CH"]
        ),
        "forgery_retains_outer_signature_R": bool(stable["FORGERY_RETAINS_R"]),
        "forgery_retains_outer_signature_z": bool(stable["FORGERY_RETAINS_Z"]),
        "full_message_is_fresh": bool(stable["FULL_MESSAGE_IS_FRESH"]),
        "honest_signature_accepts": bool(stable["HONEST_SIGNATURE_ACCEPTS"]),
        "old_signature_accepts_after_join": bool(
            stable["OLD_SIGNATURE_ACCEPTS_AFTER_JOIN"]
        ),
        "pairwise_coprime_sanitizers": bool(
            stable["PAIRWISE_COPRIME_BY_ACCUMULATED_PRODUCT"]
        ),
        "public_gcd_equals_global_sanitizer_scalar": bool(
            stable["GCD_EQUALS_SK_S"]
        ),
        "recovered_scalar_matches_public_key": bool(
            stable["RECOVERED_TIMES_P_EQUALS_PK_S"]
        ),
        "unchanged_signature_rejects_fresh_message": not bool(
            stable["MUTATION_WITHOUT_RETARGET_ACCEPTS"]
        ),
        "wrong_candidate_forgery_rejected": not bool(
            stable["WRONG_CANDIDATE_FORGERY_ACCEPTS"]
        ),
        "wrong_candidate_rejected_by_public_key": not bool(
            stable["WRONG_CANDIDATE_TIMES_P_EQUALS_PK_S"]
        ),
        "wrong_sanitizer_public_key_rejects": not bool(
            stable["WRONG_PUBLIC_KEY_ACCEPTS"]
        ),
    }
    report = {
        "attack": {
            "classification": (
                "public cross-Join global sanitizer-scalar recovery followed "
                "by a one-query fresh-message forgery"
            ),
            "observed_join_events": 1,
            "public_parameter_epochs": 2,
            "sanitizing_queries": 0,
            "signing_queries": 1,
        },
        "checks": checks,
        "digests": {
            "public_mask_after_join_sha256": stable["SX_JOINED_SHA256"],
            "public_mask_before_join_sha256": stable["SX_OLD_SHA256"],
        },
        "environment": {
            "dependencies": stable["DEPENDENCIES"],
            "workers": 1,
        },
        "measurements": {
            "final_sanitizers": stable["FINAL_SANITIZERS"],
            "global_sanitizer_scalar_bits": stable["SK_S_BITS"],
            "initial_sanitizers": stable["INITIAL_SANITIZERS"],
            "joined_sanitizers": stable["JOINED_SANITIZERS"],
            "residual_cofactor": stable["RESIDUAL_COFACTOR"],
        },
        "profile": stable["PROFILE"],
        "result": (
            "PASS_DSS_MS_PUBLIC_CROSS_JOIN_RECOVERY_AND_FRESH_MESSAGE_FORGERY"
            if all(checks.values()) and bool(stable["QUALIFYING_PASS"])
            else "FAIL"
        ),
        "scope": (
            "One deterministic exact n=3000, Join(+20), BLS12-381/SHA-256 "
            "primary instance using a source-equivalent ordinary verifier"
        ),
    }
    print(json.dumps(report, indent=2, sort_keys=True))


def main() -> int:
    global REFERENCE_MODE
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("quick", "exact"), default="quick")
    parser.add_argument("--seed", type=int)
    parser.add_argument(
        "--reference",
        action="store_true",
        help="emit stable JSON without runtime, RSS, or interpreter-version fields",
    )
    args = parser.parse_args()
    if args.reference and args.mode != "exact":
        parser.error("--reference requires --mode exact")
    REFERENCE_MODE = args.reference

    if args.mode == "exact":
        profile = EXACT_PROFILE
        n, add, bits = 3000, 20, 256
        proxy_trials, proxy_n, proxy_add = 24, 96, 20
        seed = 2026041 if args.seed is None else args.seed
    else:
        profile = QUICK_PROFILE
        n, add, bits = 96, 20, 256
        proxy_trials, proxy_n, proxy_add = 8, 48, 12
        seed = 2026043 if args.seed is None else args.seed

    started = time.perf_counter()
    print_result("PROFILE", profile)
    print_result("MODE", args.mode)
    print_result("EXACT_FULL_PROFILE", args.mode == "exact")
    print_result("PYTHON", sys.version.split()[0])
    print_result("DETERMINISTIC_SEED", seed)
    print_result("DEPENDENCIES", "python-standard-library-only")

    # Validate that this is actual BLS12-381 subgroup arithmetic.
    if not point_on_curve(G1):
        raise AssertionError("BLS12-381 G1 generator is not on y^2=x^3+4")
    if scalar_mul(Q_ORDER, G1, reduce_scalar=False) is not None:
        raise AssertionError("BLS12-381 G1 generator does not have order q")
    print_result("BLS12381_GENERATOR_ON_CURVE", True)
    print_result("BLS12381_Q_TIMES_GENERATOR_INFINITY", True)
    print_result("BLS12381_BASE_FIELD_BITS", P_FIELD.bit_length())
    print_result("BLS12381_SUBGROUP_ORDER_BITS", Q_ORDER.bit_length())

    rng = random.Random(seed)
    generated_at = time.perf_counter()
    moduli, old_product_generated, keygen_attempts = generate_initial_moduli(
        rng, n, bits
    )
    after_keygen = time.perf_counter()

    # Mirrors mpz_urandomb(..., bits-5) after the initial sanitizer loop.
    sk_s = rng.getrandbits(bits - 5)
    if sk_s == 0:
        raise AssertionError("deterministic draw unexpectedly produced zero sk_s")
    pk_s = scalar_mul(sk_s)

    old_product, a_old = exact_crt_coefficient_sum(moduli)
    if old_product != old_product_generated:
        raise AssertionError("product mismatch")
    sx_old = a_old * sk_s
    after_old_crt = time.perf_counter()

    additions, join_batch_product, join_attempts = generate_join_moduli(
        rng, old_product, add, bits
    )
    joined_moduli = moduli + additions
    joined_product, a_joined = exact_crt_coefficient_sum(joined_moduli)
    if joined_product != old_product * join_batch_product:
        raise AssertionError("joined product mismatch")
    sx_joined = a_joined * sk_s
    after_join_crt = time.perf_counter()

    recovered = math.gcd(sx_old, sx_joined)
    residual = math.gcd(a_old, a_joined)
    if recovered != sk_s * residual:
        raise AssertionError("public GCD factorization identity failed")
    candidate_valid = scalar_mul(recovered) == pk_s
    wrong_candidate_valid = scalar_mul((recovered + 1) % Q_ORDER) == pk_s

    print_result("INITIAL_SANITIZERS", len(moduli))
    print_result("JOINED_SANITIZERS", len(additions))
    print_result("FINAL_SANITIZERS", len(joined_moduli))
    print_result("INITIAL_GENERATION_ATTEMPTS", keygen_attempts)
    print_result("JOIN_GENERATION_ATTEMPTS", join_attempts)
    print_result("SANITIZER_BITS_MIN", min(x.bit_length() for x in joined_moduli))
    print_result("SANITIZER_BITS_MAX", max(x.bit_length() for x in joined_moduli))
    print_result("ALL_SANITIZERS_ODD", all(x & 1 for x in joined_moduli))
    print_result("PAIRWISE_COPRIME_BY_ACCUMULATED_PRODUCT", True)
    print_result("SK_S_BITS", sk_s.bit_length())
    print_result("SK_S_LT_ALL_INITIAL_SK_I", sk_s < min(moduli))
    print_result("SK_S_LT_ALL_JOINED_SK_I", sk_s < min(joined_moduli))
    print_result(
        "HONEST_RESIDUE_RECOVERY_COUNT_INITIAL",
        sum((sx_old % modulus) == sk_s for modulus in moduli),
    )
    print_result(
        "HONEST_RESIDUE_RECOVERY_COUNT_JOINED",
        sum((sx_joined % modulus) == sk_s for modulus in joined_moduli),
    )
    print_result("OLD_PRODUCT_BITS", old_product.bit_length())
    print_result("JOINED_PRODUCT_BITS", joined_product.bit_length())
    print_result("A_OLD_BITS", a_old.bit_length())
    print_result("A_JOINED_BITS", a_joined.bit_length())
    print_result("SX_OLD_BITS", sx_old.bit_length())
    print_result("SX_JOINED_BITS", sx_joined.bit_length())
    print_result("SX_OLD_SHA256", integer_digest(sx_old))
    print_result("SX_JOINED_SHA256", integer_digest(sx_joined))
    print_result("PUBLIC_GCD_BITS", recovered.bit_length())
    print_result("RESIDUAL_COFACTOR", residual)
    print_result("RESIDUAL_COFACTOR_BITS", residual.bit_length())
    print_result("GCD_EQUALS_SK_S", recovered == sk_s)
    print_result("RECOVERED_TIMES_P_EQUALS_PK_S", candidate_valid)
    print_result("WRONG_CANDIDATE_TIMES_P_EQUALS_PK_S", wrong_candidate_valid)

    if residual != 1 or not candidate_valid:
        print_result("QUALIFYING_PASS", False)
        print_result("FAILURE_REASON", "fixed-seed residual cofactor was not one")
        if REFERENCE_MODE:
            emit_reference()
        return 2

    # Honest signature under the public PK_s; Verify never consumes S_x.
    signer_sk = labelled_scalar("signer-sk")
    signer_pk = scalar_mul(signer_sk)
    message_fixed = labelled_scalar("message-fixed")
    message_old = labelled_scalar("message-old")
    message_fresh = labelled_scalar("message-fresh")
    if message_fresh == message_old:
        raise AssertionError("fresh sanitizable message collided")
    honest = sign(message_fixed, message_old, signer_sk, pk_s)
    honest_accepts = verify(message_fixed, message_old, honest, pk_s, signer_pk)
    old_accepts_after_join = verify(
        message_fixed, message_old, honest, pk_s, signer_pk
    )

    chosen_k = labelled_scalar("attacker-k")
    recovered_by_attacker, forged = public_epoch_attacker(
        sx_old,
        sx_joined,
        pk_s,
        message_fixed,
        message_old,
        honest,
        signer_pk,
        message_fresh,
        chosen_k,
    )
    forged_accepts = verify(
        message_fixed, message_fresh, forged, pk_s, signer_pk
    )

    # Negative control 1: mutate m without retargeting (s,T).
    mutation_without_retarget_accepts = verify(
        message_fixed, message_fresh, honest, pk_s, signer_pk
    )

    # Negative control 2: use a scalar that fails the public-key check.
    wrong_scalar = (recovered_by_attacker + 1) % Q_ORDER
    old_ch = reconstruct_ch(message_old, honest, pk_s)
    wrong_t = point_sub(old_ch, scalar_mul(chosen_k))
    wrong_e = h_ch(message_fresh, wrong_t)
    wrong_s = (chosen_k - wrong_e * wrong_scalar) % Q_ORDER
    wrong_candidate_forgery = Signature(
        r_point=honest.r_point, z=honest.z, s=wrong_s, t_point=wrong_t
    )
    wrong_candidate_forgery_accepts = verify(
        message_fixed, message_fresh, wrong_candidate_forgery, pk_s, signer_pk
    )

    # Negative control 3: the valid forgery is not portable to a wrong PK_s.
    wrong_pk_s = scalar_mul((sk_s + 1) % Q_ORDER)
    wrong_public_key_accepts = verify(
        message_fixed, message_fresh, forged, wrong_pk_s, signer_pk
    )

    original_ch = reconstruct_ch(message_old, honest, pk_s)
    forged_ch = reconstruct_ch(message_fresh, forged, pk_s)
    attack_parameters = tuple(inspect.signature(public_epoch_attacker).parameters)

    print_result("HONEST_SIGNATURE_ACCEPTS", honest_accepts)
    print_result("OLD_SIGNATURE_ACCEPTS_AFTER_JOIN", old_accepts_after_join)
    print_result("FULL_MESSAGE_IS_FRESH", (message_fixed, message_fresh) != (message_fixed, message_old))
    print_result("FORGERY_RETAINS_R", forged.r_point == honest.r_point)
    print_result("FORGERY_RETAINS_Z", forged.z == honest.z)
    print_result("FORGERY_CH_EQUALS_ORIGINAL_CH", forged_ch == original_ch)
    print_result("FORGED_FRESH_MESSAGE_ACCEPTS", forged_accepts)
    print_result("MUTATION_WITHOUT_RETARGET_ACCEPTS", mutation_without_retarget_accepts)
    print_result("WRONG_CANDIDATE_FORGERY_ACCEPTS", wrong_candidate_forgery_accepts)
    print_result("WRONG_PUBLIC_KEY_ACCEPTS", wrong_public_key_accepts)
    print_result("ATTACKER_FUNCTION_PARAMETERS", ",".join(attack_parameters))
    print_result("ATTACKER_RECEIVES_SANITIZER_SK_I", "sk_i" in attack_parameters)
    print_result("ATTACKER_RECEIVES_HIDDEN_SK_S", "sk_s" in attack_parameters)

    proxy_started = time.perf_counter()
    proxy_successes, proxy_bits = proxy_cofactor_trials(
        seed, proxy_trials, proxy_n, proxy_add
    )
    proxy_finished = time.perf_counter()
    print_result("PROXY_TRIALS", proxy_trials)
    print_result("PROXY_INITIAL_N", proxy_n)
    print_result("PROXY_ADD", proxy_add)
    print_result("PROXY_RESIDUAL_ONE_SUCCESSES", proxy_successes)
    print_result(
        "PROXY_RESIDUAL_ONE_RATE",
        f"{proxy_successes / proxy_trials:.6f}" if proxy_trials else "nan",
    )
    print_result("PROXY_COFACTOR_BITS", ",".join(map(str, proxy_bits)))
    print_result("PROXY_IS_NOT_EXACT_PROFILE", True)
    print_result("RANDOM_INTEGER_COPRIME_HEURISTIC_6_OVER_PI2", f"{6 / math.pi**2:.6f}")

    usage = resource.getrusage(resource.RUSAGE_SELF)
    print_result("SECONDS_GENERATE_INITIAL", f"{after_keygen - generated_at:.6f}")
    print_result("SECONDS_CRT_INITIAL", f"{after_old_crt - after_keygen:.6f}")
    print_result("SECONDS_JOIN_AND_CRT", f"{after_join_crt - after_old_crt:.6f}")
    print_result("SECONDS_PROXY", f"{proxy_finished - proxy_started:.6f}")
    print_result("SECONDS_TOTAL", f"{time.perf_counter() - started:.6f}")
    print_result("MAX_RSS_KIB", usage.ru_maxrss)

    qualifying = all(
        (
            recovered_by_attacker == sk_s,
            candidate_valid,
            honest_accepts,
            old_accepts_after_join,
            forged_accepts,
            forged_ch == original_ch,
            not mutation_without_retarget_accepts,
            not wrong_candidate_forgery_accepts,
            not wrong_public_key_accepts,
            (message_fixed, message_fresh) != (message_fixed, message_old),
            "sk_i" not in attack_parameters,
            "sk_s" not in attack_parameters,
        )
    )
    print_result("QUALIFYING_PASS", qualifying)
    if REFERENCE_MODE:
        emit_reference()
    return 0 if qualifying else 3


if __name__ == "__main__":
    raise SystemExit(main())
