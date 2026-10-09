#!/usr/bin/env python3
"""Full-parameter model and zero-query forgery for ePrint 2010/352.

This clean-room implementation follows the final PDF (updated 2010-06-27)
at the paper's concrete d=2, r=3, m=448 row.  The paper asks for an odd
prime q of about 2^20 and later says q must exceed 20 bits; q=1,048,609 is
a 21-bit prime satisfying that requirement.

The verifier receives only the coefficient arrays of the homogeneous
quaternion-valued polynomials F and T.  Secret (k_i,A_i) values are used to
generate F and an honest T, but never by verify() or forge().
"""

from __future__ import annotations

import hashlib
import json
import random
import resource
import sys
import time
from typing import Iterable


Q = 1_048_609
D = 2
R_EXP = 3
M = 448
S = 1 + R_EXP + R_EXP**2  # 13
SEED = 0x5941474953415741
TRIALS = 80

Quat = tuple[int, int, int, int]
Monomial = tuple[int, int, int, int]
Poly = dict[Monomial, int]
QPoly = tuple[Poly, Poly, Poly, Poly]

ZERO: Quat = (0, 0, 0, 0)
ONE: Quat = (1, 0, 0, 0)
I_UNIT: Quat = (0, 1, 0, 0)
J_UNIT: Quat = (0, 0, 1, 0)
K_UNIT: Quat = (0, 0, 0, 1)
TWO_K: Quat = (0, 0, 0, 2)


def qadd(a: Quat, b: Quat) -> Quat:
    return tuple((a[i] + b[i]) % Q for i in range(4))  # type: ignore[return-value]


def qscale(c: int, a: Quat) -> Quat:
    return tuple(c * a[i] % Q for i in range(4))  # type: ignore[return-value]


def qmul(a: Quat, b: Quat) -> Quat:
    a0, a1, a2, a3 = a
    b0, b1, b2, b3 = b
    return (
        (a0 * b0 - a1 * b1 - a2 * b2 - a3 * b3) % Q,
        (a0 * b1 + a1 * b0 + a2 * b3 - a3 * b2) % Q,
        (a0 * b2 - a1 * b3 + a2 * b0 + a3 * b1) % Q,
        (a0 * b3 + a1 * b2 - a2 * b1 + a3 * b0) % Q,
    )


def qpow(a: Quat, n: int) -> Quat:
    if n < 0:
        raise ValueError("negative quaternion exponent")
    out = ONE
    while n:
        if n & 1:
            out = qmul(out, a)
        a = qmul(a, a)
        n >>= 1
    return out


def commutes(a: Quat, b: Quat) -> bool:
    return qmul(a, b) == qmul(b, a)


def padd_scaled(dst: Poly, src: Poly, scale: int) -> None:
    scale %= Q
    if not scale:
        return
    for mon, coeff in src.items():
        value = (dst.get(mon, 0) + scale * coeff) % Q
        if value:
            dst[mon] = value
        else:
            dst.pop(mon, None)


def pmul(a: Poly, b: Poly) -> Poly:
    out: Poly = {}
    for ma, ca in a.items():
        for mb, cb in b.items():
            mon = tuple(ma[j] + mb[j] for j in range(4))
            out[mon] = (out.get(mon, 0) + ca * cb) % Q
    return {mon: coeff for mon, coeff in out.items() if coeff}


# (output coordinate, left coordinate, right coordinate, sign)
QMUL_TERMS = (
    (0, 0, 0, 1), (0, 1, 1, -1), (0, 2, 2, -1), (0, 3, 3, -1),
    (1, 0, 1, 1), (1, 1, 0, 1), (1, 2, 3, 1), (1, 3, 2, -1),
    (2, 0, 2, 1), (2, 1, 3, -1), (2, 2, 0, 1), (2, 3, 1, 1),
    (3, 0, 3, 1), (3, 1, 2, 1), (3, 2, 1, -1), (3, 3, 0, 1),
)


def qpmul(a: QPoly, b: QPoly) -> QPoly:
    out: list[Poly] = [{}, {}, {}, {}]
    for oi, ai, bi, sign in QMUL_TERMS:
        padd_scaled(out[oi], pmul(a[ai], b[bi]), sign)
    return tuple(out)  # type: ignore[return-value]


def qp_left_const(a: Quat, b: QPoly) -> QPoly:
    out: list[Poly] = [{}, {}, {}, {}]
    for oi, ai, bi, sign in QMUL_TERMS:
        padd_scaled(out[oi], b[bi], sign * a[ai])
    return tuple(out)  # type: ignore[return-value]


def qpadd_scaled(dst: list[Poly], src: QPoly, scale: int) -> None:
    for j in range(4):
        padd_scaled(dst[j], src[j], scale)


def variable_qpoly() -> QPoly:
    components: list[Poly] = []
    for coordinate in range(4):
        mon = [0, 0, 0, 0]
        mon[coordinate] = 1
        components.append({tuple(mon): 1})
    return tuple(components)  # type: ignore[return-value]


def qppow(a: QPoly, n: int) -> QPoly:
    out: QPoly = ({(0, 0, 0, 0): 1}, {}, {}, {})
    while n:
        if n & 1:
            out = qpmul(out, a)
        a = qpmul(a, a)
        n >>= 1
    return out


X = variable_qpoly()
X_POWERS = {e: qppow(X, e) for e in (1, 3, 9)}


def expand_public_polynomial(
    scalars: list[int],
    constants: list[Quat],
    right_multiplier: Quat | None = None,
    multiplier_exponent: int = 0,
) -> QPoly:
    """Expand equation (11), or equation (12) when a multiplier is supplied."""
    total: list[Poly] = [{}, {}, {}, {}]
    for scalar, a in zip(scalars, constants, strict=True):
        factors: list[QPoly] = []
        for exponent in (1, 3, 9):
            left = qpow(a, exponent)
            if right_multiplier is not None:
                right = qpow(right_multiplier, multiplier_exponent * exponent)
                left = qmul(left, right)
            factors.append(qp_left_const(left, X_POWERS[exponent]))
        term = qpmul(qpmul(factors[0], factors[1]), factors[2])
        qpadd_scaled(total, term, scalar)
    return tuple(total)  # type: ignore[return-value]


def peval(poly: Poly, x: Quat) -> int:
    powers = [[1] * (S + 1) for _ in range(4)]
    for coordinate in range(4):
        for exponent in range(1, S + 1):
            powers[coordinate][exponent] = (
                powers[coordinate][exponent - 1] * x[coordinate]
            ) % Q
    out = 0
    for mon, coeff in poly.items():
        term = coeff
        for coordinate in range(4):
            term = term * powers[coordinate][mon[coordinate]] % Q
        out = (out + term) % Q
    return out


def qpeval(poly: QPoly, x: Quat) -> Quat:
    return tuple(peval(poly[j], x) for j in range(4))  # type: ignore[return-value]


def secret_eval(
    scalars: list[int],
    constants: list[Quat],
    x: Quat,
    right_multiplier: Quat | None = None,
    multiplier_exponent: int = 0,
) -> Quat:
    out = ZERO
    for scalar, a in zip(scalars, constants, strict=True):
        term = ONE
        for exponent in (1, 3, 9):
            factor = qpow(a, exponent)
            if right_multiplier is not None:
                factor = qmul(
                    factor,
                    qpow(right_multiplier, multiplier_exponent * exponent),
                )
            factor = qmul(factor, qpow(x, exponent))
            term = qmul(term, factor)
        out = qadd(out, qscale(scalar, term))
    return out


def clone_qpoly(poly: QPoly) -> QPoly:
    return tuple(dict(component) for component in poly)  # type: ignore[return-value]


def add_monomial(poly: QPoly, coordinate: int, monomial: Monomial, value: int) -> QPoly:
    out = clone_qpoly(poly)
    updated = (out[coordinate].get(monomial, 0) + value) % Q
    if updated:
        out[coordinate][monomial] = updated
    else:
        out[coordinate].pop(monomial, None)
    return out


def compose_left_i(poly: QPoly) -> QPoly:
    """Return the public coefficient representation of X -> poly(i*X).

    Left multiplication by i maps
        (x0,x1,x2,x3) -> (-x1,x0,-x3,x2).
    It therefore acts by a signed permutation on every degree-13 monomial.
    """
    out: list[Poly] = [{}, {}, {}, {}]
    for coordinate, component in enumerate(poly):
        for (e0, e1, e2, e3), coeff in component.items():
            target = (e1, e0, e3, e2)
            sign = -1 if (e0 + e2) & 1 else 1
            value = (out[coordinate].get(target, 0) + sign * coeff) % Q
            if value:
                out[coordinate][target] = value
            else:
                out[coordinate].pop(target, None)
    return tuple(out)  # type: ignore[return-value]


def verify(public_f: QPoly, signature_t: QPoly, r_value: Quat, message: Quat, p: int) -> bool:
    """Literal two-stage verifier from Section 5 using public coefficients."""
    g = sum(message)
    first_f = qpeval(public_f, qmul(qpow(r_value, g), message))
    first_t = qpeval(signature_t, qmul(r_value, message))
    if first_f == first_t:
        return False
    second_f = qpeval(public_f, qpow(r_value, g + p))
    second_t = qpeval(signature_t, qpow(r_value, p + 1))
    return second_f == second_t


def all_degree_s_monomials() -> list[Monomial]:
    return [
        (e0, e1, e2, S - e0 - e1 - e2)
        for e0 in range(S + 1)
        for e1 in range(S - e0 + 1)
        for e2 in range(S - e0 - e1 + 1)
    ]


MONOMIALS = all_degree_s_monomials()


def polynomial_hash(poly: QPoly) -> str:
    packed = [
        [component.get(mon, 0) for mon in MONOMIALS]
        for component in poly
    ]
    encoded = json.dumps(packed, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def is_prime_trial(n: int) -> bool:
    if n < 2:
        return False
    p = 2
    while p * p <= n:
        if n % p == 0:
            return n == p
        p += 1 if p == 2 else 2
    return True


def random_quaternion(rng: random.Random) -> Quat:
    return tuple(rng.randrange(Q) for _ in range(4))  # type: ignore[return-value]


def forge_zero_query(public_f: QPoly) -> tuple[QPoly, QPoly, Quat, Quat, float]:
    """Forge using only the public coefficient representation of F."""
    attack_started = time.perf_counter()
    composed = compose_left_i(public_f)
    perturbation: Monomial = (0, 0, S, 0)
    forged_t = add_monomial(composed, 0, perturbation, 1)
    attack_seconds = time.perf_counter() - attack_started
    return forged_t, composed, I_UNIT, TWO_K, attack_seconds


def main() -> int:
    started = time.perf_counter()
    rng = random.Random(SEED)

    assert is_prime_trial(Q)
    assert len(MONOMIALS) == 560
    assert qmul(I_UNIT, K_UNIT) == (0, 0, Q - 1, 0)  # i*k=-j
    assert qpow(I_UNIT, 4) == ONE

    scalars = [rng.randrange(Q) for _ in range(M)]
    constants = [random_quaternion(rng) for _ in range(M)]

    # These conditions define the paper's advertised message/R domain.  For
    # uniform A_i and fixed noncentral i,k, a commutation event has probability
    # 1/q^2 per comparison; the fixed clean-room instance is audited directly.
    r_commuting = sum(commutes(I_UNIT, a) for a in constants)
    e_commuting = sum(commutes(TWO_K, a) for a in constants)
    assert not commutes(I_UNIT, TWO_K)
    assert r_commuting == 0
    assert e_commuting == 0

    public_f = expand_public_polynomial(scalars, constants)
    assert all(sum(mon) == S for component in public_f for mon in component)

    # Confirm that the 2,240 public coefficients implement equation (11).
    public_truth_checks = 8
    for _ in range(public_truth_checks):
        x = random_quaternion(rng)
        assert qpeval(public_f, x) == secret_eval(scalars, constants, x)

    # Zero-query forgery.  For E=2k, g=2.  The public polynomial F(iX)
    # evaluated at X=i^(p+1) is F(i^(p+2)), exactly the verifier's left side.
    # The perturbation x_2^13 vanishes on every power of R=i, but at
    # RE=i*(2k)=-2j it is nonzero.
    perturbation: Monomial = (0, 0, S, 0)
    signing_queries = 0
    forged_t, public_f_after_left_i, forged_r, forged_message, attack_seconds = (
        forge_zero_query(public_f)
    )
    assert forged_r == I_UNIT
    for _ in range(8):
        x = random_quaternion(rng)
        assert qpeval(public_f_after_left_i, x) == qpeval(public_f, qmul(I_UNIT, x))

    orbit = [qpow(I_UNIT, p + 1) for p in range(4)]
    orbit_expected = [I_UNIT, (Q - 1, 0, 0, 0), (0, Q - 1, 0, 0), ONE]
    assert orbit == orbit_expected
    assert all(pow(point[2], S, Q) == 0 for point in orbit)
    re_value = qmul(I_UNIT, forged_message)
    assert re_value == (0, 0, Q - 2, 0)
    assert pow(re_value[2], S, Q) == (-pow(2, S, Q)) % Q
    assert qmul(qpow(I_UNIT, sum(forged_message)), forged_message) == (0, 0, 0, Q - 2)
    assert qmul(I_UNIT, re_value) == (0, 0, 0, Q - 2)

    forged_all_p = all(
        verify(public_f, forged_t, I_UNIT, forged_message, p)
        for p in range(4)
    )
    assert forged_all_p

    # Generate an honest signature only after the public-input-only forger has
    # completed.  This proves the same E=2k target is in the working message
    # domain without supplying any oracle output to forge_zero_query().
    honest_message = TWO_K
    assert sum(honest_message) == 2
    assert not commutes(I_UNIT, honest_message)
    assert all(not commutes(honest_message, a) for a in constants)
    honest_t = expand_public_polynomial(
        scalars,
        constants,
        right_multiplier=I_UNIT,
        multiplier_exponent=sum(honest_message) - 1,
    )
    for _ in range(4):
        x = random_quaternion(rng)
        assert qpeval(honest_t, x) == secret_eval(
            scalars,
            constants,
            x,
            right_multiplier=I_UNIT,
            multiplier_exponent=1,
        )

    honest_all_p = all(
        verify(public_f, honest_t, I_UNIT, honest_message, p)
        for p in range(4)
    )
    assert honest_all_p

    honest_accepts = 0
    forged_accepts = 0
    sampled_ps: list[int] = []
    for _ in range(TRIALS):
        p = rng.randrange(Q * Q)
        sampled_ps.append(p)
        honest_accepts += verify(public_f, honest_t, I_UNIT, honest_message, p)
        forged_accepts += verify(public_f, forged_t, I_UNIT, forged_message, p)
    assert honest_accepts == TRIALS
    assert forged_accepts == TRIALS

    # The original g=1 construction is accepted for every p, but the honest
    # g=1 output T=F is rejected by the preliminary inequality.  Retain this
    # as a correctness regression while making the g=2 construction primary.
    legacy_g1_t = add_monomial(public_f, 0, perturbation, 1)
    legacy_g1_forgery_all_p = all(
        verify(public_f, legacy_g1_t, I_UNIT, K_UNIT, p) for p in range(4)
    )
    legacy_g1_honest_all_p = all(
        verify(public_f, public_f, I_UNIT, K_UNIT, p) for p in range(4)
    )
    assert legacy_g1_forgery_all_p
    assert not legacy_g1_honest_all_p

    # Seven independent changes each restore equality in the first check or
    # break the randomized identity at a fixed challenge.
    x0_13: Monomial = (S, 0, 0, 0)
    x1_13: Monomial = (0, S, 0, 0)
    x3_13: Monomial = (0, 0, 0, S)
    changed_message: Quat = (0, 0, 2, 0)
    assert not commutes(I_UNIT, changed_message)
    assert all(not commutes(changed_message, a) for a in constants)
    controls = {
        "remove_perturbation": verify(
            public_f, public_f_after_left_i, I_UNIT, forged_message, 0
        ),
        "wrong_x1_13_only": verify(
            public_f,
            add_monomial(public_f_after_left_i, 0, x1_13, 1),
            I_UNIT,
            forged_message,
            0,
        ),
        "wrong_x0_13_only": verify(
            public_f,
            add_monomial(public_f_after_left_i, 0, x0_13, 1),
            I_UNIT,
            forged_message,
            1,
        ),
        "wrong_x3_13_only": verify(
            public_f,
            add_monomial(public_f_after_left_i, 0, x3_13, 1),
            I_UNIT,
            forged_message,
            0,
        ),
        "extra_x0_13": verify(
            public_f, add_monomial(forged_t, 0, x0_13, 1), I_UNIT, forged_message, 3
        ),
        "extra_x1_13": verify(
            public_f, add_monomial(forged_t, 0, x1_13, 1), I_UNIT, forged_message, 0
        ),
        "changed_message_to_2j": any(
            verify(public_f, forged_t, I_UNIT, changed_message, p) for p in range(4)
        ),
    }
    assert len(controls) == 7
    assert not any(controls.values())

    elapsed = time.perf_counter() - started
    peak_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result = {
        "status": "PASS",
        "scheme": "Yagisawa quaternion signature",
        "eprint": "2010/352",
        "target_pdf_sha256": "37ad500d8c0442173422d1976f9185b45302de819825624bdfa862de3ec5f9b9",
        "parameters": {"q": Q, "q_bits": Q.bit_length(), "d": D, "r": R_EXP, "m": M, "s": S},
        "public_coefficients": 4 * len(MONOMIALS),
        "signing_queries": signing_queries,
        "attack_seconds": attack_seconds,
        "fresh_message": list(forged_message),
        "R": list(I_UNIT),
        "perturbation": {"output_coordinate": 0, "monomial": list(perturbation), "coefficient": 1},
        "quaternion_identity": {"i_times_2k": list(re_value), "i_order": 4},
        "domain_audit": {
            "R_noncommuting_with_message": True,
            "R_commuting_secret_constants": r_commuting,
            "message_commuting_secret_constants": e_commuting,
            "random_key_failure_union_bound": M * (2 / (Q * Q) - 1 / (Q * Q * Q)),
        },
        "public_secret_cross_checks": public_truth_checks,
        "public_composition_cross_checks": 8,
        "all_p_residue_classes": 4,
        "honest_trials": TRIALS,
        "honest_accepts": honest_accepts,
        "forgery_trials": TRIALS,
        "forgery_accepts": forged_accepts,
        "negative_controls": len(controls),
        "negative_controls_rejected": sum(not accepted for accepted in controls.values()),
        "control_results": controls,
        "legacy_g1_regression": {
            "forgery_all_p": legacy_g1_forgery_all_p,
            "honest_output_all_p": legacy_g1_honest_all_p,
        },
        "public_key_sha256": polynomial_hash(public_f),
        "composed_public_key_sha256": polynomial_hash(public_f_after_left_i),
        "honest_signature_T_sha256": polynomial_hash(honest_t),
        "forged_signature_T_sha256": polynomial_hash(forged_t),
        "sampled_p_sha256": hashlib.sha256(json.dumps(sampled_ps).encode()).hexdigest(),
        "elapsed_seconds": elapsed,
        "peak_rss_kib": peak_kib,
        "workers": 1,
        "python": sys.version.split()[0],
    }

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
