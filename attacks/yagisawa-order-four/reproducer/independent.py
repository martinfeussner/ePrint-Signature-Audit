#!/usr/bin/env python3
"""Independent full-row reproduction of the Yagisawa order-four forgery.

This is a from-paper implementation of ePrint 2010/352.  The verifier only
uses the public coefficient arrays and the submitted signature tuple (T,R,E).
The forger receives only the same public coefficient arrays.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


Q = 1_048_583                 # 2^20 + 7: odd, prime, and 21 bits
D = 2
R_PARAM = 3
M = 448
S = sum(R_PARAM ** j for j in range(D + 1))  # 1 + 3 + 9 = 13
SEED = 0x59414749534157415F494E444550454E44454E54

Quat = Tuple[int, int, int, int]
Exp = Tuple[int, int, int, int]
ScalarPoly = Dict[Exp, int]
QuatPoly = List[ScalarPoly]

# Hamilton multiplication table: basis[a] * basis[b] = sign * basis[out].
QMUL_TABLE: Tuple[Tuple[Tuple[int, int], ...], ...] = (
    ((0, +1), (1, +1), (2, +1), (3, +1)),
    ((1, +1), (0, -1), (3, +1), (2, -1)),
    ((2, +1), (3, -1), (0, -1), (1, +1)),
    ((3, +1), (2, +1), (1, -1), (0, -1)),
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def is_prime_trial(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    for d in range(3, math.isqrt(n) + 1, 2):
        if n % d == 0:
            return False
    return True


def qadd(a: Quat, b: Quat, q: int = Q) -> Quat:
    return tuple((a[i] + b[i]) % q for i in range(4))  # type: ignore[return-value]


def qscale(c: int, a: Quat, q: int = Q) -> Quat:
    return tuple((c * a[i]) % q for i in range(4))  # type: ignore[return-value]


def qmul(a: Quat, b: Quat, q: int = Q) -> Quat:
    a0, a1, a2, a3 = a
    b0, b1, b2, b3 = b
    return (
        (a0*b0 - a1*b1 - a2*b2 - a3*b3) % q,
        (a0*b1 + a1*b0 + a2*b3 - a3*b2) % q,
        (a0*b2 - a1*b3 + a2*b0 + a3*b1) % q,
        (a0*b3 + a1*b2 - a2*b1 + a3*b0) % q,
    )


def qpow(a: Quat, e: int, q: int = Q) -> Quat:
    if e < 0:
        raise ValueError("negative quaternion exponent is not used here")
    out: Quat = (1, 0, 0, 0)
    base = a
    while e:
        if e & 1:
            out = qmul(out, base, q)
        base = qmul(base, base, q)
        e >>= 1
    return out


def commutes(a: Quat, b: Quat, q: int = Q) -> bool:
    return qmul(a, b, q) == qmul(b, a, q)


def monomials_of_degree(degree: int) -> List[Exp]:
    out: List[Exp] = []
    for e0 in range(degree + 1):
        for e1 in range(degree - e0 + 1):
            for e2 in range(degree - e0 - e1 + 1):
                e3 = degree - e0 - e1 - e2
                out.append((e0, e1, e2, e3))
    return out


MONOMIALS = monomials_of_degree(S)
MONOMIAL_INDEX = {e: i for i, e in enumerate(MONOMIALS)}


def exp_add(a: Exp, b: Exp) -> Exp:
    return (a[0]+b[0], a[1]+b[1], a[2]+b[2], a[3]+b[3])


def qpoly_mul(a: QuatPoly, b: QuatPoly, q: int = Q) -> QuatPoly:
    out: QuatPoly = [{}, {}, {}, {}]
    for ia in range(4):
        if not a[ia]:
            continue
        for ib in range(4):
            if not b[ib]:
                continue
            io, sign = QMUL_TABLE[ia][ib]
            dst = out[io]
            for ea, ca in a[ia].items():
                for eb, cb in b[ib].items():
                    e = exp_add(ea, eb)
                    dst[e] = (dst.get(e, 0) + sign * ca * cb) % q
    for component in out:
        for e in [e for e, c in component.items() if c == 0]:
            del component[e]
    return out


def qpoly_pow(a: QuatPoly, e: int, q: int = Q) -> QuatPoly:
    out: QuatPoly = [{(0, 0, 0, 0): 1}, {}, {}, {}]
    base = a
    while e:
        if e & 1:
            out = qpoly_mul(out, base, q)
        base = qpoly_mul(base, base, q)
        e >>= 1
    return out


def const_left_mul(a: Quat, p: QuatPoly, q: int = Q) -> QuatPoly:
    out: QuatPoly = [{}, {}, {}, {}]
    for ia, ca in enumerate(a):
        if ca == 0:
            continue
        for ib in range(4):
            if not p[ib]:
                continue
            io, sign = QMUL_TABLE[ia][ib]
            dst = out[io]
            for e, cb in p[ib].items():
                dst[e] = (dst.get(e, 0) + sign * ca * cb) % q
    for component in out:
        for e in [e for e, c in component.items() if c == 0]:
            del component[e]
    return out


def add_scaled_in_place(dst: QuatPoly, c: int, src: QuatPoly,
                        q: int = Q) -> None:
    for component in range(4):
        d = dst[component]
        for e, value in src[component].items():
            d[e] = (d.get(e, 0) + c * value) % q


def coefficient_array(p: QuatPoly) -> List[List[int]]:
    return [
        [p[component].get(e, 0) for e in MONOMIALS]
        for component in range(4)
    ]


def coefficient_sha256(coefficients: Sequence[Sequence[int]]) -> str:
    # Canonical fixed-width little-endian encoding, component-major.
    width = (Q.bit_length() + 7) // 8
    h = hashlib.sha256()
    for component in coefficients:
        for c in component:
            h.update(int(c).to_bytes(width, "little"))
    return h.hexdigest()


def eval_coefficients(coefficients: Sequence[Sequence[int]], x: Quat,
                      q: int = Q) -> Quat:
    powers = [[1] * (S + 1) for _ in range(4)]
    for coordinate in range(4):
        for e in range(1, S + 1):
            powers[coordinate][e] = powers[coordinate][e-1] * x[coordinate] % q
    values = [0, 0, 0, 0]
    for component in range(4):
        acc = 0
        for c, e in zip(coefficients[component], MONOMIALS):
            if c:
                term = c
                term = term * powers[0][e[0]] % q
                term = term * powers[1][e[1]] % q
                term = term * powers[2][e[2]] % q
                term = term * powers[3][e[3]] % q
                acc += term
        values[component] = acc % q
    return tuple(values)  # type: ignore[return-value]


def build_x_powers() -> List[QuatPoly]:
    x: QuatPoly = [
        {(1, 0, 0, 0): 1},
        {(0, 1, 0, 0): 1},
        {(0, 0, 1, 0): 1},
        {(0, 0, 0, 1): 1},
    ]
    return [qpoly_pow(x, R_PARAM ** j) for j in range(D + 1)]


def build_from_constants(terms: Sequence[Tuple[int, Sequence[Quat]]],
                         x_powers: Sequence[QuatPoly]) -> List[List[int]]:
    """Expand sum_i k_i prod_j (C_ij X^(r^j))."""
    total: QuatPoly = [{}, {}, {}, {}]
    for k, constants in terms:
        product: QuatPoly = [{(0, 0, 0, 0): 1}, {}, {}, {}]
        for constant, x_power in zip(constants, x_powers):
            product = qpoly_mul(product, const_left_mul(constant, x_power))
        add_scaled_in_place(total, k, product)
    return coefficient_array(total)


@dataclass(frozen=True)
class SecretTerm:
    k: int
    a: Quat


@dataclass(frozen=True)
class Signature:
    t: List[List[int]]
    r: Quat
    e: Quat


def keygen(rng: random.Random, x_powers: Sequence[QuatPoly]) -> Tuple[List[SecretTerm], List[List[int]]]:
    secret = [
        SecretTerm(rng.randrange(1, Q), tuple(rng.randrange(Q) for _ in range(4)))
        for _ in range(M)
    ]
    public = build_from_constants(
        [
            (term.k, [qpow(term.a, R_PARAM ** j) for j in range(D + 1)])
            for term in secret
        ],
        x_powers,
    )
    return secret, public


def honest_sign(secret: Sequence[SecretTerm], r: Quat, e: Quat,
                x_powers: Sequence[QuatPoly]) -> Signature:
    g = sum(e) % Q
    terms: List[Tuple[int, Sequence[Quat]]] = []
    for term in secret:
        constants = [
            qmul(
                qpow(term.a, R_PARAM ** j),
                qpow(r, (R_PARAM ** j) * (g - 1)),
            )
            for j in range(D + 1)
        ]
        terms.append((term.k, constants))
    return Signature(build_from_constants(terms, x_powers), r, e)


def direct_f(secret: Sequence[SecretTerm], x: Quat) -> Quat:
    """Evaluate paper equation (11) directly, without public coefficients."""
    total: Quat = (0, 0, 0, 0)
    for term in secret:
        product: Quat = (1, 0, 0, 0)
        for j in range(D + 1):
            exponent = R_PARAM ** j
            product = qmul(product, qmul(qpow(term.a, exponent), qpow(x, exponent)))
        total = qadd(total, qscale(term.k, product))
    return total


def direct_t(secret: Sequence[SecretTerm], r: Quat, e: Quat,
             x: Quat) -> Quat:
    """Evaluate paper equation (12) directly, without T coefficients."""
    g = sum(e) % Q
    total: Quat = (0, 0, 0, 0)
    for term in secret:
        product: Quat = (1, 0, 0, 0)
        for j in range(D + 1):
            exponent = R_PARAM ** j
            factor = qmul(
                qmul(qpow(term.a, exponent), qpow(r, (g - 1) * exponent)),
                qpow(x, exponent),
            )
            product = qmul(product, factor)
        total = qadd(total, qscale(term.k, product))
    return total


def perturb(coefficients: Sequence[Sequence[int]], exponent: Exp,
            component: int = 0, delta: int = 1) -> List[List[int]]:
    out = [list(row) for row in coefficients]
    out[component][MONOMIAL_INDEX[exponent]] = (
        out[component][MONOMIAL_INDEX[exponent]] + delta
    ) % Q
    return out


def verify(public: Sequence[Sequence[int]], signature: Signature,
           p_values: Iterable[int]) -> Tuple[bool, str, List[dict]]:
    """Paper verifier using no secret material."""
    r, e, t = signature.r, signature.e, signature.t
    g = sum(e) % Q
    guard_left = eval_coefficients(public, qmul(qpow(r, g), e))
    guard_right = eval_coefficients(t, qmul(r, e))
    if guard_left == guard_right:
        return False, "guard_equality", [{
            "check": "F(R^g E) != T(RE)",
            "left": list(guard_left),
            "right": list(guard_right),
        }]

    checks: List[dict] = []
    for p in p_values:
        left_x = qpow(r, g + p)
        right_x = qpow(r, p + 1)
        left = eval_coefficients(public, left_x)
        right = eval_coefficients(t, right_x)
        equal = left == right
        checks.append({
            "p": p,
            "p_mod_4": p % 4,
            "left_input": list(left_x),
            "right_input": list(right_x),
            "equal": equal,
        })
        if not equal:
            return False, "random_p_equality", checks
    return True, "accepted", checks


def write_coeff_artifact(path: Path, kind: str,
                         coefficients: Sequence[Sequence[int]],
                         extra: dict | None = None) -> None:
    doc = {
        "kind": kind,
        "parameters": {"q": Q, "d": D, "r": R_PARAM, "m": M, "s": S},
        "ordering": "component-major; monomials lexicographic ascending (e0,e1,e2,e3)",
        "monomials": [list(e) for e in MONOMIALS],
        "coefficients": coefficients,
        "canonical_coefficient_sha256": coefficient_sha256(coefficients),
    }
    if extra:
        doc.update(extra)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    timings: Dict[str, float] = {}
    assert is_prime_trial(Q)
    assert Q.bit_length() == 21 and Q % 2 == 1
    assert len(MONOMIALS) == math.comb(S + 3, 3) == 560
    assert 4 * len(MONOMIALS) == 2240
    one: Quat = (1, 0, 0, 0)
    i_basis: Quat = (0, 1, 0, 0)
    j_basis: Quat = (0, 0, 1, 0)
    k_basis_check: Quat = (0, 0, 0, 1)
    minus_one: Quat = (Q - 1, 0, 0, 0)
    basis_laws = {
        "i_squared_minus_one": qmul(i_basis, i_basis) == minus_one,
        "j_squared_minus_one": qmul(j_basis, j_basis) == minus_one,
        "k_squared_minus_one": qmul(k_basis_check, k_basis_check) == minus_one,
        "ij_equals_k": qmul(i_basis, j_basis) == k_basis_check,
        "jk_equals_i": qmul(j_basis, k_basis_check) == i_basis,
        "ki_equals_j": qmul(k_basis_check, i_basis) == j_basis,
        "ji_equals_minus_k": qmul(j_basis, i_basis) == qscale(Q - 1, k_basis_check),
        "one_is_identity": qmul(one, i_basis) == i_basis and qmul(i_basis, one) == i_basis,
    }
    assert all(basis_laws.values())

    t0 = time.perf_counter()
    x_powers = build_x_powers()
    timings["build_symbolic_x_powers_seconds"] = time.perf_counter() - t0

    rng = random.Random(SEED)
    t0 = time.perf_counter()
    secret, public = keygen(rng, x_powers)
    timings["full_row_keygen_and_public_expansion_seconds"] = time.perf_counter() - t0

    conformance_rng = random.Random(SEED ^ 0x434F4E464F524D414E4345)
    conformance_points: List[Quat] = [
        (1, 0, 0, 0),
        (0, 1, 0, 0),
        tuple(conformance_rng.randrange(Q) for _ in range(4)),
        tuple(conformance_rng.randrange(Q) for _ in range(4)),
    ]
    t0 = time.perf_counter()
    f_conformance = [
        {
            "point": list(x),
            "coefficient_value": list(eval_coefficients(public, x)),
            "direct_value": list(direct_f(secret, x)),
        }
        for x in conformance_points
    ]
    timings["direct_public_key_conformance_seconds"] = time.perf_counter() - t0
    assert all(row["coefficient_value"] == row["direct_value"] for row in f_conformance)

    i: Quat = (0, 1, 0, 0)
    e_primary: Quat = (0, 0, 0, 2)   # 2k, hence g=2
    e_secondary: Quat = (0, 0, 0, 1) # k, hence g=1
    e_changed: Quat = (0, 0, 2, 0)   # 2j, hence g=2
    fixed_pair_valid = {
        "R_i_noncommutes_with_every_A": all(not commutes(i, term.a) for term in secret),
        "E_2k_noncommutes_with_every_A": all(not commutes(e_primary, term.a) for term in secret),
        "E_k_noncommutes_with_every_A": all(not commutes(e_secondary, term.a) for term in secret),
        "E_2j_noncommutes_with_every_A": all(not commutes(e_changed, term.a) for term in secret),
        "R_i_noncommutes_with_E_2k": not commutes(i, e_primary),
        "R_i_noncommutes_with_E_k": not commutes(i, e_secondary),
        "R_i_noncommutes_with_E_2j": not commutes(i, e_changed),
    }
    if not all(fixed_pair_valid.values()):
        raise RuntimeError(f"deterministic ordinary key missed fixed-pair validity: {fixed_pair_valid}")

    # Materialize the only input made available to the isolated forger.
    public_path = args.output / "public-key.json"
    write_coeff_artifact(
        public_path, "public-key-F", public,
        {"seed_commitment": hashlib.sha256(str(SEED).encode()).hexdigest()},
    )

    primary_path = args.output / "forgery.json"
    secondary_path = args.output / "forgery-g1-regression.json"
    forger_path = Path(__file__).with_name("public_forger.py")
    isolated_forger_argv = [
        sys.executable,
        str(forger_path),
        "--public-key", str(public_path),
        "--primary-output", str(primary_path),
        "--secondary-output", str(secondary_path),
    ]
    t0 = time.perf_counter()
    isolated = subprocess.run(
        isolated_forger_argv,
        check=True,
        capture_output=True,
        text=True,
    )
    timings["isolated_public_only_forger_seconds"] = time.perf_counter() - t0
    (args.output / "isolated-forger.stdout").write_text(isolated.stdout)
    (args.output / "isolated-forger.stderr").write_text(isolated.stderr)
    primary_doc = json.loads(primary_path.read_text())
    secondary_doc = json.loads(secondary_path.read_text())
    assert primary_doc["signing_queries"] == secondary_doc["signing_queries"] == 0
    assert not primary_doc["forger_interface"]["signing_oracle_available"]
    assert not primary_doc["forger_interface"]["secret_material_available"]
    forged = Signature(
        primary_doc["coefficients"], tuple(primary_doc["R"]), tuple(primary_doc["E"])
    )
    forged_g1 = Signature(
        secondary_doc["coefficients"], tuple(secondary_doc["R"]), tuple(secondary_doc["E"])
    )

    all_p_representatives = [0, 1, 2, 3]
    t0 = time.perf_counter()
    forged_ok, forged_reason, forged_checks = verify(public, forged, all_p_representatives)
    timings["primary_forgery_all_p_classes_verification_seconds"] = time.perf_counter() - t0
    assert forged_ok, forged_reason
    g1_ok, g1_reason, g1_checks = verify(public, forged_g1, all_p_representatives)
    assert g1_ok, g1_reason

    # Removing D from the primary artifact leaves exactly the public signed
    # monomial permutation for F(iX). Check it against direct public evaluation.
    composed_f_ix = perturb(forged.t, (0, 0, S, 0), delta=-1)
    composition_conformance = [
        {
            "point": list(x),
            "permuted_coefficients_value": list(eval_coefficients(composed_f_ix, x)),
            "direct_public_F_at_iX": list(eval_coefficients(public, qmul(i, x))),
        }
        for x in conformance_points
    ]
    assert all(
        row["permuted_coefficients_value"] == row["direct_public_F_at_iX"]
        for row in composition_conformance
    )

    # Period/order proof and perturbation values for both forgeries.
    order_four = (
        qpow(i, 4) == (1, 0, 0, 0)
        and len({qpow(i, e) for e in range(4)}) == 4
    )
    assert order_four
    subgroup = [qpow(i, e) for e in range(4)]
    d_coeff = [[0] * len(MONOMIALS) for _ in range(4)]
    d_coeff[0][MONOMIAL_INDEX[(0, 0, S, 0)]] = 1
    d_on_subgroup = [eval_coefficients(d_coeff, x) for x in subgroup]
    primary_anti_point = qmul(i, e_primary)   # -2j
    secondary_anti_point = qmul(i, e_secondary) # -j
    d_on_primary_anti_point = eval_coefficients(d_coeff, primary_anti_point)
    d_on_secondary_anti_point = eval_coefficients(d_coeff, secondary_anti_point)
    assert all(value == (0, 0, 0, 0) for value in d_on_subgroup)
    assert d_on_primary_anti_point != (0, 0, 0, 0)
    assert d_on_secondary_anti_point != (0, 0, 0, 0)

    # Only after the public forgery has been produced and accepted, generate
    # an honest signature on exactly the same E=2k target.
    t0 = time.perf_counter()
    honest = honest_sign(secret, i, e_primary, x_powers)
    timings["post_forgery_same_message_honest_signature_expansion_seconds"] = time.perf_counter() - t0
    t0 = time.perf_counter()
    t_conformance = [
        {
            "point": list(x),
            "coefficient_value": list(eval_coefficients(honest.t, x)),
            "direct_value": list(direct_t(secret, honest.r, honest.e, x)),
        }
        for x in conformance_points
    ]
    timings["direct_honest_signature_conformance_seconds"] = time.perf_counter() - t0
    assert all(row["coefficient_value"] == row["direct_value"] for row in t_conformance)
    t0 = time.perf_counter()
    honest_ok, honest_reason, honest_checks = verify(public, honest, all_p_representatives)
    timings["post_forgery_same_message_honest_verification_seconds"] = time.perf_counter() - t0
    assert honest_ok, honest_reason

    # Negative control 1: omit D, retaining exactly F(iX). The guard catches it.
    no_perturb = Signature(composed_f_ix, i, e_primary)
    np_ok, np_reason, np_checks = verify(public, no_perturb, all_p_representatives)
    assert not np_ok and np_reason == "guard_equality"

    # Negative control 2: add x0^13 as well. It preserves the guard effect at
    # -2j but fails when the order-four subgroup reaches +/-1.
    bad_support_t = perturb(forged.t, (S, 0, 0, 0))
    bad_support = Signature(bad_support_t, i, e_primary)
    bs_ok, bs_reason, bs_checks = verify(public, bad_support, all_p_representatives)
    assert not bs_ok and bs_reason == "random_p_equality"

    # Negative control 3: change E=2k to the paper-valid E'=2j while retaining T*.
    changed_message = Signature(forged.t, i, e_changed)
    cm_ok, cm_reason, cm_checks = verify(public, changed_message, all_p_representatives)
    assert not cm_ok and cm_reason == "guard_equality"

    total_seconds = time.perf_counter() - started
    timings["total_seconds"] = total_seconds

    results = {
        "experiment": "YAGISAWA-ORDER-FOUR-INDEPENDENT",
        "disposition": "PASS_ZERO_QUERY_FULL_PARAMETER_G2_FRESH_MESSAGE_FORGERY",
        "source_boundary": "checksum-pinned ePrint 2010/352 final PDF/text only",
        "target": {
            "eprint": "2010/352",
            "title": "A Digital Signature Using Multivariate Functions on Quaternion Ring",
            "pdf_sha256": "37ad500d8c0442173422d1976f9185b45302de819825624bdfa862de3ec5f9b9",
            "text_sha256": "19c7abb8e26191292bfaf776432a79d14436ab849b0e356372321f61397ab2c7",
        },
        "parameters": {
            "q": Q,
            "q_bits": Q.bit_length(),
            "q_is_prime_by_complete_trial_division": is_prime_trial(Q),
            "d": D,
            "r": R_PARAM,
            "m": M,
            "s": S,
            "monomials_per_output": len(MONOMIALS),
            "public_coefficients": 4 * len(MONOMIALS),
            "secret_scalars": M,
            "secret_quaternion_coordinates": 4 * M,
            "secret_variables_total": 5 * M,
        },
        "quaternion_basis_self_checks": basis_laws,
        "public_key": {
            "coefficient_sha256": coefficient_sha256(public),
            "nonzero_coefficients": sum(c != 0 for row in public for c in row),
        },
        "independent_equation_conformance": {
            "equation_11_public_F": f_conformance,
            "equation_12_honest_T": t_conformance,
            "public_signed_monomial_permutation_F_iX": composition_conformance,
            "all_match": True,
        },
        "fixed_forgery_pair_validity": fixed_pair_valid,
        "honest_same_message_signature_generated_after_forgery": {
            "generated_after_primary_forgery_accepted": True,
            "accepted": honest_ok,
            "reason": honest_reason,
            "R": list(honest.r),
            "E": list(honest.e),
            "g": sum(honest.e) % Q,
            "T_coefficient_sha256": coefficient_sha256(honest.t),
            "p_values": all_p_representatives,
            "checks": honest_checks,
        },
        "primary_forgery_g2": {
            "signing_queries": 0,
            "fresh_message_at_forgery_time": True,
            "isolated_process": True,
            "forger_inputs": ["serialized public coefficient representation F"],
            "signing_oracle_available": False,
            "secret_material_available": False,
            "R": list(forged.r),
            "E": list(forged.e),
            "g": sum(forged.e) % Q,
            "T_construction": "F(iX) by public signed monomial permutation, plus scalar-output monomial x2^13",
            "T_coefficient_sha256": coefficient_sha256(forged.t),
            "accepted": forged_ok,
            "reason": forged_reason,
            "R_order_exactly_four": order_four,
            "p_period": 4,
            "p_residue_classes_checked": all_p_representatives,
            "all_integer_p_covered_by_periodicity": True,
            "subgroup_points": [list(x) for x in subgroup],
            "perturbation_on_subgroup": [list(x) for x in d_on_subgroup],
            "anti_substitution_point_R_times_E": list(primary_anti_point),
            "perturbation_at_anti_substitution_point": list(d_on_primary_anti_point),
            "checks": forged_checks,
        },
        "secondary_g1_regression": {
            "signing_queries": 0,
            "R": list(forged_g1.r),
            "E": list(forged_g1.e),
            "g": sum(forged_g1.e) % Q,
            "T_construction": "F(X) plus scalar-output monomial x2^13",
            "T_coefficient_sha256": coefficient_sha256(forged_g1.t),
            "accepted": g1_ok,
            "reason": g1_reason,
            "p_residue_classes_checked": all_p_representatives,
            "all_integer_p_covered_by_periodicity": True,
            "anti_substitution_point_R_times_E": list(secondary_anti_point),
            "perturbation_at_anti_substitution_point": list(d_on_secondary_anti_point),
            "checks": g1_checks,
        },
        "negative_controls": {
            "omitted_perturbation_T_equals_F_iX": {
                "accepted": np_ok,
                "reason": np_reason,
                "checks": np_checks,
            },
            "perturbation_with_x0_13_leak_on_order_four_subgroup": {
                "accepted": bs_ok,
                "reason": bs_reason,
                "checks": bs_checks,
            },
            "changed_message_E_prime_equals_2j": {
                "accepted": cm_ok,
                "reason": cm_reason,
                "checks": cm_checks,
            },
        },
        "timings": timings,
        "implementation": {
            "language": "Python 3 standard library only",
            "deterministic_seed_hex": hex(SEED),
            "reproduce_py_sha256": sha256_file(Path(__file__)),
            "public_forger_py_sha256": sha256_file(forger_path),
            "isolated_forger_argv": isolated_forger_argv,
            "isolated_forger_stdout": isolated.stdout,
            "isolated_forger_stderr": isolated.stderr,
            "event_order": [
                "generate and serialize public F",
                "run isolated public-only forger with zero signing queries",
                "verify primary g=2 forgery for every p mod 4",
                "generate honest signature on the same E=2k",
                "verify same-message honest signature",
            ],
        },
    }

    write_coeff_artifact(
        args.output / "honest-signature.json", "post-forgery-same-message-honest-signature-T", honest.t,
        {
            "R": list(honest.r),
            "E": list(honest.e),
            "generated_after_primary_forgery_accepted": True,
        },
    )
    (args.output / "results.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps({
        "disposition": results["disposition"],
        "q": Q,
        "full_row": [D, R_PARAM, M, S],
        "public_coefficients": 4 * len(MONOMIALS),
        "honest_same_message_accepted_after_forgery": honest_ok,
        "primary_g2_forgery_accepted": forged_ok,
        "secondary_g1_regression_accepted": g1_ok,
        "all_p_classes": all_p_representatives,
        "negative_controls_rejected": [not np_ok, not bs_ok, not cm_ok],
        "public_key_sha256": coefficient_sha256(public),
        "primary_g2_forgery_sha256": coefficient_sha256(forged.t),
        "secondary_g1_forgery_sha256": coefficient_sha256(forged_g1.t),
        "total_seconds": total_seconds,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
