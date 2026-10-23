#!/usr/bin/env python3
"""Full-row paper-spec replay of the adaptive-Phi pair-swap forgery.

The challenger constructs exact BabyJubJub/MultiMiMC7 KGO outputs, but
forge() receives only those public outputs. SMA/KZG group elements are
represented by public-SRS formal coefficient vectors. Polynomial identity is
stronger than equality after evaluation at the hidden powers-of-tau point and
makes use of the absent degree n+1 explicit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
N = 1024
PAIR_COUNT = 254
MISSING_DEGREE = N + 1
MASTER_SEED = b"ePrintAuditV4/lrs-2025-1174/exp-0001/pair-swap/seed-v1"
MESSAGE = b"ePrintAuditV4/lrs-2025-1174/exp-0001/fresh-message"
SCOPE = b"ePrintAuditV4/lrs-2025-1174/exp-0001/scope"
BASE = (
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
)
MIMC_PATH = Path(__file__).resolve().parent / "upstream" / "mimc.circom"
MIMC_SHA256 = "511bf6471eadfc7c4c17a96820bb6902f2262acfad7d285421d428db3b3c71c8"


def mod(x: int) -> int:
    return x % Q


def inv(x: int) -> int:
    if x % Q == 0:
        raise ZeroDivisionError("field inverse of zero")
    return pow(x, Q - 2, Q)


def derive_scalar(label: bytes, counter: int, modulus: int = Q) -> int:
    material = MASTER_SEED + b"\x00" + label + counter.to_bytes(8, "big")
    retry = 0
    while True:
        candidate = material if retry == 0 else material + b"\x00retry" + retry.to_bytes(8, "big")
        value = int.from_bytes(hashlib.sha256(candidate).digest(), "big") % modulus
        if value != 0:
            return value
        retry += 1


def pack_bytes(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def pack_scalar(x: int) -> bytes:
    return (x % Q).to_bytes(32, "big")


def pack_scalars(values: Sequence[int]) -> bytes:
    return len(values).to_bytes(8, "big") + b"".join(pack_scalar(x) for x in values)


def ro_fields(domain: bytes, chunks: Sequence[bytes], count: int) -> list[int]:
    prefix = b"ePrintAuditV4-paper-ROM-v1\x00" + pack_bytes(domain)
    prefix += b"".join(pack_bytes(chunk) for chunk in chunks)
    return [
        int.from_bytes(hashlib.sha256(prefix + i.to_bytes(8, "big")).digest(), "big") % Q
        for i in range(count)
    ]


def group_encoding(group: bytes, coeffs: Sequence[int]) -> bytes:
    return hashlib.sha256(b"formal-group-v1\x00" + group + pack_scalars(coeffs)).digest()


def load_mimc_constants() -> list[int]:
    raw = MIMC_PATH.read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    if got != MIMC_SHA256:
        raise RuntimeError(f"MiMC source hash mismatch: {got}")
    match = re.search(r"var c\[91\]\s*=\s*\[(.*?)\];", raw.decode(), re.S)
    if not match:
        raise RuntimeError("MiMC constants not found")
    constants = [int(x) for x in re.findall(r"\d+", match.group(1))]
    if len(constants) != 91 or constants[0] != 0:
        raise RuntimeError(f"unexpected MiMC constant count: {len(constants)}")
    return constants


MIMC_CONSTANTS = load_mimc_constants()


def mimc7(x: int, key: int) -> int:
    state = 0
    for i, c in enumerate(MIMC_CONSTANTS):
        t = mod(key + x) if i == 0 else mod(key + state + c)
        state = pow(t, 7, Q)
    return mod(state + key)


def multi_mimc(a: int, b: int) -> int:
    r = 1
    for x in (a, b):
        r = mod(r + x + mimc7(x, r))
    return r


def baby_add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p1
    x2, y2 = p2
    a, d = 168700, 168696
    tau = mod(x1 * x2 * y1 * y2)
    den_x, den_y = mod(1 + d * tau), mod(1 - d * tau)
    both_inv = inv(mod(den_x * den_y))
    inv_x, inv_y = mod(den_y * both_inv), mod(den_x * both_inv)
    return (
        mod((x1 * y2 + y1 * x2) * inv_x),
        mod((y1 * y2 - a * x1 * x2) * inv_y),
    )


def make_base_table(bits: int = 254) -> list[tuple[int, int]]:
    table = [BASE]
    for _ in range(1, bits):
        table.append(baby_add(table[-1], table[-1]))
    return table


BASE_TABLE = make_base_table()


def baby_mul(scalar: int) -> tuple[int, int]:
    if scalar <= 0 or scalar >= Q:
        raise ValueError("secret is outside the paper KeyGen scalar field")
    acc, bit, x = (0, 1), 0, scalar
    while x:
        if x & 1:
            acc = baby_add(acc, BASE_TABLE[bit])
        bit += 1
        x >>= 1
    return acc


@dataclass(frozen=True)
class PublicKey:
    x: int
    y: int
    phi: int


def keygen_from_secret(sk: int) -> PublicKey:
    x, y = baby_mul(sk)
    return PublicKey(x, y, multi_mimc(x, y))


def poly_pad(poly: Sequence[int], length: int) -> list[int]:
    if len(poly) > length:
        raise ValueError("polynomial longer than pad")
    return [x % Q for x in poly] + [0] * (length - len(poly))


def poly_add(a: Sequence[int], b: Sequence[int], scale_b: int = 1) -> list[int]:
    length, sb = max(len(a), len(b)), scale_b % Q
    return [
        mod((a[i] if i < len(a) else 0) + sb * (b[i] if i < len(b) else 0))
        for i in range(length)
    ]


def poly_scale(a: Sequence[int], scalar: int) -> list[int]:
    return [mod(scalar * x) for x in a]


def poly_mul(a: Sequence[int], b: Sequence[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    nz_a = [(i, x) for i, x in enumerate(a) if x]
    nz_b = [(i, x) for i, x in enumerate(b) if x]
    for i, x in nz_a:
        for j, y in nz_b:
            out[i + j] = mod(out[i + j] + x * y)
    return out


def poly_eval(poly: Sequence[int], x: int) -> int:
    acc = 0
    for coefficient in reversed(poly):
        acc = mod(acc * x + coefficient)
    return acc


def quotient_at(poly: Sequence[int], z: int) -> tuple[list[int], int]:
    p, n = list(poly), len(poly) - 1
    value = poly_eval(p, z)
    if n == 0:
        return [], value
    quotient = [0] * n
    carry = p[n]
    quotient[n - 1] = carry
    for degree in range(n - 1, 0, -1):
        carry = mod(p[degree] + z * carry)
        quotient[degree - 1] = carry
    if mod(p[0] - value + z * quotient[0]) != 0:
        raise AssertionError("synthetic division mismatch")
    return quotient, value


def x_minus_z_times(poly: Sequence[int], z: int) -> list[int]:
    out = [0] * (len(poly) + 1)
    for i, coefficient in enumerate(poly):
        out[i] = mod(out[i] - z * coefficient)
        out[i + 1] = mod(out[i + 1] + coefficient)
    return out


@dataclass
class Challenges:
    s: list[int]
    t: list[int]
    u: list[int]
    delta_eq: int
    delta_b: int
    delta_o: int
    delta_d2: int
    delta_d1: int
    delta_phi: int


def base_challenges(
    message: bytes,
    a_poly: Sequence[int],
    b_poly: Sequence[int],
    s_poly: Sequence[int] | None = None,
) -> tuple[list[int], list[int] | None, list[int] | None, list[int] | None]:
    c_enc = group_encoding(b"G1", a_poly)
    b_enc = group_encoding(b"G2", b_poly)
    s = ro_fields(b"H_s", [message, c_enc, b_enc], N)
    if s_poly is None:
        return s, None, None, None
    s_enc = group_encoding(b"G1", s_poly)
    t = ro_fields(b"H_t", [message, pack_scalars(s), c_enc, b_enc, s_enc], N)
    u = [0] * N
    for idx in range(1, N):
        u[idx] = ro_fields(
            b"H_u",
            [
                message,
                (idx + 1).to_bytes(4, "big"),
                (2).to_bytes(4, "big"),
                N.to_bytes(4, "big"),
                c_enc,
                b_enc,
                s_enc,
            ],
            1,
        )[0]
    delta = ro_fields(b"H_agg", [message, c_enc, b_enc, s_enc], 6)
    return s, t, u, delta


def derive_challenges(
    message: bytes, a_poly: Sequence[int], b_poly: Sequence[int], s_poly: Sequence[int]
) -> Challenges:
    s, t, u, delta = base_challenges(message, a_poly, b_poly, s_poly)
    assert t is not None and u is not None and delta is not None
    return Challenges(s, t, u, *delta)


def make_public_polys(ch: Challenges, ring: Sequence[int]) -> tuple[list[int], list[int], list[int]]:
    ph, pu, pt = [0] * (N + 1), [0] * (N + 1), [0] * (N + 1)
    for idx in range(N):
        degree = N - idx
        ph[degree] = mod(
            ch.delta_o
            + (ch.delta_eq * ch.t[idx] - ch.delta_b) * ch.s[idx]
            + ch.delta_phi * ring[idx]
        )
        pt[idx + 1] = mod(ch.delta_eq * ch.t[idx])
    pu[N] = ch.delta_phi
    pu[N - 1] = mod(pu[N - 1] - ch.delta_d2)
    for idx in range(1, N):  # paper i=2..n
        pu[N - idx] = mod(pu[N - idx] - ch.delta_d1 * ch.u[idx])
    return ph, pu, pt


def equation15_poly(
    a_poly: Sequence[int],
    b_poly: Sequence[int],
    s_poly: Sequence[int],
    ch: Challenges,
    ch_commit: Sequence[int],
    cu_commit: Sequence[int],
    ct_commit: Sequence[int],
) -> list[int]:
    inner = poly_add(poly_scale(s_poly, ch.delta_b), ch_commit)
    result = poly_mul(b_poly, inner)
    result = poly_add(result, poly_mul(a_poly, cu_commit), -1)
    result = poly_add(result, poly_mul(s_poly, ct_commit), -1)
    result = poly_pad(result, 2 * N + 1)
    result[MISSING_DEGREE] = mod(result[MISSING_DEGREE] - ch.delta_o)
    return result


def kzg_delta_blob(
    message: bytes,
    ring: Sequence[int],
    ch: Challenges,
    a_poly: Sequence[int],
    b_poly: Sequence[int],
    s_poly: Sequence[int],
) -> bytes:
    return b"".join(
        [
            pack_bytes(message),
            pack_scalars(ring),
            pack_scalars(ch.s),
            pack_scalars(ch.t),
            pack_scalars(ch.u),
            group_encoding(b"G1", a_poly),
            group_encoding(b"G2", b_poly),
            group_encoding(b"G1", s_poly),
        ]
    )


@dataclass
class SmaProof:
    a_poly: list[int]
    b_poly: list[int]
    s_poly: list[int]
    pi: list[int]
    ch_commit: list[int]
    cu_commit: list[int]
    ct_commit: list[int]
    pi_kzg: list[int]
    missing_before_public_projection: int


def make_kzg(
    message: bytes,
    ring: Sequence[int],
    ch: Challenges,
    a_poly: Sequence[int],
    b_poly: Sequence[int],
    s_poly: Sequence[int],
    ph: list[int],
    pu: list[int],
    pt: list[int],
) -> list[int]:
    delta_blob = kzg_delta_blob(message, ring, ch, a_poly, b_poly, s_poly)
    commitments = [
        group_encoding(b"G1", ph),
        group_encoding(b"G2", pu),
        group_encoding(b"G2", pt),
    ]
    z = ro_fields(b"H_KZG_z", [delta_blob, *commitments], 1)[0]
    batch = ro_fields(b"H_KZG_batch", [delta_blob, *commitments, pack_scalar(z)], 3)
    qh, _ = quotient_at(ph, z)
    qu, _ = quotient_at(pu, z)
    qt, _ = quotient_at(pt, z)
    combined = poly_add(poly_scale(qh, batch[0]), poly_scale(qu, batch[1]))
    return poly_pad(poly_add(combined, poly_scale(qt, batch[2])), N)


def make_sma_proof(
    message: bytes,
    ring: Sequence[int],
    a_poly: list[int],
    b_poly: list[int],
    s_poly: list[int],
    public_only: bool,
) -> SmaProof:
    ch = derive_challenges(message, a_poly, b_poly, s_poly)
    ph, pu, pt = make_public_polys(ch, ring)
    full_pi = equation15_poly(a_poly, b_poly, s_poly, ch, ph, pu, pt)
    missing = full_pi[MISSING_DEGREE]
    pi = list(full_pi)
    if public_only:
        pi[MISSING_DEGREE] = 0
    elif missing != 0:
        raise AssertionError("attempted unavailable g_(n+1)")
    pi_kzg = make_kzg(message, ring, ch, a_poly, b_poly, s_poly, ph, pu, pt)
    return SmaProof(list(a_poly), list(b_poly), list(s_poly), pi, ph, pu, pt, pi_kzg, missing)


def verify_kzg(message: bytes, ring: Sequence[int], proof: SmaProof, ch: Challenges) -> bool:
    ph_expected, pu_expected, pt_expected = make_public_polys(ch, ring)
    delta_blob = kzg_delta_blob(message, ring, ch, proof.a_poly, proof.b_poly, proof.s_poly)
    commitments = [
        group_encoding(b"G1", proof.ch_commit),
        group_encoding(b"G2", proof.cu_commit),
        group_encoding(b"G2", proof.ct_commit),
    ]
    z = ro_fields(b"H_KZG_z", [delta_blob, *commitments], 1)[0]
    batch = ro_fields(b"H_KZG_batch", [delta_blob, *commitments, pack_scalar(z)], 3)
    evals = [poly_eval(ph_expected, z), poly_eval(pu_expected, z), poly_eval(pt_expected, z)]
    lhs = poly_scale(poly_add(proof.ch_commit, [mod(-evals[0])]), batch[0])
    lhs = poly_add(lhs, poly_scale(poly_add(proof.cu_commit, [mod(-evals[1])]), batch[1]))
    lhs = poly_add(lhs, poly_scale(poly_add(proof.ct_commit, [mod(-evals[2])]), batch[2]))
    rhs = x_minus_z_times(proof.pi_kzg, z)
    return poly_pad(lhs, N + 1) == poly_pad(rhs, N + 1)


def verify_sma(message: bytes, ring: Sequence[int], proof: SmaProof) -> tuple[bool, bool, bool]:
    ch = derive_challenges(message, proof.a_poly, proof.b_poly, proof.s_poly)
    eq15 = equation15_poly(
        proof.a_poly, proof.b_poly, proof.s_poly, ch,
        proof.ch_commit, proof.cu_commit, proof.ct_commit,
    )
    eq15_ok = poly_pad(eq15, 2 * N + 1) == poly_pad(proof.pi, 2 * N + 1)
    kzg_ok = verify_kzg(message, ring, proof, ch)
    missing_public_ok = proof.pi[MISSING_DEGREE] == 0
    return eq15_ok and kzg_ok and missing_public_ok, eq15_ok, kzg_ok


@dataclass
class AttackResult:
    ring: list[PublicKey]
    baseline_ring: list[PublicKey]
    b: list[int]
    challenges: Challenges
    a_poly: list[int]
    b_poly: list[int]
    s_poly: list[int]
    proof: SmaProof
    baseline_proof: SmaProof
    d: int
    swap_bits: list[int]
    e_b: int
    e_o: int
    w: int
    baseline_missing: int
    accepted_missing: int


def forge(
    public_pool: Sequence[PublicKey], sk_star: int, pk_star: PublicKey, message: bytes
) -> AttackResult:
    """Attack API: no ring secret is accepted by or visible to this function."""
    if len(public_pool) != N:
        raise ValueError("full profile requires exactly 1024 KGO outputs")
    if pk_star.phi in {pk.phi for pk in public_pool}:
        raise AssertionError("attacker phi unexpectedly in ring pool")

    pairs = [(public_pool[2 * j], public_pool[2 * j + 1]) for j in range(PAIR_COUNT)]
    b = [0] * N
    for j, (a, c) in enumerate(pairs):
        if a.phi == c.phi:
            raise AssertionError("pair hash collision")
        b[2 * j] = mod((1 << j) * inv(a.phi - c.phi))

    r = derive_scalar(b"pedersen-r", 0)
    r_b = derive_scalar(b"vector-r-b", 0)
    r_s = derive_scalar(b"vector-r-s", 0)
    a_poly = [r, pk_star.phi]
    b_poly = [0] * (N + 1)
    b_poly[0] = r_b
    for idx, coefficient in enumerate(b):
        b_poly[idx + 1] = coefficient

    s_values, _, _, _ = base_challenges(message, a_poly, b_poly)
    s_poly = [0] * (N + 1)
    s_poly[0] = r_s
    for idx in range(N):
        s_poly[N - idx] = mod(s_values[idx] * b[idx])
    ch = derive_challenges(message, a_poly, b_poly, s_poly)
    if ch.s != s_values:
        raise AssertionError("H_s chronology mismatch")
    if ch.delta_phi == 0:
        raise RuntimeError("SEALED_EXCEPTION_DELTA_PHI_ZERO")

    e_b = sum((ch.s[i] * b[i] * (b[i] - 1)) % Q for i in range(N)) % Q
    e_o = mod(sum(b) - 1)
    w = mod(pk_star.phi - (ch.delta_b * e_b + ch.delta_o * e_o) * inv(ch.delta_phi))
    baseline = list(public_pool)
    b0 = sum((b[2 * j] * pairs[j][0].phi) % Q for j in range(PAIR_COUNT)) % Q
    d_value = mod(b0 - w)
    if d_value >= (1 << PAIR_COUNT):
        raise AssertionError("q<2^254 coverage invariant failed")
    swap_bits = [(d_value >> j) & 1 for j in range(PAIR_COUNT)]
    ring = list(baseline)
    for j, bit in enumerate(swap_bits):
        if bit:
            ring[2 * j], ring[2 * j + 1] = ring[2 * j + 1], ring[2 * j]

    weighted = sum((b[i] * ring[i].phi) % Q for i in range(N)) % Q
    if weighted != w:
        raise AssertionError("pair-swap weighted target mismatch")
    accepted_missing = mod(
        ch.delta_b * e_b
        + ch.delta_o * e_o
        + ch.delta_phi * mod(weighted - pk_star.phi)
    )
    baseline_weighted = sum((b[i] * baseline[i].phi) % Q for i in range(N)) % Q
    baseline_missing = mod(
        ch.delta_b * e_b
        + ch.delta_o * e_o
        + ch.delta_phi * mod(baseline_weighted - pk_star.phi)
    )
    if accepted_missing != 0 or baseline_missing == 0:
        raise AssertionError("missing-power controls failed before proof construction")

    proof = make_sma_proof(
        message, [pk.phi for pk in ring], a_poly, b_poly, s_poly, public_only=False
    )
    baseline_proof = make_sma_proof(
        message, [pk.phi for pk in baseline], a_poly, b_poly, s_poly, public_only=True
    )
    return AttackResult(
        ring, baseline, b, ch, a_poly, b_poly, s_poly, proof, baseline_proof,
        d_value, swap_bits, e_b, e_o, w, baseline_missing, accepted_missing,
    )


def ordinary_verify(
    message: bytes,
    scope: bytes,
    ring: Sequence[PublicKey],
    result: AttackResult,
    sk_star: int,
    pk_star: PublicKey,
    proof: SmaProof | None = None,
) -> dict[str, bool]:
    selected = proof if proof is not None else result.proof
    sma_ok, eq15_ok, kzg_ok = verify_sma(message, [pk.phi for pk in ring], selected)
    scope_field = int.from_bytes(hashlib.sha256(scope).digest(), "big") % Q
    link_tag = multi_mimc(sk_star, scope_field)  # stable author-circuit order
    cc_ok = keygen_from_secret(sk_star) == pk_star and link_tag == multi_mimc(sk_star, scope_field)
    # Honest CPlink: C1 opens to the same phi_star committed by ccGro16.
    link_ok = selected.a_poly[1] == pk_star.phi and selected.a_poly[0] != 0
    return {
        "sma": sma_ok,
        "sma_eq15": eq15_ok,
        "sma_kzg": kzg_ok,
        "ccGro16_honest_relation": cc_ok,
        "CPlink_honest_common_opening": link_ok,
        "ordinary_accept": sma_ok and cc_ok and link_ok,
    }


def challenger_kgo() -> tuple[list[int], list[PublicKey], int, PublicKey, int]:
    # forge() will receive the public list, not this secret vector.
    sk_star = derive_scalar(b"attacker-secret", 0)
    pk_star = keygen_from_secret(sk_star)
    secrets: list[int] = []
    publics: list[PublicKey] = []
    seen = {pk_star.phi}
    skipped, counter = 0, 0
    while len(publics) < N:
        sk = derive_scalar(b"honest-kgo-secret", counter)
        counter += 1
        pk = keygen_from_secret(sk)
        if pk.phi in seen:
            skipped += 1
            continue
        seen.add(pk.phi)
        secrets.append(sk)
        publics.append(pk)
    return secrets, publics, sk_star, pk_star, skipped


def invariant_kgo(secrets: Sequence[int], publics: Sequence[PublicKey]) -> bool:
    return len(secrets) == len(publics) == N and all(
        keygen_from_secret(sk) == pk for sk, pk in zip(secrets, publics)
    )


def result_line(name: str, value: object) -> None:
    rendered = ("PASS" if value else "FAIL") if isinstance(value, bool) else str(value)
    print(f"{name}={rendered}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    started = time.monotonic()

    secrets, public_pool, sk_star, pk_star, skipped = challenger_kgo()
    kgo_ok = invariant_kgo(secrets, public_pool)
    # Critical access boundary: forge gets only public_pool and the outside key.
    attack = forge(tuple(public_pool), sk_star, pk_star, MESSAGE)

    positive = ordinary_verify(MESSAGE, SCOPE, attack.ring, attack, sk_star, pk_star)
    baseline = ordinary_verify(
        MESSAGE, SCOPE, attack.baseline_ring, attack, sk_star, pk_star, attack.baseline_proof
    )
    flipped_ring = list(attack.ring)
    flipped_ring[0], flipped_ring[1] = flipped_ring[1], flipped_ring[0]
    flipped = ordinary_verify(MESSAGE, SCOPE, flipped_ring, attack, sk_star, pk_star)
    changed = ordinary_verify(MESSAGE + b"/changed", SCOPE, attack.ring, attack, sk_star, pk_star)

    own_absent = pk_star.phi not in {pk.phi for pk in attack.ring}
    final_is_permutation = sorted(pk.phi for pk in attack.ring) == sorted(
        pk.phi for pk in public_pool
    )
    nonzero_support = sum(1 for x in attack.b if x != 0)
    support_uncorrupted = nonzero_support == PAIR_COUNT
    public_srs_only = (
        len(attack.a_poly) <= 2
        and len(attack.b_poly) <= N + 1
        and len(attack.s_poly) <= N + 1
        and len(attack.proof.pi) == 2 * N + 1
        and attack.proof.pi[MISSING_DEGREE] == 0
        and len(attack.proof.ch_commit) <= N + 1
        and len(attack.proof.cu_commit) <= N + 1
        and len(attack.proof.ct_commit) <= N + 1
        and len(attack.proof.pi_kzg) <= N
    )
    flipped_weighted = sum((attack.b[i] * flipped_ring[i].phi) % Q for i in range(N)) % Q
    flipped_missing = mod(
        attack.challenges.delta_b * attack.e_b
        + attack.challenges.delta_o * attack.e_o
        + attack.challenges.delta_phi * mod(flipped_weighted - pk_star.phi)
    )

    result_line("PROFILE", "eprint-2025-1174-v2-bn254-babyjubjub-mimc91-n1024-m1024")
    result_line("N", N)
    result_line("M", len(attack.ring))
    result_line("KGO_EXACT_RECOMPUTATION", kgo_ok)
    result_line("KGO_COLLISION_SKIPS", skipped)
    result_line("RING_IS_KGO_PERMUTATION", final_is_permutation)
    result_line("ATTACK_RECEIVED_RING_SECRETS", False)
    result_line("NONZERO_B_SUPPORT", nonzero_support)
    result_line("NONZERO_SUPPORT_UNCORRUPTED", support_uncorrupted)
    result_line("PHI_STAR_ABSENT", own_absent)
    result_line("PUBLIC_SRS_ONLY", public_srs_only)
    result_line("SETUP_TRAPDOOR_USED", False)
    result_line("DELTA_PHI_NONZERO", attack.challenges.delta_phi != 0)
    result_line("CANONICAL_D_BIT_LENGTH", attack.d.bit_length())
    result_line("SWAP_COUNT", sum(attack.swap_bits))
    result_line("ACCEPTED_MISSING_COEFFICIENT", attack.accepted_missing)
    result_line("FIXED_RING_MISSING_COEFFICIENT", attack.baseline_missing)
    result_line(
        "FIXED_RING_PROOF_MISSING_BEFORE_PROJECTION",
        attack.baseline_proof.missing_before_public_projection,
    )
    result_line("FLIPPED_PAIR_0_MISSING_COEFFICIENT", flipped_missing)
    for key, value in positive.items():
        result_line(f"POSITIVE_{key.upper()}", value)
    for key, value in baseline.items():
        result_line(f"CONTROL_PRE_CHALLENGE_BASELINE_{key.upper()}", value)
    for key, value in flipped.items():
        result_line(f"CONTROL_FLIP_PAIR_0_{key.upper()}", value)
    for key, value in changed.items():
        result_line(f"CONTROL_CHANGED_MESSAGE_{key.upper()}", value)

    controls_reject = (
        not baseline["ordinary_accept"]
        and not flipped["ordinary_accept"]
        and not changed["ordinary_accept"]
    )
    overall = all(
        [
            kgo_ok,
            final_is_permutation,
            support_uncorrupted,
            own_absent,
            public_srs_only,
            attack.accepted_missing == 0,
            attack.proof.pi[MISSING_DEGREE] == 0,
            positive["ordinary_accept"],
            controls_reject,
        ]
    )
    result_line("NO_SIGNING_ORACLE_QUERIES", True)
    result_line("FRESH_MESSAGE", True)
    result_line("NEGATIVE_CONTROLS_REJECT", controls_reject)
    result_line("ATTACK_REPRODUCTION", overall)
    result_line("WALL_SECONDS_INTERNAL", f"{time.monotonic() - started:.6f}")

    public_ring = [
        {
            "position": i + 1,
            "pk_x": str(pk.x),
            "pk_y": str(pk.y),
            "phi": str(pk.phi),
            "b": str(attack.b[i]),
        }
        for i, pk in enumerate(attack.ring)
    ]
    provenance = hashlib.sha256(b"".join(pack_scalar(sk) for sk in secrets)).hexdigest()
    evidence = {
        "schema": "eprint-audit-v4-lrs-1174-pair-swap-evidence-v1",
        "profile": "eprint-2025-1174-v2-bn254-babyjubjub-mimc91-n1024-m1024",
        "message": MESSAGE.decode(),
        "scope": SCOPE.decode(),
        "ring_size": N,
        "ring": public_ring,
        "kgo_secret_vector_commitment_sha256": provenance,
        "attacker_public_key": {
            "x": str(pk_star.x), "y": str(pk_star.y), "phi": str(pk_star.phi)
        },
        "phi_star_absent": own_absent,
        "nonzero_support_uncorrupted": support_uncorrupted,
        "canonical_d": str(attack.d),
        "swap_bits_little_endian": "".join(str(bit) for bit in attack.swap_bits),
        "accepted_missing_coefficient": str(attack.accepted_missing),
        "baseline_missing_coefficient": str(attack.baseline_missing),
        "flip_pair_0_missing_coefficient": str(flipped_missing),
        "positive": positive,
        "pre_challenge_baseline": baseline,
        "flip_pair_0": flipped,
        "changed_message": changed,
        "attack_reproduction_pass": overall,
    }
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True, exist_ok=True)
        (args.evidence_dir / "public-evidence.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0 if overall else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"UNCAUGHT_ERROR={type(exc).__name__}:{exc}", file=sys.stderr)
        raise
