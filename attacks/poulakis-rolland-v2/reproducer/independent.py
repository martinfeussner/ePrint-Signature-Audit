#!/usr/bin/env python3
"""Independent full-size reproduction of a one-query PR-v2 forgery.

The construction follows Sections 2--4 and the 2048-bit-field example in
Poulakis--Rolland, ePrint 2012/134.  It uses the paper's p1,p2 endpoint but
generates a new subgroup generator, secret exponent, and signing split.
"""

from __future__ import annotations

import hashlib
import json
import math
import resource
import sys
import time
from dataclasses import dataclass


P1 = int(
    "61087960575038789816988536114150792266377636351843177587564"
    "31924627119957041754060999158399749767833896533906296859311"
    "25485163415231551275212583044052150577614828617005803730389"
    "43877400689242960278845109703690843026188873847913442234432"
    "36591255684234493362159572100747699404245339214008078743836"
    "7162669180839"
)
P2 = int(
    "950794575789036193985289494100238271764913649341936446441081"
    "377072500578035754538268902518142982960234055319718348171564"
    "531835348013169675598575434394528269729126327128190711758193"
    "487088395696503090307111303433870155114599617217105648040005"
    "344506796898422897977489196110610260665664553656001074068087"
    "13249343"
)

N = P1 * P2
FIELD_P = 4 * N - 1
PHI_N = (P1 - 1) * (P2 - 1)
G = 2
DECLARED_FACTOR_BITS = 1024
PUBLIC_SAFE_S_MAX = N - (1 << (DECLARED_FACTOR_BITS + 1))
INF = None


def H_bytes(domain: bytes, *parts: bytes, outlen: int) -> bytes:
    h = hashlib.shake_256()
    h.update(len(domain).to_bytes(2, "big"))
    h.update(domain)
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.digest(outlen)


def hash_below(domain: bytes, message: bytes, modulus: int, *, nonzero: bool = False):
    """Rejection sampling matching the paper's |n|-bit map-to-point outline."""
    bits = modulus.bit_length()
    outlen = (bits + 7) // 8
    excess = 8 * outlen - bits
    for counter in range(1 << 32):
        raw = bytearray(H_bytes(domain, message, counter.to_bytes(8, "big"), outlen=outlen))
        if excess:
            raw[0] &= (1 << (8 - excess)) - 1
        value = int.from_bytes(raw, "big")
        if value < modulus and (value != 0 or not nonzero):
            return value, counter
    raise RuntimeError("rejection sampler exhausted")


def drbg_below(label: bytes, modulus: int, *, nonzero: bool = True) -> int:
    return hash_below(b"PR-v2 independent DRBG/" + label, b"2026-10-09", modulus,
                      nonzero=nonzero)[0]


def inv_mod(x: int, modulus: int) -> int:
    return pow(x % modulus, -1, modulus)


def ec_add(P, Q):
    if P is INF:
        return Q
    if Q is INF:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % FIELD_P == 0:
        return INF
    if P == Q:
        if y1 == 0:
            return INF
        lam = (3 * x1 * x1 + 1) * inv_mod(2 * y1, FIELD_P) % FIELD_P
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, FIELD_P) % FIELD_P
    x3 = (lam * lam - x1 - x2) % FIELD_P
    y3 = (lam * (x1 - x3) - y1) % FIELD_P
    return x3, y3


def ec_neg(P):
    return INF if P is INF else (P[0], (-P[1]) % FIELD_P)


def ec_mul(k: int, P):
    if P is INF or k == 0:
        return INF
    if k < 0:
        return ec_mul(-k, ec_neg(P))
    R = INF
    T = P
    while k:
        if k & 1:
            R = ec_add(R, T)
        T = ec_add(T, T)
        k >>= 1
    return R


def on_curve(P) -> bool:
    if P is INF:
        return True
    x, y = P
    return 0 <= x < FIELD_P and 0 <= y < FIELD_P and (y * y - x * x * x - x) % FIELD_P == 0


def fresh_generator():
    for counter in range(1 << 32):
        x = int.from_bytes(H_bytes(b"PR-v2 independent P", counter.to_bytes(8, "big"),
                                   outlen=(FIELD_P.bit_length() + 7) // 8), "big") % FIELD_P
        rhs = (x * x * x + x) % FIELD_P
        if rhs == 0 or pow(rhs, (FIELD_P - 1) // 2, FIELD_P) != 1:
            continue
        y = pow(rhs, (FIELD_P + 1) // 4, FIELD_P)
        if y & 1:
            y = FIELD_P - y
        P = ec_mul(4, (x, y))
        if (P is not INF and ec_mul(N, P) is INF
                and ec_mul(P1, P) is not INF and ec_mul(P2, P) is not INF):
            return P, counter
    raise RuntimeError("generator search exhausted")


# F_(p^2) = F_p[i]/(i^2+1), represented as (real, imaginary).
F2_ONE = (1, 0)


def f2_add(a, b):
    return ((a[0] + b[0]) % FIELD_P, (a[1] + b[1]) % FIELD_P)


def f2_sub(a, b):
    return ((a[0] - b[0]) % FIELD_P, (a[1] - b[1]) % FIELD_P)


def f2_mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % FIELD_P,
            (a[0] * b[1] + a[1] * b[0]) % FIELD_P)


def f2_scale(a, c: int):
    return (a[0] * c % FIELD_P, a[1] * c % FIELD_P)


def f2_pow(a, exponent: int):
    r = F2_ONE
    while exponent:
        if exponent & 1:
            r = f2_mul(r, a)
        a = f2_mul(a, a)
        exponent >>= 1
    return r


def distort(P):
    if P is INF:
        return INF
    x, y = P
    return ((-x % FIELD_P, 0), (0, y))


def line_numerator(T, U, B):
    """Evaluate l_(T,U)(B); all omitted vertical denominators lie in F_p*."""
    if T is INF or U is INF:
        return F2_ONE
    x1, y1 = T
    x2, y2 = U
    bx, by = B
    if x1 == x2 and (y1 + y2) % FIELD_P == 0:
        # This whole vertical line lies in F_p and disappears after final exponentiation.
        return F2_ONE
    if T == U:
        lam = (3 * x1 * x1 + 1) * inv_mod(2 * y1, FIELD_P) % FIELD_P
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, FIELD_P) % FIELD_P
    return f2_sub(f2_sub(by, (y1, 0)), f2_scale(f2_sub(bx, (x1, 0)), lam))


def modified_tate(A, B):
    """Modified reduced Tate pairing e_n(A,B)=t_n(A,phi(B))."""
    if A is INF or B is INF:
        return F2_ONE
    D = distort(B)
    f = F2_ONE
    T = A
    for bit in bin(N)[3:]:
        f = f2_mul(f2_mul(f, f), line_numerator(T, T, D))
        T = ec_add(T, T)
        if bit == "1":
            f = f2_mul(f, line_numerator(T, A, D))
            T = ec_add(T, A)
    if T is not INF:
        raise AssertionError("Miller loop did not end at infinity")
    # q+1=4n, so (q^2-1)/n=4(q-1).
    return f2_pow(f, 4 * (FIELD_P - 1))


def h_scalar(message: bytes):
    return hash_below(b"PR-v2 h", message, N)[0]


def map_to_point(message: bytes, P):
    kappa, ctr = map_scalar(message)
    return ec_mul(kappa, P), kappa, ctr


def map_scalar(message: bytes):
    return hash_below(b"PR-v2 H", message, N, nonzero=True)


def compress(P):
    if P is INF:
        raise ValueError("identity has no ordinary signature encoding")
    return P[0], P[1] & 1


def decompress(x: int, sign: int):
    if not (0 <= x < FIELD_P and sign in (0, 1)):
        return INF
    rhs = (x * x * x + x) % FIELD_P
    if rhs == 0:
        y = 0
    elif pow(rhs, (FIELD_P - 1) // 2, FIELD_P) != 1:
        return INF
    else:
        y = pow(rhs, (FIELD_P + 1) // 4, FIELD_P)
    if y & 1 != sign:
        y = (-y) % FIELD_P
    P = (x, y)
    return P if on_curve(P) else INF


@dataclass(frozen=True)
class PublicKey:
    P: tuple[int, int]
    Q: tuple[int, int]
    g: int
    n: int


@dataclass(frozen=True)
class Signature:
    s: int
    x: int | None
    sign: int | None


def keygen(P):
    a = 2 + drbg_below(b"secret exponent a", PHI_N - 3, nonzero=False)
    Q = ec_mul(pow(G, a, N), P)
    return PublicKey(P, Q, G, N), a


def sign(message: bytes, pk: PublicKey, a: int):
    # The paper chooses positive k,l with k+l=a.
    k = 1 + drbg_below(b"one signing split k", a - 1, nonzero=False)
    l = a - k
    h = h_scalar(message)
    s = (k + h + N) % PHI_N
    if s == 0:
        raise RuntimeError("negligible zero scalar; change deterministic seed")
    # Section 4 denotes the map-to-point generator by Q; conservatively use
    # the public-key Q rather than choosing the favorable base P.
    Hm, _, _ = map_to_point(message, pk.Q)
    S = ec_mul(pow(pk.g, l, N), Hm)
    x, b = compress(S)
    return Signature(s, x, b), {"k": k, "l": l, "h": h}


def verify(message: bytes, sig: Signature, pk: PublicKey, *, with_reason=False):
    def out(ok, reason):
        return (ok, reason) if with_reason else ok

    # An implementable public check. Honest s is in [1,phi(n)-1], hence in [1,n-1].
    if not isinstance(sig.s, int) or not (1 <= sig.s < pk.n):
        return out(False, "scalar-range")
    if sig.x is None or sig.sign is None:
        return out(False, "identity-encoding")
    S = decompress(sig.x, sig.sign)
    if S is INF:
        return out(False, "point-decoding")
    if ec_mul(pk.n, S) is not INF:
        return out(False, "non-subgroup")
    Hm, _, _ = map_to_point(message, pk.Q)
    left_base = ec_mul(pow(pk.g, sig.s, pk.n), pk.P)
    rhs_scalar = pow(pk.g, h_scalar(message) + pk.n, pk.n)
    right_base = ec_mul(rhs_scalar, pk.Q)
    ok = modified_tate(left_base, S) == modified_tate(right_base, Hm)
    return out(ok, "pairing-equality" if ok else "pairing-mismatch")


def forge_one_query_range_sampled(m0: bytes, sig0: Signature, pk: PublicKey):
    """Range-preserving c/U forgery using public values and one signature."""
    S0 = decompress(sig0.x, sig0.sign)
    kappa0, _ = map_scalar(m0)
    if math.gcd(kappa0, pk.n) != 1:
        raise RuntimeError("queried map scalar is not invertible")
    c = sig0.s - h_scalar(m0)
    U = ec_mul(pow(kappa0, -1, pk.n), S0)

    # A public bound from factors of at most 1024 bits guarantees
    # s* < phi(n): phi(n)=n-(p1+p2)+1 > n-2^1025.
    for attempt in range(1, 1 << 20):
        message = b"fresh existential forgery candidate/" + attempt.to_bytes(8, "big")
        h_star = h_scalar(message)
        s_star = c + h_star
        if not (1 <= s_star <= PUBLIC_SAFE_S_MAX):
            continue
        kappa_star, _ = map_scalar(message)
        S_star = ec_mul(kappa_star, U)
        x, b = compress(S_star)
        return message, Signature(s_star, x, b), {
            "attempts": attempt,
            "c_sign": -1 if c < 0 else 1,
            "c_bits": abs(c).bit_length(),
            "kappa0_invertible": True,
        }
    raise RuntimeError("public target-message sampler exhausted")


def forge_one_query_same_s(m0: bytes, sig0: Signature, pk: PublicKey, target: bytes):
    """Stronger public-only variant: keep the oracle's valid response s unchanged.

    For H(m)=[kappa_m]G_H (with G_H=Q here), scale S0 by
      mu=(kappa*/kappa0) g^(h*-h0) mod n.
    Bilinearity transfers the pairing equation from m0 to any fresh target.
    """
    if target == m0:
        raise ValueError("target must be fresh")
    S0 = decompress(sig0.x, sig0.sign)
    kappa0, _ = map_scalar(m0)
    if math.gcd(kappa0, pk.n) != 1:
        raise RuntimeError("queried map scalar is not invertible")
    kappa_star, _ = map_scalar(target)
    delta_h = h_scalar(target) - h_scalar(m0)
    mu = kappa_star * pow(kappa0, -1, pk.n) % pk.n
    mu = mu * pow(pk.g, delta_h, pk.n) % pk.n
    S_star = ec_mul(mu, S0)
    x, b = compress(S_star)
    return Signature(sig0.s, x, b), {
        "s_reused_exactly": True,
        "target_sampling_attempts": 0,
        "kappa0_invertible": True,
        "works_for_fixed_target": True,
    }


def probable_prime(n: int, bases=(2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)):
    if n < 2 or n % 2 == 0:
        return n == 2
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def main():
    started = time.perf_counter()
    checkpoints = {}
    prime_checks = {"p1": probable_prime(P1), "p2": probable_prime(P2), "field_p": probable_prime(FIELD_P)}
    assert all(prime_checks.values())
    assert FIELD_P % 4 == 3 and FIELD_P + 1 == 4 * N
    checkpoints["parameter_checks_s"] = time.perf_counter() - started

    P, generator_counter = fresh_generator()
    assert on_curve(P) and ec_mul(N, P) is INF
    pk, a = keygen(P)
    checkpoints["keygen_s"] = time.perf_counter() - started - sum(checkpoints.values())

    m0 = b"single chosen-message signing query"
    m_star = b"fixed fresh target chosen before the attack"
    sig0, signing_meta = sign(m0, pk, a)
    t = time.perf_counter()
    honest_ok, honest_reason = verify(m0, sig0, pk, with_reason=True)
    checkpoints["honest_verify_s"] = time.perf_counter() - t
    assert honest_ok

    t = time.perf_counter()
    sig_star, forge_meta = forge_one_query_same_s(m0, sig0, pk, m_star)
    checkpoints["same_s_attack_only_s"] = time.perf_counter() - t
    assert m_star != m0
    t = time.perf_counter()
    forged_ok, forged_reason = verify(m_star, sig_star, pk, with_reason=True)
    checkpoints["forged_verify_s"] = time.perf_counter() - t
    assert forged_ok

    # Independently exercise the c=s0-h(m0), U=[kappa0^-1]S0 construction.
    # This form chooses a public-range target.
    t = time.perf_counter()
    m_range, sig_range, range_meta = forge_one_query_range_sampled(m0, sig0, pk)
    checkpoints["range_sampled_attack_only_s"] = time.perf_counter() - t
    t = time.perf_counter()
    range_ok, range_reason = verify(m_range, sig_range, pk, with_reason=True)
    checkpoints["range_sampled_verify_s"] = time.perf_counter() - t
    assert range_ok and m_range != m0

    S_star = decompress(sig_star.x, sig_star.sign)
    altered = ec_add(S_star, pk.P)
    altered_x, altered_b = compress(altered)
    control_inputs = {
        "changed_message": (m_star + b"/changed", sig_star),
        "altered_point": (m_star, Signature(sig_star.s, altered_x, altered_b)),
        "flipped_point_sign": (m_star, Signature(sig_star.s, sig_star.x, 1 - sig_star.sign)),
        "altered_scalar": (m_star, Signature(sig_star.s + 1, sig_star.x, sig_star.sign)),
        "identity": (m_star, Signature(sig_star.s, None, None)),
        "non_subgroup_order_2": (m_star, Signature(sig_star.s, 0, 0)),
    }
    controls = {}
    t = time.perf_counter()
    for name, args in control_inputs.items():
        accepted, reason = verify(*args, pk, with_reason=True)
        controls[name] = {"accepted": accepted, "reason": reason}
        assert not accepted, name
    checkpoints["negative_controls_s"] = time.perf_counter() - t

    # Attack algebra: U is the message-independent [g^l]P signing witness.
    S0 = decompress(sig0.x, sig0.sign)
    kappa0, _ = map_scalar(m0)
    U = ec_mul(pow(kappa0, -1, N), S0)
    assert U == ec_mul(pow(G, signing_meta["l"], N), pk.Q)

    elapsed = time.perf_counter() - started
    result = {
        "result": "PASS",
        "attack": "one-query fresh-message existential forgery",
        "endpoint": {
            "factor_bits": [P1.bit_length(), P2.bit_length()],
            "n_bits": N.bit_length(),
            "field_bits": FIELD_P.bit_length(),
            "curve": "y^2=x^3+x over F_p, p=4n-1",
            "pairing": "modified reduced Tate via distortion (-x, i*y)",
            "generator_search_counter": generator_counter,
            "fresh_key_material": True,
        },
        "query_count": 1,
        "messages_distinct": m0 != m_star,
        "honest_signature": {"accepted": honest_ok, "reason": honest_reason},
        "forgery_same_s": {"accepted": forged_ok, "reason": forged_reason, **forge_meta},
        "forgery_range_sampled": {
            "accepted": range_ok,
            "reason": range_reason,
            "s_in_actual_phi_range_observer_check": 1 <= sig_range.s < PHI_N,
            **range_meta,
        },
        "negative_controls": controls,
        "parameter_probable_prime_checks": prime_checks,
        "timings": {**{k: round(v, 6) for k, v in checkpoints.items()}, "total_s": round(elapsed, 6)},
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "python": sys.version.split()[0],
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
