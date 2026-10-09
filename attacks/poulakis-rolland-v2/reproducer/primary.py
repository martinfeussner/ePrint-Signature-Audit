#!/usr/bin/env python3
"""Poulakis--Rolland v2 full-parameter reconstruction and one-query forgery.

This is a clean-room executable model of ePrint 2012/134, revision
20150430:055329.  It uses the paper's printed 1023- and 1024-bit factors and a
corrected generator derived from the printed example.  SHAKE256 instantiates
the paper's abstract hash/KDF interfaces.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import sys
import time
from dataclasses import dataclass


P1 = int(
    "61087960575038789816988536114150792266377636351843177587564319246271199570417540609991583997497678338965339062968593112548516341523155127521258304405215057761482861700580373038943877400689242960278845109703690843026188873847913442234432365912556842344933621595721007476994042453392140080787438367162669180839"
)
P2 = int(
    "95079457578903619398528949410023827176491364934193644644108137707250057803575453826890251814298296023405531971834817156453183534801316967559857543439452826972912632712819071175819348708839569650309030711130343387015511459961721710564804000534450679689842289797748919611061026066566455365600107406808713249343"
)
N = P1 * P2
PHI = (P1 - 1) * (P2 - 1)
QFIELD = 4 * N - 1
G = 2
A = (1 << 256) + (1 << 9) + 1

# The paper prints x(P)=2^1500+2.  Its printed y(P) has one extra decimal
# digit near the end.  Taking the q == 3 mod 4 square root repairs that typo.
PRINTED_XP = (1 << 1500) + 2
PRINTED_YP = int(
    "92629334720096485394250229023531473128561210303747369871170532503591346084781038053790347765721405539373837575715741111302632222520728502603977901582753916707479492439228918725855423715991340003621514555505206507732534242013847767107764800751435936328543137789247911179152023276247696951339536945505339588067200491193957998044975563046555194785086909103272771864842171753848435480722850484547366650914307823107502201128733622163636510656608071825566283432994640380462713709910638633429178083083878848700277309884412794341026781057881112432733889255328105052291841518470922081921433382412472012678120546125640726148962"
)
PRINTED_XQ = int(
    "4929066269630890940118676840165480358358027921633777075970567954555377619703413204182898033360761758707320538968410060117892434111734916010762648188844327776866756495663993605440601155890594094956263486692530338536439206685871072096621223391963085213804194323958767770010377591298098261888264447928963024835312975003285776611156441376633776947815847988008319196552077880554266338219162536485455422641818199238687159366040776610195158709092926451452926125820820564544916736264069574112504476158054648006035374272664210840670688899424879273678267062426009254707550914157923366582588873582336648011173165127581579893233"
)
PRINTED_YQ = int(
    "9251640006679849414362134638435628671328426925266395037136231007610587593256539123868607426378281972116750233717652921901662256889076587632786360429521239281996051884310217309505235221721760612499163363529422455175409284709873271636908991699714235667300461460401314617119825149525737613057257718590923730935907182295497757283180913934597216850220500675730525413684644075563296631876920873257853188066562736344515028989009339090827154585880138328472819829180452504062174178921959822834145697232804630292818810258440117103130036374232447169484309288773766481841241697043304934210730109599042000468957343998962535886947"
)
PRINTED_Q = (PRINTED_XQ, PRINTED_YQ)

Point = tuple[int, int] | None
Fp2 = tuple[int, int]


def ec_on_curve(p: Point) -> bool:
    if p is None:
        return True
    x, y = p
    return (y * y - x * x * x - x) % QFIELD == 0


def ec_neg(p: Point) -> Point:
    return None if p is None else (p[0], (-p[1]) % QFIELD)


def ec_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % QFIELD == 0:
            return None
        lam = (3 * x1 * x1 + 1) * pow(2 * y1, -1, QFIELD) % QFIELD
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, QFIELD) % QFIELD
    x3 = (lam * lam - x1 - x2) % QFIELD
    return x3, (lam * (x1 - x3) - y1) % QFIELD


def ec_mul(k: int, p: Point) -> Point:
    if k < 0:
        return ec_mul(-k, ec_neg(p))
    out = None
    while k:
        if k & 1:
            out = ec_add(out, p)
        p = ec_add(p, p)
        k >>= 1
    return out


def f2_mul(x: Fp2, y: Fp2) -> Fp2:
    a, b = x
    c, d = y
    ac = a * c % QFIELD
    bd = b * d % QFIELD
    return (ac - bd) % QFIELD, ((a + b) * (c + d) - ac - bd) % QFIELD


def f2_sq(x: Fp2) -> Fp2:
    a, b = x
    return (a * a - b * b) % QFIELD, (2 * a * b) % QFIELD


def f2_inv(x: Fp2) -> Fp2:
    a, b = x
    z = pow((a * a + b * b) % QFIELD, -1, QFIELD)
    return a * z % QFIELD, -b * z % QFIELD


def f2_pow(x: Fp2, k: int) -> Fp2:
    out = (1, 0)
    while k:
        if k & 1:
            out = f2_mul(out, x)
        x = f2_sq(x)
        k >>= 1
    return out


def miller_line_and_sum(a: Point, b: Point, distorted_eval: tuple[int, int]) -> tuple[Fp2, Point]:
    """Return the line through a,b at phi(B), and a+b.

    Vertical denominators are deliberately omitted: at the final exponent
    (q^2-1)/n = 4(q-1), every nonzero F_q denominator maps to one.
    """
    assert a is not None and b is not None
    xa, ya = a
    xb, yb = b
    tx, ty = distorted_eval  # phi(B)=((-x_B), i*y_B)
    if xa == xb and (ya + yb) % QFIELD == 0:
        # A vertical F_q line also disappears after final exponentiation.
        return (1, 0), None
    if a == b:
        lam = (3 * xa * xa + 1) * pow(2 * ya, -1, QFIELD) % QFIELD
    else:
        lam = (yb - ya) * pow(xb - xa, -1, QFIELD) % QFIELD
    xr = (lam * lam - xa - xb) % QFIELD
    yr = (lam * (xa - xr) - ya) % QFIELD
    # y(phi(B))-ya-lam*(x(phi(B))-xa); x(phi(B)) is in F_q,
    # y(phi(B)) is purely imaginary.
    line = ((-ya - lam * (tx - xa)) % QFIELD, ty)
    return line, (xr, yr)


def modified_tate(p: Point, b: Point) -> Fp2:
    """Reduced modified Tate pairing e_n(p,b)=t_n(p,phi(b))."""
    assert p is not None and b is not None
    distorted = ((-b[0]) % QFIELD, b[1])
    r = p
    f = (1, 0)
    for bit in bin(N)[3:]:
        line, r = miller_line_and_sum(r, r, distorted)
        f = f2_mul(f2_sq(f), line)
        if bit == "1":
            assert r is not None
            line, r = miller_line_and_sum(r, p, distorted)
            f = f2_mul(f, line)
    assert r is None
    return f2_pow(f, (QFIELD * QFIELD - 1) // N)


def expand_bits(domain: bytes, message: bytes, nbits: int) -> int:
    nbytes = (nbits + 7) // 8
    raw = hashlib.shake_256(domain + len(message).to_bytes(8, "big") + message).digest(nbytes)
    value = int.from_bytes(raw, "big")
    return value >> (8 * nbytes - nbits)


def scalar_hash(message: bytes) -> int:
    # Concrete instantiation of the paper's abstract h:{0,1}*->{0,...,n-1}.
    return expand_bits(b"PR-v2/h/", message, N.bit_length()) % N


def map_scalar(message: bytes) -> int:
    # Section 4 rejection sampler.  T_0 is the one-bit string "0" and T_i,
    # i>0, is i's minimal binary representation.
    nbits = N.bit_length()
    i = 0
    while True:
        ti = b"0" if i == 0 else bin(i)[2:].encode("ascii")
        nbytes = (nbits + 7) // 8
        # Preserve the paper's m||T_i order.  The fixed prefix only separates
        # this KDF from the distinct scalar hash interface.
        raw = hashlib.shake_256(b"PR-v2/H/" + message + ti).digest(nbytes)
        kappa = int.from_bytes(raw, "big") >> (8 * nbytes - nbits)
        if kappa < N:
            return kappa
        i += 1


def encode_point(p: Point) -> tuple[int, int]:
    if p is None:
        raise ValueError("the paper's (x,b) format cannot encode infinity")
    return p[0], p[1] & 1


def decode_point(encoded: tuple[int, int]) -> Point:
    x, b = encoded
    if not (0 <= x < QFIELD and b in (0, 1)):
        return None
    rhs = (pow(x, 3, QFIELD) + x) % QFIELD
    y = pow(rhs, (QFIELD + 1) // 4, QFIELD)
    if y * y % QFIELD != rhs:
        return None
    if (y & 1) != b:
        y = QFIELD - y
    return x, y


@dataclass(frozen=True)
class Signature:
    s: int
    x: int
    b: int

    @classmethod
    def from_point(cls, s: int, point: Point) -> "Signature":
        x, b = encode_point(point)
        return cls(s, x, b)

    def point(self) -> Point:
        return decode_point((self.x, self.b))


def sign(message: bytes, k: int | None = None) -> Signature:
    # The paper says choose positive k,l with k+l=a.  This samples exactly
    # that advertised domain; the optional k is only for reproducible tests.
    if k is None:
        k = secrets.randbelow(A - 2) + 1
    if not (1 <= k <= A - 2):
        raise ValueError("k outside the paper's positive split domain")
    ell = A - k
    h = scalar_hash(message)
    kappa = map_scalar(message)
    H = ec_mul(kappa, PUBLIC_Q)
    S = ec_mul(pow(G, ell, N), H)
    return Signature.from_point((k + h + N) % PHI, S)


def verify(message: bytes, sig: Signature) -> bool:
    # phi(n) is secret; s<n is the strongest simple public range check and
    # contains every honest s because phi(n)<n.
    if not (0 <= sig.s < N):
        return False
    S = sig.point()
    if S is None or ec_mul(N, S) is not None:
        return False
    h = scalar_hash(message)
    H = ec_mul(map_scalar(message), PUBLIC_Q)
    left = modified_tate(ec_mul(pow(G, sig.s, N), BASE_P), S)
    right = modified_tate(ec_mul(pow(G, h + N, N), PUBLIC_Q), H)
    return left == right


def forge_one_query(source: bytes, target: bytes, sig: Signature) -> Signature:
    """Transform one ordinary source signature into a target signature."""
    k0 = map_scalar(source)
    k1 = map_scalar(target)
    if math.gcd(k0, N) != 1:
        # This event is negligible; it also directly factors n.
        raise ValueError("source map scalar is not invertible modulo n")
    delta = scalar_hash(target) - scalar_hash(source)
    if delta >= 0:
        gd = pow(G, delta, N)
    else:
        gd = pow(pow(G, -1, N), -delta, N)
    rho = k1 * pow(k0, -1, N) % N
    rho = rho * gd % N
    forged_point = ec_mul(rho, sig.point())
    return Signature.from_point(sig.s, forged_point)


def main() -> None:
    global BASE_P, PUBLIC_Q
    started = time.monotonic()
    repaired_y = pow((pow(PRINTED_XP, 3, QFIELD) + PRINTED_XP) % QFIELD, (QFIELD + 1) // 4, QFIELD)
    printed_p_candidate = (PRINTED_XP, repaired_y)
    # The repaired printed P has order 2n, with nP=(0,0).  Doubling gives a
    # point of the intended exact order n.  The published Q is consistent with
    # the repaired order-2n point, so double it as well.
    BASE_P = ec_mul(2, printed_p_candidate)
    PUBLIC_Q = ec_mul(pow(G, A, N), BASE_P)

    checks = {
        "p1_bits": P1.bit_length(),
        "p2_bits": P2.bit_length(),
        "n_bits": N.bit_length(),
        "q_bits": QFIELD.bit_length(),
        "q_equals_4n_minus_1": QFIELD == 4 * N - 1,
        "printed_y_on_curve": ec_on_curve((PRINTED_XP, PRINTED_YP)),
        "repaired_y_decimal_digits": len(str(repaired_y)),
        "printed_y_extra_digit_index_zero_based": 587,
        "repaired_printed_P_on_curve": ec_on_curve(printed_p_candidate),
        "n_times_repaired_printed_P": ec_mul(N, printed_p_candidate),
        "two_n_times_repaired_printed_P_is_infinity": ec_mul(2 * N, printed_p_candidate) is None,
        "printed_Q_on_curve": ec_on_curve(PRINTED_Q),
        "printed_Q_matches_ga_times_repaired_printed_P": ec_mul(pow(G, A, N), printed_p_candidate) == PRINTED_Q,
        "n_times_printed_Q": ec_mul(N, PRINTED_Q),
        "two_n_times_printed_Q_is_infinity": ec_mul(2 * N, PRINTED_Q) is None,
        "corrected_P_has_order_n": ec_mul(N, BASE_P) is None,
        "corrected_Q_matches_gaP": ec_mul(pow(G, A, N), BASE_P) == PUBLIC_Q,
        "corrected_Q_has_order_n": ec_mul(N, PUBLIC_Q) is None,
    }
    # Pairing sanity: nontrivial and bilinear on independent small scalars.
    pairing = modified_tate(BASE_P, BASE_P)
    pairing_checks = {
        "e_not_one": pairing != (1, 0),
        "e_to_n_is_one": f2_pow(pairing, N) == (1, 0),
        "e_to_n_over_p1_not_one": f2_pow(pairing, N // P1) != (1, 0),
        "e_to_n_over_p2_not_one": f2_pow(pairing, N // P2) != (1, 0),
        "bilinear_3_5": modified_tate(ec_mul(3, BASE_P), ec_mul(5, BASE_P)) == f2_pow(pairing, 15),
    }

    source = b"authorized one-query source message"
    target = b"fresh target message never submitted to the signer"
    unrelated = b"unrelated control message"
    # Fixed random tape for a stable transcript; the attack does not use it.
    honest = sign(source, k=123456789012345678901234567890123456789)
    honest_ok = verify(source, honest)
    target_rejects_source = not verify(target, honest)
    forged = forge_one_query(source, target, honest)
    forged_ok = verify(target, forged)
    unrelated_rejects_forgery = not verify(unrelated, forged)
    altered_s = Signature((forged.s + 1) % N, forged.x, forged.b)
    altered_s_rejected = not verify(target, altered_s)
    kappa0 = map_scalar(source)
    kappa1 = map_scalar(target)
    h0 = scalar_hash(source)
    h1 = scalar_hash(target)
    delta = h1 - h0
    gd = pow(G, delta, N) if delta >= 0 else pow(pow(G, -1, N), -delta, N)
    rho = kappa1 * pow(kappa0, -1, N) % N * gd % N

    result = {
        "scheme": "Poulakis--Rolland v2 / ePrint 2012/134 / 20150430:055329",
        "hash_instantiation": "SHAKE256 with explicit local domain separation; paper leaves h/KDF concrete choice open",
        "section4_generator": "the corrected public-key Q, matching Section 4's named generator Q",
        "parameters": {"n": str(N), "q": str(QFIELD), "g": G, "a": str(A)},
        "parameter_checks": checks,
        "pairing_checks": pairing_checks,
        "messages": {
            "source_hex": source.hex(),
            "target_hex": target.hex(),
            "unrelated_hex": unrelated.hex(),
        },
        "attack_public_values": {
            "h_source": str(h0),
            "h_target": str(h1),
            "kappa_source": str(kappa0),
            "kappa_target": str(kappa1),
            "gcd_kappa_source_n": math.gcd(kappa0, N),
            "rho": str(rho),
        },
        "source_signature": {"s": str(honest.s), "x": str(honest.x), "b": honest.b},
        "forged_signature": {"s": str(forged.s), "x": str(forged.x), "b": forged.b},
        "attack_checks": {
            "one_signing_query": True,
            "target_was_not_signed": True,
            "same_s_as_source": forged.s == honest.s,
            "forged_point_differs": (forged.x, forged.b) != (honest.x, honest.b),
            "honest_signature_accepts": honest_ok,
            "source_signature_rejected_on_target": target_rejects_source,
            "forgery_accepts_on_fresh_target": forged_ok,
            "forgery_rejected_on_unrelated_message": unrelated_rejects_forgery,
            "altered_s_rejected": altered_s_rejected,
        },
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    expected_checks = [
        checks["q_equals_4n_minus_1"],
        not checks["printed_y_on_curve"],
        checks["repaired_printed_P_on_curve"],
        checks["two_n_times_repaired_printed_P_is_infinity"],
        checks["printed_Q_on_curve"],
        checks["printed_Q_matches_ga_times_repaired_printed_P"],
        checks["two_n_times_printed_Q_is_infinity"],
        checks["corrected_P_has_order_n"],
        checks["corrected_Q_matches_gaP"],
        checks["corrected_Q_has_order_n"],
        *pairing_checks.values(),
        *result["attack_checks"].values(),
    ]
    if not all(expected_checks):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
