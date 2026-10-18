#!/usr/bin/env python3
"""Deterministic paper-level reproducer for the FABS KP-ABS verifier.

This is a typed-group/exponent model of Figure 1.  It does not import or
execute the unpinned Charm implementation.  Multiplicative group elements are
represented by their exponents in prime-order cyclic groups; the pairing maps
exponents (a,b) to a*b.  No attack routine receives or inspects a secret.  The
two minimal forgeries do not use the public value X; the strengthened public-
witness variant deliberately uses public X to make its Z commitment
nonidentity.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Iterable, Sequence


# Standard BN254 scalar-field/group order, pinned explicitly for this model.
BN254_SCALAR_ORDER = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


def _mod(x: int) -> int:
    return x % BN254_SCALAR_ORDER


@dataclass(frozen=True)
class Element:
    """Element of a named multiplicative prime-order group, stored as exponent."""

    group: str
    exponent: int

    def __post_init__(self) -> None:
        if self.group not in ("G1", "G2", "GT"):
            raise ValueError(f"unknown group {self.group!r}")
        object.__setattr__(self, "exponent", _mod(self.exponent))

    def __mul__(self, other: "Element") -> "Element":
        if not isinstance(other, Element) or self.group != other.group:
            raise TypeError("group multiplication requires equal element types")
        return Element(self.group, self.exponent + other.exponent)

    def __truediv__(self, other: "Element") -> "Element":
        if not isinstance(other, Element) or self.group != other.group:
            raise TypeError("group division requires equal element types")
        return Element(self.group, self.exponent - other.exponent)

    def __pow__(self, scalar: int) -> "Element":
        if not isinstance(scalar, int):
            raise TypeError("group exponent must be an integer scalar")
        return Element(self.group, self.exponent * scalar)

    @property
    def is_identity(self) -> bool:
        return self.exponent == 0

    def encoded(self) -> bytes:
        tag = self.group.encode("ascii")
        return len(tag).to_bytes(1, "big") + tag + self.exponent.to_bytes(32, "big")


G1_ID = Element("G1", 0)
G2_ID = Element("G2", 0)
GT_ID = Element("GT", 0)
G1_GENERATOR = Element("G1", 1)
G2_GENERATOR = Element("G2", 1)


def pairing(a: Element, b: Element) -> Element:
    if a.group != "G1" or b.group != "G2":
        raise TypeError("pairing requires G1 x G2")
    return Element("GT", a.exponent * b.exponent)


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


class TypedRandomOracles:
    """Deterministic typed instantiation with explicit query accounting."""

    def __init__(self) -> None:
        self.h0_queries = 0
        self.h1_queries = 0

    def h0(
        self,
        A: Element,
        B: Element,
        C: Element,
        Y: Element,
        Z: Element,
        W: Element,
        message: bytes,
    ) -> int:
        expected = ("G1", "G1", "G2", "GT", "GT", "G1")
        actual = (A.group, B.group, C.group, Y.group, Z.group, W.group)
        if actual != expected:
            raise TypeError(f"wrong H0 tuple types: {actual!r}")
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        self.h0_queries += 1
        transcript = b"FABS-H0-TYPED-V1"
        for component in (A, B, C, Y, Z, W):
            transcript += _lp(component.encoded())
        transcript += _lp(message)
        return int.from_bytes(hashlib.sha256(transcript).digest(), "big") % BN254_SCALAR_ORDER

    def h1(self, attribute: str) -> Element:
        if not isinstance(attribute, str):
            raise TypeError("attribute must be a string")
        self.h1_queries += 1
        raw = attribute.encode("utf-8")
        digest = hashlib.sha256(b"FABS-H1-TYPED-V1" + _lp(raw)).digest()
        return Element("G1", int.from_bytes(digest, "big"))


@dataclass(frozen=True)
class PublicKey:
    g1: Element
    g2: Element
    X: Element


@dataclass(frozen=True)
class AllAndSecretKey:
    sk1: Element
    sk2: tuple[Element, ...]


@dataclass(frozen=True)
class Signature:
    A: Element
    B: Element
    C: Element
    c: int
    s_alpha: int
    s_k: int
    s_i: tuple[int, ...]

    def normalized(self) -> "Signature":
        return replace(
            self,
            c=_mod(self.c),
            s_alpha=_mod(self.s_alpha),
            s_k=_mod(self.s_k),
            s_i=tuple(_mod(x) for x in self.s_i),
        )


def verify(
    public_key: PublicKey,
    signature: Signature,
    attributes: Sequence[str],
    message: bytes,
    oracles: TypedRandomOracles,
) -> bool:
    """Literal typed mathematical verifier from Figure 1."""

    signature = signature.normalized()
    if public_key.g1.group != "G1" or public_key.g2.group != "G2" or public_key.X.group != "GT":
        return False
    if signature.A.group != "G1" or signature.B.group != "G1" or signature.C.group != "G2":
        return False
    if len(signature.s_i) != len(attributes):
        return False

    Y = pairing(signature.A, public_key.g2) / pairing(signature.B, signature.C)
    Z = (public_key.X ** signature.s_alpha) * (Y ** signature.c)
    W = public_key.g1 ** signature.s_k
    for attribute, response in zip(attributes, signature.s_i):
        W = W * (oracles.h1(attribute) ** response)
    W = W * (signature.B ** signature.c)
    c_prime = oracles.h0(signature.A, signature.B, signature.C, Y, Z, W, message)
    return c_prime == signature.c


def _derive_scalar(label: str, *, nonzero: bool = False) -> int:
    value = int.from_bytes(hashlib.sha256(b"FABS-REPRODUCER-V1:" + label.encode()).digest(), "big")
    value %= BN254_SCALAR_ORDER
    if nonzero and value == 0:
        return 1
    return value


def setup() -> tuple[PublicKey, int]:
    alpha = _derive_scalar("setup-alpha", nonzero=True)
    return PublicKey(G1_GENERATOR, G2_GENERATOR, pairing(G1_GENERATOR, G2_GENERATOR) ** alpha), alpha


def _all_and_rows(n: int) -> list[list[int]]:
    """MSP rows whose all-one reconstruction coefficients give (1,0,...,0)."""

    if n <= 0:
        raise ValueError("an all-AND policy requires at least one attribute")
    if n == 1:
        return [[1]]
    rows: list[list[int]] = []
    first = [0] * n
    first[0], first[1] = 1, 1
    rows.append(first)
    for i in range(1, n - 1):
        row = [0] * n
        row[i], row[i + 1] = -1, 1
        rows.append(row)
    last = [0] * n
    last[n - 1] = -1
    rows.append(last)
    assert [sum(row[j] for row in rows) for j in range(n)] == [1] + [0] * (n - 1)
    return rows


def keygen_all_and(
    alpha: int,
    attributes: Sequence[str],
    oracles: TypedRandomOracles,
) -> AllAndSecretKey:
    rows = _all_and_rows(len(attributes))
    r = _derive_scalar(f"key-r-{len(attributes)}", nonzero=True)
    sharing_vector = [_mod(alpha + r)] + [
        _derive_scalar(f"key-v-{len(attributes)}-{j}") for j in range(1, len(attributes))
    ]
    components: list[Element] = []
    for row, attribute in zip(rows, attributes):
        share = sum(a * b for a, b in zip(row, sharing_vector))
        components.append((G1_GENERATOR ** share) * (oracles.h1(attribute) ** r))
    return AllAndSecretKey(G2_GENERATOR ** r, tuple(components))


def honest_sign_all_and(
    public_key: PublicKey,
    secret_key: AllAndSecretKey,
    attributes: Sequence[str],
    message: bytes,
    oracles: TypedRandomOracles,
) -> Signature:
    if len(secret_key.sk2) != len(attributes):
        raise ValueError("secret key and attribute list disagree")
    n = len(attributes)
    k = _derive_scalar(f"sign-k-{n}", nonzero=True)
    t = _derive_scalar(f"sign-t-{n}", nonzero=True)
    r_alpha = _derive_scalar(f"sign-r-alpha-{n}")
    r_k = _derive_scalar(f"sign-r-k-{n}")
    r_i = [_derive_scalar(f"sign-r-i-{n}-{i}") for i in range(n)]

    # For the chosen all-AND MSP, every reconstruction coefficient gamma_i is 1.
    A = G1_ID
    B = public_key.g1 ** k
    for component, attribute in zip(secret_key.sk2, attributes):
        A = A * (component ** (k * t))
        B = B * (oracles.h1(attribute) ** k)
    C = secret_key.sk1 ** t
    Y = public_key.X ** (k * t)
    Z = public_key.X ** r_alpha
    W = public_key.g1 ** r_k
    for attribute, response_randomness in zip(attributes, r_i):
        W = W * (oracles.h1(attribute) ** response_randomness)
    c = oracles.h0(A, B, C, Y, Z, W, message)
    return Signature(
        A=A,
        B=B,
        C=C,
        c=c,
        s_alpha=r_alpha - k * t * c,
        s_k=r_k - k * c,
        s_i=tuple(response_randomness - k * c for response_randomness in r_i),
    ).normalized()


def forge_all_identity(
    attributes: Sequence[str], message: bytes, oracles: TypedRandomOracles
) -> Signature:
    """One-H0-query universal forgery with beta=k=delta_i=r_i=0."""

    # Y'=1, Z'=1, and W'=1 for every resulting challenge c.
    c = oracles.h0(G1_ID, G1_ID, G2_ID, GT_ID, GT_ID, G1_ID, message)
    return Signature(G1_ID, G1_ID, G2_ID, c, 0, 0, (0,) * len(attributes))


def forge_nonidentity(
    attributes: Sequence[str], message: bytes, oracles: TypedRandomOracles
) -> Signature:
    """Nonidentity variant: A=B=g1, C=g2, beta=0, k=1, delta_i=0.

    Here Y'=e(g1,g2)/e(g1,g2)=1.  Take r_alpha=0 and public r_k=rho.
    With s_alpha=0, s_k=rho-c, and s_i=0, verification reconstructs
    Z'=1 and W'=g1^rho.
    """

    rho = _derive_scalar("nonidentity-r-k", nonzero=True)
    W = G1_GENERATOR ** rho
    c = oracles.h0(
        G1_GENERATOR,
        G1_GENERATOR,
        G2_GENERATOR,
        GT_ID,
        GT_ID,
        W,
        message,
    )
    return Signature(
        G1_GENERATOR,
        G1_GENERATOR,
        G2_GENERATOR,
        c,
        0,
        rho - c,
        (0,) * len(attributes),
    ).normalized()


def forge_nonidentity_nonzero_commitments(
    public_key: PublicKey,
    attributes: Sequence[str],
    message: bytes,
    oracles: TypedRandomOracles,
) -> Signature:
    """Strengthened public-witness transcript with nonzero commitments.

    Keep A=B=g1, C=g2, beta=0, k=1, and delta_i=0, but take
    r_alpha=1, nonzero public r_k, and deterministic nonzero r_i.  Therefore
    Z=X and W=g1^r_k product H1(attribute_i)^r_i.  Responses are
    s_alpha=1, s_k=r_k-c, and s_i=r_i.  This costs one H0 query and one H1
    query per attribute, but still no key/signing query, secret, or pairing.
    """

    r_alpha = 1
    r_k = _derive_scalar("strengthened-nonidentity-r-k", nonzero=True)
    r_i = tuple(
        _derive_scalar(f"strengthened-nonidentity-r-i-{i}-{attribute}", nonzero=True)
        for i, attribute in enumerate(attributes)
    )
    Z = public_key.X ** r_alpha
    W = public_key.g1 ** r_k
    for attribute, response_randomness in zip(attributes, r_i):
        W = W * (oracles.h1(attribute) ** response_randomness)
    c = oracles.h0(
        G1_GENERATOR,
        G1_GENERATOR,
        G2_GENERATOR,
        GT_ID,
        Z,
        W,
        message,
    )
    return Signature(
        G1_GENERATOR,
        G1_GENERATOR,
        G2_GENERATOR,
        c,
        r_alpha,
        r_k - c,
        r_i,
    ).normalized()


def _attrs(n: int, prefix: str = "reference-attribute") -> tuple[str, ...]:
    return tuple(f"{prefix}-{i:03d}" for i in range(n))


def _assert_reject(name: str, condition: bool, results: dict[str, bool]) -> None:
    results[name] = condition
    if condition:
        raise AssertionError(f"negative control unexpectedly accepted: {name}")


def run() -> dict[str, object]:
    oracles = TypedRandomOracles()
    public_key, alpha = setup()

    honest_controls: dict[str, bool] = {}
    for n in (1, 3, 100):
        attributes = _attrs(n)
        secret_key = keygen_all_and(alpha, attributes, oracles)
        signature = honest_sign_all_and(
            public_key, secret_key, attributes, f"honest-control-{n}".encode(), oracles
        )
        accepted = verify(
            public_key, signature, attributes, f"honest-control-{n}".encode(), oracles
        )
        honest_controls[f"all_and_{n}"] = accepted
        if not accepted:
            raise AssertionError(f"honest all-AND control failed for n={n}")

    universal_message = b"attacker-chosen-fresh-message-for-all-sets"
    attack_runs: dict[str, dict[str, object]] = {}
    challenges: dict[str, list[int]] = {"all_identity": [], "nonidentity": []}
    for variant, forge in (
        ("all_identity", forge_all_identity),
        ("nonidentity", forge_nonidentity),
    ):
        for n in (0, 1, 3, 100):
            attributes = _attrs(n)
            h0_before, h1_before = oracles.h0_queries, oracles.h1_queries
            signature = forge(attributes, universal_message, oracles)
            forge_h0 = oracles.h0_queries - h0_before
            forge_h1 = oracles.h1_queries - h1_before
            accepted = verify(public_key, signature, attributes, universal_message, oracles)
            if not accepted:
                raise AssertionError(f"{variant} forgery failed for n={n}")
            if forge_h0 != 1 or forge_h1 != 0:
                raise AssertionError("forger query accounting changed")
            key = f"{variant}_attributes_{n}"
            attack_runs[key] = {
                "accepted": accepted,
                "forger_h0_queries": forge_h0,
                "forger_h1_queries": forge_h1,
                "key_queries": 0,
                "signing_queries": 0,
                "challenge": str(signature.c),
                "A_exponent": str(signature.A.exponent),
                "B_exponent": str(signature.B.exponent),
                "C_exponent": str(signature.C.exponent),
                "A_identity": signature.A.is_identity,
                "B_identity": signature.B.is_identity,
                "C_identity": signature.C.is_identity,
                "s_alpha": str(signature.s_alpha),
                "s_k": str(signature.s_k),
                "s_i_count": len(signature.s_i),
                "s_i_all_zero": all(response == 0 for response in signature.s_i),
            }
            challenges[variant].append(signature.c)
        if len(set(challenges[variant])) != 1:
            raise AssertionError("challenge unexpectedly depends on the attribute set")

    for n in (0, 1, 3, 100):
        attributes = _attrs(n)
        h0_before, h1_before = oracles.h0_queries, oracles.h1_queries
        signature = forge_nonidentity_nonzero_commitments(
            public_key, attributes, universal_message, oracles
        )
        forge_h0 = oracles.h0_queries - h0_before
        forge_h1 = oracles.h1_queries - h1_before
        accepted = verify(public_key, signature, attributes, universal_message, oracles)
        if not accepted:
            raise AssertionError(
                f"strengthened nonidentity forgery failed for n={n}"
            )
        if forge_h0 != 1 or forge_h1 != n:
            raise AssertionError("strengthened forger query accounting changed")
        key = f"strengthened_nonidentity_attributes_{n}"
        attack_runs[key] = {
            "accepted": accepted,
            "forger_h0_queries": forge_h0,
            "forger_h1_queries": forge_h1,
            "key_queries": 0,
            "signing_queries": 0,
            "challenge": str(signature.c),
            "A_exponent": str(signature.A.exponent),
            "B_exponent": str(signature.B.exponent),
            "C_exponent": str(signature.C.exponent),
            "A_identity": signature.A.is_identity,
            "B_identity": signature.B.is_identity,
            "C_identity": signature.C.is_identity,
            "s_alpha": str(signature.s_alpha),
            "s_k": str(signature.s_k),
            "s_i_count": len(signature.s_i),
            "s_i_all_nonzero": all(response != 0 for response in signature.s_i),
        }

    # Same nonidentity signature and response vector accepts after every attribute
    # name is changed: the attributes disappear because every s_i is zero.
    attrs_100 = _attrs(100)
    alt_attrs_100 = _attrs(100, prefix="different-attribute")
    portable = forge_nonidentity(attrs_100, universal_message, oracles)
    portability_accepts = verify(
        public_key, portable, alt_attrs_100, universal_message, oracles
    )
    if not portability_accepts:
        raise AssertionError("zero-response attribute-set portability failed")

    # A fresh signature is constructed for each fresh message using exactly one
    # H0 query.  Holding a completed signature fixed while changing its message
    # is a negative control and must reject.
    fresh_message_controls: dict[str, bool] = {}
    for i in range(4):
        msg = f"independent-fresh-message-{i}".encode()
        before = oracles.h0_queries
        sig = forge_all_identity(attrs_100, msg, oracles)
        if oracles.h0_queries - before != 1:
            raise AssertionError("fresh-message forgery used more than one H0 query")
        accepted = verify(public_key, sig, attrs_100, msg, oracles)
        fresh_message_controls[msg.decode()] = accepted
        if not accepted:
            raise AssertionError("fresh-message universal forgery failed")

    negatives: dict[str, bool] = {}
    base = forge_nonidentity(attrs_100, b"negative-control-base", oracles)
    _assert_reject(
        "held_signature_changed_message",
        verify(public_key, base, attrs_100, b"negative-control-base-changed", oracles),
        negatives,
    )
    _assert_reject(
        "challenge_plus_one",
        verify(public_key, replace(base, c=base.c + 1), attrs_100, b"negative-control-base", oracles),
        negatives,
    )
    _assert_reject(
        "A_times_generator",
        verify(
            public_key,
            replace(base, A=base.A * G1_GENERATOR),
            attrs_100,
            b"negative-control-base",
            oracles,
        ),
        negatives,
    )
    _assert_reject(
        "B_times_generator",
        verify(
            public_key,
            replace(base, B=base.B * G1_GENERATOR),
            attrs_100,
            b"negative-control-base",
            oracles,
        ),
        negatives,
    )
    _assert_reject(
        "C_times_generator",
        verify(
            public_key,
            replace(base, C=base.C * G2_GENERATOR),
            attrs_100,
            b"negative-control-base",
            oracles,
        ),
        negatives,
    )
    _assert_reject(
        "s_alpha_plus_one",
        verify(
            public_key,
            replace(base, s_alpha=base.s_alpha + 1),
            attrs_100,
            b"negative-control-base",
            oracles,
        ),
        negatives,
    )
    _assert_reject(
        "s_k_plus_one",
        verify(
            public_key,
            replace(base, s_k=base.s_k + 1),
            attrs_100,
            b"negative-control-base",
            oracles,
        ),
        negatives,
    )
    changed_responses = list(base.s_i)
    changed_responses[0] += 1
    _assert_reject(
        "first_attribute_response_plus_one",
        verify(
            public_key,
            replace(base, s_i=tuple(changed_responses)),
            attrs_100,
            b"negative-control-base",
            oracles,
        ),
        negatives,
    )

    # Verify the advertised internal cancellations directly for the exact
    # 100-attribute reference forgery.
    Y = pairing(portable.A, public_key.g2) / pairing(portable.B, portable.C)
    Z = (public_key.X ** portable.s_alpha) * (Y ** portable.c)
    W = public_key.g1 ** portable.s_k
    for attribute, response in zip(attrs_100, portable.s_i):
        W = W * (oracles.h1(attribute) ** response)
    W = W * (portable.B ** portable.c)
    expected_rho = _derive_scalar("nonidentity-r-k", nonzero=True)
    if not (Y.is_identity and Z.is_identity and W == G1_GENERATOR ** expected_rho):
        raise AssertionError("nonidentity cancellation invariant failed")

    strengthened = forge_nonidentity_nonzero_commitments(
        public_key, attrs_100, universal_message, oracles
    )
    strengthened_Y = pairing(strengthened.A, public_key.g2) / pairing(
        strengthened.B, strengthened.C
    )
    strengthened_Z = (public_key.X ** strengthened.s_alpha) * (
        strengthened_Y ** strengthened.c
    )
    strengthened_W = public_key.g1 ** strengthened.s_k
    for attribute, response in zip(attrs_100, strengthened.s_i):
        strengthened_W = strengthened_W * (oracles.h1(attribute) ** response)
    strengthened_W = strengthened_W * (strengthened.B ** strengthened.c)
    if not (
        strengthened_Y.is_identity
        and strengthened_Z == public_key.X
        and not strengthened_Z.is_identity
        and not strengthened_W.is_identity
        and all(response != 0 for response in strengthened.s_i)
    ):
        raise AssertionError("strengthened nonidentity invariant failed")

    return {
        "schema_version": 1,
        "profile_id": "FABS-2026-022-KPABS-BN254-MSP-EUFCMA-PAPER-v1",
        "verifier": "literal Figure 1 typed mathematical verifier",
        "model": "prime-order typed exponent model with bilinear pairing",
        "bn254_scalar_order_decimal": str(BN254_SCALAR_ORDER),
        "bn254_scalar_order_hex": hex(BN254_SCALAR_ORDER),
        "attack_result": "PASS_UNIVERSAL_ZERO_QUERY_FRESH_MESSAGE_FORGERY",
        "honest_controls": honest_controls,
        "attack_runs": attack_runs,
        "attribute_independence": {
            "one_challenge_for_sizes_0_1_3_100_all_identity": True,
            "one_challenge_for_sizes_0_1_3_100_nonidentity": True,
            "same_nonidentity_signature_accepts_100_changed_attribute_names": portability_accepts,
        },
        "fresh_message_controls": fresh_message_controls,
        "negative_controls_acceptance": negatives,
        "reference_case": {
            "policy": "100-input all-AND MSP with 100 distinct attributes",
            "all_identity_accepted": attack_runs["all_identity_attributes_100"]["accepted"],
            "nonidentity_accepted": attack_runs["nonidentity_attributes_100"]["accepted"],
            "nonidentity_components": "A=g1, B=g1, C=g2",
            "nonidentity_witness_description": "beta=0,k=1,delta_i=0,r_alpha=0,r_k=rho,r_i=0",
            "nonidentity_Y_identity": Y.is_identity,
            "nonidentity_Z_identity": Z.is_identity,
            "nonidentity_W_exponent": str(W.exponent),
            "strengthened_nonidentity_accepted": attack_runs[
                "strengthened_nonidentity_attributes_100"
            ]["accepted"],
            "strengthened_nonidentity_witness_description": (
                "beta=0,k=1,delta_i=0,r_alpha=1,r_k nonzero,r_i nonzero"
            ),
            "strengthened_Y_identity": strengthened_Y.is_identity,
            "strengthened_Z_equals_X": strengthened_Z == public_key.X,
            "strengthened_Z_identity": strengthened_Z.is_identity,
            "strengthened_W_identity": strengthened_W.is_identity,
            "strengthened_all_s_i_nonzero": all(
                response != 0 for response in strengthened.s_i
            ),
        },
        "adversary_resources_per_forgery": {
            "key_generation_queries": 0,
            "signing_queries": 0,
            "H0_queries": 1,
            "H1_queries": 0,
            "secret_values_used": 0,
            "pairings_by_forger": 0,
            "work": "O(number of attributes) zero responses plus one H0 evaluation",
        },
        "strengthened_adversary_resources_per_forgery": {
            "key_generation_queries": 0,
            "signing_queries": 0,
            "H0_queries": 1,
            "H1_queries": "number of attributes",
            "secret_values_used": 0,
            "pairings_by_forger": 0,
            "work": "O(number of attributes) group operations/H1 evaluations plus one H0 evaluation",
        },
        "target_source_executed": False,
        "external_dependencies": [],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
