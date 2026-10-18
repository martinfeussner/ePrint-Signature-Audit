"""Deterministic prime-order reference model for the CUBE proof verifier."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


# Scalar-field order used by the BN254 profile.  Group elements are represented
# by their generator coefficient.  The public actual-BN254 reproducer separately
# executes the same equations with Arkworks group and pairing operations.
ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617


@dataclass(frozen=True)
class Proof:
    a_bar: int
    b_bar: int
    u: int
    s: int
    t: int
    u_gamma: int


@dataclass(frozen=True)
class Instance:
    x_public: int
    bases: tuple[int, ...]
    h_gamma: int
    messages: tuple[int, ...]
    context: bytes


def mod(value: int) -> int:
    return value % ORDER


def make_instance(message_count: int, offset: int, context_byte: int) -> tuple[Instance, int, int]:
    signing_key = mod(37 + offset)
    hidden_message = mod(71 + offset)
    bases = tuple(mod(101 + offset + 17 * index) for index in range(message_count))
    messages = tuple(mod(1009 + offset + 29 * index) for index in range(message_count))
    context = b"LetsVerify" + bytes(21) + bytes([context_byte])
    return (
        Instance(signing_key, bases, mod(809 + offset), messages, context),
        signing_key,
        hidden_message,
    )


def commitment(instance: Instance) -> int:
    return mod(1 + sum(base * message for base, message in zip(instance.bases, instance.messages)))


def challenge(instance: Instance, proof: Proof) -> int:
    payload = bytearray(instance.context)
    for value in (*instance.messages, proof.a_bar, proof.b_bar, proof.u):
        payload.extend(mod(value).to_bytes(32, "big"))
    return int.from_bytes(hashlib.sha3_256(payload).digest(), "big") % ORDER


def honest_proof(instance: Instance, signing_key: int, hidden_message: int) -> Proof:
    e, r, alpha, beta, delta = 43, 47, 53, 59, 61
    denominator_inverse = pow(mod(signing_key + e), -1, ORDER)
    signature_a = mod((commitment(instance) + instance.h_gamma * hidden_message) * denominator_inverse)
    a_bar = mod(signature_a * r)
    b_bar = mod((commitment(instance) + instance.h_gamma * hidden_message) * r - a_bar * e)
    u = mod(commitment(instance) * alpha + a_bar * beta + instance.h_gamma * delta)
    provisional = Proof(a_bar, b_bar, u, 0, 0, 0)
    c = challenge(instance, provisional)
    return Proof(
        a_bar,
        b_bar,
        u,
        mod(alpha + r * c),
        mod(beta - e * c),
        mod(delta + r * hidden_message * c),
    )


def verify(instance: Instance, proof: Proof) -> bool:
    # In the reference coordinate model, e(a*G1,b*G2) has exponent a*b.
    if mod(proof.a_bar * instance.x_public) != mod(proof.b_bar):
        return False
    c = challenge(instance, proof)
    left = mod(proof.u + c * proof.b_bar)
    right = mod(
        proof.s * commitment(instance)
        + proof.t * proof.a_bar
        + proof.u_gamma * instance.h_gamma
    )
    return left == right


def zero_proof() -> Proof:
    return Proof(0, 0, 0, 0, 0, 0)


def run_profile(message_count: int, offset: int, context_byte: int, label: str) -> dict[str, object]:
    instance, signing_key, hidden_message = make_instance(message_count, offset, context_byte)
    honest = honest_proof(instance, signing_key, hidden_message)
    candidate = zero_proof()

    changed_messages = Instance(
        instance.x_public,
        instance.bases,
        instance.h_gamma,
        tuple(mod(value + 1 + index) for index, value in enumerate(instance.messages)),
        instance.context,
    )
    changed_context = Instance(
        instance.x_public,
        instance.bases,
        instance.h_gamma,
        instance.messages,
        instance.context[:-2] + b"\xa5" + instance.context[-1:],
    )
    changed_honest_message = Instance(
        instance.x_public,
        instance.bases,
        instance.h_gamma,
        (mod(instance.messages[0] + 1), *instance.messages[1:]),
        instance.context,
    )

    checks = {
        "candidate accepts": verify(instance, candidate),
        "candidate accepts changed context": verify(changed_context, candidate),
        "candidate accepts changed messages": verify(changed_messages, candidate),
        "honest proof accepts": verify(instance, honest),
        "honest proof rejects changed message": not verify(changed_honest_message, honest),
        "identity A mutation rejects": not verify(instance, Proof(1, 0, 0, 0, 0, 0)),
        "identity B mutation rejects": not verify(instance, Proof(0, 1, 0, 0, 0, 0)),
        "identity U mutation rejects": not verify(instance, Proof(0, 0, 1, 0, 0, 0)),
        "zero-response s mutation rejects": not verify(instance, Proof(0, 0, 0, 1, 0, 0)),
        "zero signing queries": True,
    }
    return {
        "all_expected_checks_pass": all(checks.values()),
        "checks": checks,
        "message_count": message_count,
        "parameter_row": label,
    }


def quick_report() -> dict[str, object]:
    row = run_profile(5, 0, 0, "CUBE-BN254-SOURCE-FIVE-WORD")
    return {
        "attack": {"signing_queries": 0},
        "checks": row["checks"],
        "digests": {
            "fresh_attribute_vector_sha256": hashlib.sha256(
                b"CUBE ePrint 2026/920 unauthorized explicit attribute vector"
            ).hexdigest(),
            "reference_model_domain_sha256": hashlib.sha256(
                b"CUBE-PRIME-ORDER-REFERENCE-MODEL-v1"
            ).hexdigest(),
        },
        "environment": {"workers": 1},
        "model": {
            "group_order": str(ORDER),
            "kind": "prime-order pairing-group coordinate model",
            "separate_actual_bn254_reproducer": True,
        },
        "result": "PASS" if row["all_expected_checks_pass"] else "FAIL",
        "scope": "CUBE ePrint 2026/920 ordinary proof verification equations",
    }


def all_rows_report() -> dict[str, object]:
    rows = [
        run_profile(5, 0, 0, "CUBE-BN254-SOURCE-FIVE-WORD"),
        run_profile(7, 200, 1, "CUBE-BN254-PAPER-COMPLETE-SEVEN-WORD"),
    ]
    return {
        "all_rows_pass": all(row["all_expected_checks_pass"] for row in rows),
        "attack": {"signing_queries": 0},
        "results": rows,
    }
