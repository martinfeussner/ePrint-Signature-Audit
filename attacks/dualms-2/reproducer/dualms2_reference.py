#!/usr/bin/env python3
"""Paper-level DualMS 2.0 verifier and hint-slack forger.

This module is an independent publication implementation of the equations in
Section 3.2 and Table 6 of IACR ePrint 2026/1941.  The paper specifies random
oracles over bitstrings but does not specify a final tuple or wire encoding.
The deterministic, length-delimited SHAKE256 encoding below is therefore a
declared non-normative completion.  The attack does not use an encoding
collision or ambiguity: the forger calls the same Hsig interface as Verify.

Only Python's standard library is required.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import resource
import struct
import time
from dataclasses import dataclass
from decimal import Decimal, ROUND_FLOOR, getcontext
from typing import Any, Iterable


DEGREE = 256
ETA = 1
CHALLENGE_WEIGHT = 60

Poly = list[int]
Vector = list[Poly]
Matrix = list[Vector]


@dataclass(frozen=True)
class Profile:
    label: str
    signers: int
    modulus: int
    rows: int
    columns: int
    public_shift: int
    commitment_shift: int
    expected_hint_threshold: int
    expected_B_squared_floor: int
    paper_security: str

    @property
    def public_modulus(self) -> int:
        return self.modulus // (1 << self.public_shift)

    @property
    def commitment_modulus(self) -> int:
        return self.modulus // (1 << self.commitment_shift)


PROFILES = {
    "n32": Profile(
        label="DUALMS2-ROUNDED-N32-PAPER-Q2113928077-V1",
        signers=32,
        modulus=2_113_928_077,
        rows=7,
        columns=6,
        public_shift=11,
        commitment_shift=26,
        expected_hint_threshold=138_330,
        expected_B_squared_floor=622_986_612_927_114_772_561,
        paper_security="MSIS 128.0 bits; MLWE 132.6 bits",
    ),
    "n1024": Profile(
        label="DUALMS2-ROUNDED-N1024-PAPER-Q4160748533-V1",
        signers=1024,
        modulus=4_160_748_533,
        rows=10,
        columns=6,
        public_shift=11,
        commitment_shift=28,
        expected_hint_threshold=329_464_658,
        expected_B_squared_floor=23_740_430_604_846_451_426_078_443,
        paper_security="advertised rounded Table 6 n=1024 row",
    ),
}


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _frame(value: bytes) -> bytes:
    return _u64(len(value)) + value


class CounterXof:
    """Counter-expanded SHAKE256 stream from a preabsorbed transcript."""

    def __init__(self, state: Any):
        self._state = state
        self._counter = 0
        self._buffer = bytearray()

    def read(self, size: int) -> bytes:
        while len(self._buffer) < size:
            block = self._state.copy()
            block.update(_u64(self._counter))
            self._buffer.extend(block.digest(64))
            self._counter += 1
        answer = bytes(self._buffer[:size])
        del self._buffer[:size]
        return answer

    def below(self, modulus: int) -> int:
        width = max(1, (modulus.bit_length() + 7) // 8)
        ceiling = 1 << (8 * width)
        cutoff = ceiling - ceiling % modulus
        while True:
            candidate = int.from_bytes(self.read(width), "little")
            if candidate < cutoff:
                return candidate % modulus


def _oracle_state(domain: bytes, parts: Iterable[bytes]) -> Any:
    state = hashlib.shake_256()
    state.update(_frame(domain))
    for part in parts:
        state.update(_frame(part))
    return state


def _xof(domain: bytes, *parts: bytes) -> CounterXof:
    return CounterXof(_oracle_state(domain, parts))


def _sample_poly(stream: CounterXof, modulus: int) -> Poly:
    return [stream.below(modulus) for _ in range(DEGREE)]


def _sample_small_poly(stream: CounterXof) -> Poly:
    return [stream.below(3) - 1 for _ in range(DEGREE)]


def _sample_challenge_from_state(state: Any) -> Poly:
    stream = CounterXof(state)
    challenge = [0] * DEGREE
    occupied: set[int] = set()
    while len(occupied) < CHALLENGE_WEIGHT:
        position = stream.below(DEGREE)
        if position in occupied:
            continue
        occupied.add(position)
        challenge[position] = 1 if stream.below(2) else -1
    return challenge


def _sample_challenge(domain: bytes, *parts: bytes) -> Poly:
    return _sample_challenge_from_state(_oracle_state(domain, parts))


def _encode_poly(poly: Poly) -> bytes:
    if len(poly) != DEGREE:
        raise ValueError("wrong polynomial degree")
    return b"".join(_u32(value) for value in poly)


def _encode_vector(vector: Vector) -> bytes:
    return _u32(len(vector)) + b"".join(_encode_poly(poly) for poly in vector)


def _encode_rounded(vector: Vector, modulus: int, shift: int) -> bytes:
    return _u32(modulus) + _u32(shift) + _encode_vector(vector)


def _encode_public_key_list(public_keys: list[Vector]) -> tuple[bytes, list[bytes]]:
    encoded_keys = [_encode_vector(public_key) for public_key in public_keys]
    encoded = bytearray(b"DualMS2/direct-public-key-list/v1")
    encoded.extend(_u32(len(encoded_keys)))
    for index, encoded_key in enumerate(encoded_keys):
        encoded.extend(_frame(_u32(index)))
        encoded.extend(_frame(encoded_key))
    return bytes(encoded), encoded_keys


def _centered(value: int, modulus: int) -> int:
    canonical = value % modulus
    return canonical - modulus if canonical > modulus // 2 else canonical


def _poly_add(left: Poly, right: Poly, modulus: int) -> Poly:
    return [(a + b) % modulus for a, b in zip(left, right)]


def _poly_sub(left: Poly, right: Poly, modulus: int) -> Poly:
    return [(a - b) % modulus for a, b in zip(left, right)]


def _poly_mul(left: Poly, right: Poly, modulus: int) -> Poly:
    """Multiply in Z_modulus[X]/(X^256+1), exploiting sparse inputs."""
    left_terms = [(i, value % modulus) for i, value in enumerate(left) if value % modulus]
    right_terms = [(i, value % modulus) for i, value in enumerate(right) if value % modulus]
    if not left_terms or not right_terms:
        return [0] * DEGREE
    if len(left_terms) > len(right_terms):
        left_terms, right_terms = right_terms, left_terms
    accumulator = [0] * DEGREE
    for i, a in left_terms:
        for j, b in right_terms:
            position = i + j
            if position >= DEGREE:
                accumulator[position - DEGREE] -= a * b
            else:
                accumulator[position] += a * b
    return [value % modulus for value in accumulator]


def _vector_add(left: Vector, right: Vector, modulus: int) -> Vector:
    return [_poly_add(a, b, modulus) for a, b in zip(left, right)]


def _vector_sub(left: Vector, right: Vector, modulus: int) -> Vector:
    return [_poly_sub(a, b, modulus) for a, b in zip(left, right)]


def _scalar_vector_mul(scalar: Poly, vector: Vector, modulus: int) -> Vector:
    return [_poly_mul(scalar, entry, modulus) for entry in vector]


def _matrix_vector_mul(matrix: Matrix, vector: Vector, modulus: int) -> Vector:
    if any(len(row) != len(vector) for row in matrix):
        raise ValueError("matrix/vector dimension mismatch")
    result: Vector = []
    for row in matrix:
        accumulator = [0] * DEGREE
        for entry, scalar in zip(row, vector):
            accumulator = _poly_add(accumulator, _poly_mul(entry, scalar, modulus), modulus)
        result.append(accumulator)
    return result


def _round_coefficient(value: int, shift: int, modulus: int, rounded_modulus: int) -> int:
    canonical = value % modulus
    return ((canonical + (1 << (shift - 1))) >> shift) % rounded_modulus


def _round_vector(vector: Vector, profile: Profile, shift: int, rounded_modulus: int) -> Vector:
    return [
        [_round_coefficient(value, shift, profile.modulus, rounded_modulus) for value in poly]
        for poly in vector
    ]


def _embed_rounded(vector: Vector, profile: Profile) -> Vector:
    scale = 1 << profile.public_shift
    return [[(scale * value) % profile.modulus for value in poly] for poly in vector]


def _squared_norm(vector: Vector, modulus: int) -> int:
    return sum(_centered(value, modulus) ** 2 for poly in vector for value in poly)


def _zero_vector(length: int) -> Vector:
    return [[0] * DEGREE for _ in range(length)]


def _setup(profile: Profile, seed: bytes) -> Matrix:
    stream = _xof(b"DualMS2/public-reproducer/Setup", profile.label.encode(), seed)
    return [
        [_sample_poly(stream, profile.modulus) for _ in range(profile.columns)]
        for _ in range(profile.rows)
    ]


def _honest_public_key(profile: Profile, matrix: Matrix, seed: bytes) -> Vector:
    """Generate one challenge key according to the printed KeyGen equation."""
    stream = _xof(b"DualMS2/public-reproducer/KeyGen", profile.label.encode(), seed)
    secret = [_sample_small_poly(stream) for _ in range(profile.columns + profile.rows)]
    public_key: Vector = []
    for row_index, row in enumerate(matrix):
        accumulator = [value % profile.modulus for value in secret[profile.columns + row_index]]
        for matrix_entry, secret_entry in zip(row, secret[: profile.columns]):
            accumulator = _poly_add(
                accumulator,
                _poly_mul(matrix_entry, secret_entry, profile.modulus),
                profile.modulus,
            )
        public_key.append(accumulator)
    return public_key


def _registered_key(profile: Profile, index: int) -> Vector:
    """Return a distinct public key controlled by the game adversary."""
    if not 1 <= index < profile.signers:
        raise ValueError("registered-key index out of range")
    vector = _zero_vector(profile.rows)
    slot = index - 1
    vector[slot // DEGREE][slot % DEGREE] = 1
    return vector


def _public_key_list(profile: Profile, matrix: Matrix, seed: bytes) -> list[Vector]:
    public_keys = [_honest_public_key(profile, matrix, seed)]
    public_keys.extend(_registered_key(profile, index) for index in range(1, profile.signers))
    encodings = [_encode_vector(key) for key in public_keys]
    if len(set(encodings)) != profile.signers:
        raise RuntimeError("public-key list is not distinct")
    return public_keys


def _key_aggregate(profile: Profile, public_keys: list[Vector]) -> tuple[Vector, bytes]:
    """Run KeyAgg with a direct injective encoding of the complete key list."""
    if len(public_keys) != profile.signers:
        raise ValueError("wrong public-key-list size")
    list_encoding, encoded_keys = _encode_public_key_list(public_keys)
    base = _oracle_state(b"DualMS2/public-reproducer/Hagg", [list_encoding])
    exact = _zero_vector(profile.rows)
    for index, (public_key, encoded_key) in enumerate(zip(public_keys, encoded_keys)):
        state = base.copy()
        state.update(_frame(_u32(index)))
        state.update(_frame(encoded_key))
        coefficient = _sample_challenge_from_state(state)
        exact = _vector_add(
            exact,
            _scalar_vector_mul(coefficient, public_key, profile.modulus),
            profile.modulus,
        )
    rounded = _round_vector(exact, profile, profile.public_shift, profile.public_modulus)
    return rounded, list_encoding


def _hcom(profile: Profile, aggregate_key: Vector, message: bytes) -> tuple[Vector, Matrix]:
    stream = _xof(
        b"DualMS2/public-reproducer/Hcom",
        profile.label.encode(),
        _encode_rounded(aggregate_key, profile.public_modulus, profile.public_shift),
        message,
    )
    b_vector = [_sample_poly(stream, profile.modulus) for _ in range(profile.rows)]
    b_matrix = [
        [_sample_poly(stream, profile.modulus) for _ in range(profile.columns)]
        for _ in range(profile.rows)
    ]
    return b_vector, b_matrix


def _hsig(profile: Profile, commitment: Vector, message: bytes, aggregate_key: Vector) -> Poly:
    return _sample_challenge(
        b"DualMS2/public-reproducer/Hsig",
        profile.label.encode(),
        _encode_rounded(commitment, profile.commitment_modulus, profile.commitment_shift),
        message,
        _encode_rounded(aggregate_key, profile.public_modulus, profile.public_shift),
    )


@dataclass
class Signature:
    challenge: Poly
    z: Vector
    r: Poly
    rbar: Vector
    hint: Vector


def _valid_poly(poly: Any, modulus: int) -> bool:
    return (
        isinstance(poly, list)
        and len(poly) == DEGREE
        and all(isinstance(value, int) and 0 <= value < modulus for value in poly)
    )


def _valid_vector(vector: Any, length: int, modulus: int) -> bool:
    return isinstance(vector, list) and len(vector) == length and all(
        _valid_poly(poly, modulus) for poly in vector
    )


def _valid_challenge(challenge: Any) -> bool:
    return (
        isinstance(challenge, list)
        and len(challenge) == DEGREE
        and all(value in (-1, 0, 1) for value in challenge)
        and sum(value != 0 for value in challenge) == CHALLENGE_WEIGHT
    )


def _paper_bounds(profile: Profile) -> dict[str, int | str]:
    """Recompute the printed bounds; independent gates established sigma=alpha*T."""
    getcontext().prec = 100
    d = Decimal
    alpha = d(4917) * d(profile.signers) / d(1000)
    t_value = d(CHALLENGE_WEIGHT**2 * ETA) * d(
        DEGREE * (profile.columns + profile.rows + 1)
    ).sqrt()
    sigma = alpha * t_value
    b_value = sigma * d(2 * profile.signers * profile.columns * DEGREE).sqrt()
    b_value += d(profile.rows * DEGREE).sqrt() * (
        sigma * d(2 * profile.signers).sqrt()
        + d(ETA)
        + d(CHALLENGE_WEIGHT) * (d(2) ** (profile.public_shift - 1))
        + d(2) ** profile.commitment_shift
    )
    b_squared_floor = int((b_value * b_value).to_integral_value(rounding=ROUND_FLOOR))
    hint_threshold = int(
        ((b_value / (d(2) ** profile.commitment_shift)) ** 2).to_integral_value(
            rounding=ROUND_FLOOR
        )
    )
    if hint_threshold != profile.expected_hint_threshold:
        raise RuntimeError("paper-bound recomputation disagrees with the sealed profile")
    if b_squared_floor != profile.expected_B_squared_floor:
        raise RuntimeError("squared paper bound disagrees with the sealed profile")
    return {
        "alpha": str(alpha),
        "T": str(t_value),
        "sigma": str(sigma),
        "B": str(b_value),
        "B_squared_floor": b_squared_floor,
        "B_prime_squared_floor": int(
            (sigma * sigma * d(2 * profile.signers * DEGREE)).to_integral_value(
                rounding=ROUND_FLOOR
            )
        ),
        "B_double_prime_squared_floor": ETA * ETA * profile.columns * DEGREE * profile.signers,
        "hint_norm_squared_threshold": hint_threshold,
    }


def _reconstruct(
    profile: Profile,
    matrix: Matrix,
    aggregate_key: Vector,
    message: bytes,
    signature: Signature,
) -> Vector:
    b_vector, b_matrix = _hcom(profile, aggregate_key, message)
    az = _matrix_vector_mul(matrix, signature.z, profile.modulus)
    challenge_pk = _scalar_vector_mul(
        signature.challenge,
        _embed_rounded(aggregate_key, profile),
        profile.modulus,
    )
    rb = _scalar_vector_mul(signature.r, b_vector, profile.modulus)
    brbar = _matrix_vector_mul(b_matrix, signature.rbar, profile.modulus)
    exact = _vector_add(_vector_sub(az, challenge_pk, profile.modulus), rb, profile.modulus)
    exact = _vector_add(exact, brbar, profile.modulus)
    return _round_vector(
        exact,
        profile,
        profile.commitment_shift,
        profile.commitment_modulus,
    )


def verify(
    profile: Profile,
    matrix: Matrix,
    aggregate_key: Vector,
    message: bytes,
    signature: Signature,
    bounds: dict[str, int | str] | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Evaluate the complete ordinary rounded verifier from Section 3.2."""
    if not _valid_vector(aggregate_key, profile.rows, profile.public_modulus):
        return False, {"accepted": False, "reason": "aggregate_key_shape_or_range"}
    if not _valid_challenge(signature.challenge):
        return False, {"accepted": False, "reason": "challenge_space"}
    if not _valid_vector(signature.z, profile.columns, profile.modulus):
        return False, {"accepted": False, "reason": "z_shape_or_range"}
    if not _valid_poly(signature.r, profile.modulus):
        return False, {"accepted": False, "reason": "r_shape_or_range"}
    if not _valid_vector(signature.rbar, profile.columns, profile.modulus):
        return False, {"accepted": False, "reason": "rbar_shape_or_range"}
    if not _valid_vector(signature.hint, profile.rows, profile.commitment_modulus):
        return False, {"accepted": False, "reason": "hint_shape_or_range"}

    checked_bounds = bounds or _paper_bounds(profile)
    reconstructed = _reconstruct(profile, matrix, aggregate_key, message, signature)
    commitment = _vector_add(reconstructed, signature.hint, profile.commitment_modulus)
    hash_ok = _hsig(profile, commitment, message, aggregate_key) == signature.challenge
    hint_norm = _squared_norm(signature.hint, profile.commitment_modulus)
    z_hint_norm = _squared_norm(signature.z, profile.modulus)
    z_hint_norm += (1 << (2 * profile.commitment_shift)) * hint_norm
    r_norm = _squared_norm([signature.r], profile.modulus)
    rbar_norm = _squared_norm(signature.rbar, profile.modulus)
    z_hint_ok = z_hint_norm <= int(checked_bounds["B_squared_floor"])
    r_ok = r_norm <= int(checked_bounds["B_prime_squared_floor"])
    rbar_ok = rbar_norm <= int(checked_bounds["B_double_prime_squared_floor"])
    accepted = hash_ok and z_hint_ok and r_ok and rbar_ok
    return accepted, {
        "accepted": accepted,
        "reason": "ok" if accepted else "verification_condition_failed",
        "hash_ok": hash_ok,
        "hint_norm_squared": hint_norm,
        "z_hint_norm_squared": z_hint_norm,
        "z_hint_bound_squared_floor": int(checked_bounds["B_squared_floor"]),
        "z_hint_ok": z_hint_ok,
        "r_norm_squared": r_norm,
        "r_ok": r_ok,
        "rbar_norm_squared": rbar_norm,
        "rbar_ok": rbar_ok,
    }


def _candidate_commitment(profile: Profile, seed: bytes, trial: int) -> Vector:
    stream = _xof(
        b"DualMS2/public-reproducer/candidate",
        profile.label.encode(),
        seed,
        _u32(trial),
    )
    return [
        _sample_poly(stream, profile.commitment_modulus)
        for _ in range(profile.rows)
    ]


def _forge(
    profile: Profile,
    matrix: Matrix,
    aggregate_key: Vector,
    message: bytes,
    seed: bytes,
    bounds: dict[str, int | str],
    trial_limit: int,
) -> tuple[Signature, int, dict[str, Any]]:
    zeros_z = _zero_vector(profile.columns)
    zeros_r = [0] * DEGREE
    zeros_rbar = _zero_vector(profile.columns)
    embedded_key = _embed_rounded(aggregate_key, profile)
    for trial in range(1, trial_limit + 1):
        commitment = _candidate_commitment(profile, seed, trial)
        challenge = _hsig(profile, commitment, message, aggregate_key)
        exact_target = _scalar_vector_mul(challenge, embedded_key, profile.modulus)
        exact_target = [[(-value) % profile.modulus for value in poly] for poly in exact_target]
        reconstructed = _round_vector(
            exact_target,
            profile,
            profile.commitment_shift,
            profile.commitment_modulus,
        )
        hint = _vector_sub(commitment, reconstructed, profile.commitment_modulus)
        if _squared_norm(hint, profile.commitment_modulus) > int(
            bounds["hint_norm_squared_threshold"]
        ):
            continue
        signature = Signature(challenge, zeros_z, zeros_r, zeros_rbar, hint)
        accepted, diagnostic = verify(
            profile, matrix, aggregate_key, message, signature, bounds
        )
        if not accepted:
            raise RuntimeError("constructed norm-passing signature failed ordinary Verify")
        return signature, trial, diagnostic
    raise RuntimeError(f"no n={profile.signers} forgery within {trial_limit} Hsig queries")


def _signature_digest(signature: Signature) -> str:
    payload = bytearray()
    payload.extend(bytes(value + 1 for value in signature.challenge))
    payload.extend(_encode_vector(signature.z))
    payload.extend(_encode_poly(signature.r))
    payload.extend(_encode_vector(signature.rbar))
    payload.extend(_encode_vector(signature.hint))
    return hashlib.sha256(payload).hexdigest()


def _negative_controls(
    profile: Profile,
    matrix: Matrix,
    public_keys: list[Vector],
    aggregate_key: Vector,
    message: bytes,
    signature: Signature,
    bounds: dict[str, int | str],
) -> dict[str, bool]:
    controls: dict[str, bool] = {}

    controls["changed_message_rejected"] = not verify(
        profile, matrix, aggregate_key, message + b"/changed", signature, bounds
    )[0]

    changed_challenge = copy.deepcopy(signature)
    nonzero = next(i for i, value in enumerate(changed_challenge.challenge) if value)
    changed_challenge.challenge[nonzero] *= -1
    controls["changed_challenge_rejected"] = not verify(
        profile, matrix, aggregate_key, message, changed_challenge, bounds
    )[0]

    changed_z = copy.deepcopy(signature)
    changed_z.z[0][0] = 1
    controls["changed_z_rejected"] = not verify(
        profile, matrix, aggregate_key, message, changed_z, bounds
    )[0]

    changed_r = copy.deepcopy(signature)
    changed_r.r[0] = 1
    controls["changed_r_rejected"] = not verify(
        profile, matrix, aggregate_key, message, changed_r, bounds
    )[0]

    changed_rbar = copy.deepcopy(signature)
    changed_rbar.rbar[0][0] = 1
    controls["changed_rbar_rejected"] = not verify(
        profile, matrix, aggregate_key, message, changed_rbar, bounds
    )[0]

    bad_range = copy.deepcopy(signature)
    bad_range.hint[0][0] = profile.commitment_modulus
    controls["noncanonical_hint_rejected"] = not verify(
        profile, matrix, aggregate_key, message, bad_range, bounds
    )[0]

    mutated_keys = copy.deepcopy(public_keys)
    mutated_keys[-1][(profile.signers - 2) // DEGREE][(profile.signers - 2) % DEGREE] = 2
    mutated_aggregate, _ = _key_aggregate(profile, mutated_keys)
    controls["changed_registration_list_rejected"] = not verify(
        profile, matrix, mutated_aggregate, message, signature, bounds
    )[0]

    if profile.signers == 32:
        excessive = copy.deepcopy(signature)
        excessive.hint = [
            [profile.commitment_modulus // 2] * DEGREE for _ in range(profile.rows)
        ]
        excessive_accepted, excessive_diag = verify(
            profile, matrix, aggregate_key, message, excessive, bounds
        )
        controls["excessive_canonical_hint_rejected"] = (
            not excessive_accepted and not excessive_diag.get("z_hint_ok", True)
        )

    return controls


def run_profile(profile_name: str, seed: bytes, trial_limit: int = 512) -> dict[str, Any]:
    profile = PROFILES[profile_name]
    started = time.monotonic()
    matrix = _setup(profile, seed)
    public_keys = _public_key_list(profile, matrix, seed)
    aggregate_key, list_encoding = _key_aggregate(profile, public_keys)
    bounds = _paper_bounds(profile)
    message = b"DualMS 2.0 public reproducer fresh message / " + profile.label.encode()
    signature, trials, diagnostic = _forge(
        profile,
        matrix,
        aggregate_key,
        message,
        seed,
        bounds,
        trial_limit,
    )
    controls = _negative_controls(
        profile,
        matrix,
        public_keys,
        aggregate_key,
        message,
        signature,
        bounds,
    )
    if not all(controls.values()):
        raise RuntimeError("one or more negative controls did not reject")

    max_hint_norm = profile.rows * DEGREE * (profile.commitment_modulus // 2) ** 2
    elapsed = time.monotonic() - started
    return {
        "status": "PASS",
        "profile": profile.label,
        "parameters": {
            "n": profile.signers,
            "N": DEGREE,
            "q": profile.modulus,
            "m": profile.rows,
            "ell": profile.columns,
            "eta": ETA,
            "kappa": CHALLENGE_WEIGHT,
            "nu_b": profile.public_shift,
            "nu_w": profile.commitment_shift,
            "q_b": profile.public_modulus,
            "q_w": profile.commitment_modulus,
        },
        "security_game": {
            "honest_challenge_keys": 1,
            "adversarially_registered_keys": profile.signers - 1,
            "registration_list_size": profile.signers,
            "distinct_public_keys": profile.signers,
            "signing_oracle_queries": 0,
            "fresh_message": True,
        },
        "attack": {
            "ordinary_verifier_accepted": diagnostic["accepted"],
            "hsig_queries": trials,
            "trial_count": trials,
            "hint_norm_squared": diagnostic["hint_norm_squared"],
            "hint_norm_squared_threshold": int(bounds["hint_norm_squared_threshold"]),
            "maximum_canonical_hint_norm_squared": max_hint_norm,
            "signature_sha256": _signature_digest(signature),
            "all_zero_responses": True,
        },
        "transcript": {
            "codec": "non-normative direct injective length-delimited SHAKE256 completion",
            "public_key_list_sha256": hashlib.sha256(list_encoding).hexdigest(),
            "aggregate_public_key_sha256": hashlib.sha256(
                _encode_rounded(
                    aggregate_key, profile.public_modulus, profile.public_shift
                )
            ).hexdigest(),
            "message_sha256": hashlib.sha256(message).hexdigest(),
        },
        "bounds": bounds,
        "negative_controls": controls,
        "all_negative_controls_rejected": all(controls.values()),
        "runtime": {
            "wall_seconds": round(elapsed, 6),
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "workers": 1,
        },
    }


def run_all(seed: bytes | None = None, trial_limit: int = 512) -> dict[str, Any]:
    selected_seed = seed if seed is not None else os.urandom(32)
    reports = [run_profile(name, selected_seed, trial_limit) for name in ("n32", "n1024")]
    return {
        "banner": "DUALMS 2.0 ATTACK REPRODUCTION: PASS",
        "publication_status": "VERIFIED_ATTACK",
        "seed_hex": selected_seed.hex(),
        "profiles": reports,
        "summary": {
            "profiles_passed": sum(report["status"] == "PASS" for report in reports),
            "profiles_total": len(reports),
            "signing_oracle_queries": 0,
            "all_ordinary_verifiers_accepted": all(
                report["attack"]["ordinary_verifier_accepted"] for report in reports
            ),
            "all_negative_controls_rejected": all(
                report["all_negative_controls_rejected"] for report in reports
            ),
        },
    }


if __name__ == "__main__":
    print(json.dumps(run_all(), indent=2, sort_keys=True))
