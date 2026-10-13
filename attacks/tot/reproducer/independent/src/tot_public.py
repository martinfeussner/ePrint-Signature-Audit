#!/usr/bin/env python3
"""Public-key format and ordinary raw-vector verifier for TOT.

The public map is stored as 128-bit output coefficients in the order

    1, x_i, x_i^2, x_i*x_j (i < j).

Over F_2, x_i^2 and x_i agree on every verifier input.  The key generator
uses the canonical Boolean representative with zero square coefficients and
folds their contribution into the linear coefficients.  This preserves the
public map on all of F_2^128 while retaining the paper's formal coefficient
count.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct


MAGIC = b"TOTPK01\0"
HEADER = struct.Struct("<8sHHHHI16s")
COEFFICIENT_BYTES = 16


@dataclass(frozen=True)
class PublicKey:
    q: int
    n: int
    d: int
    t: int
    modulus_low: int
    constant: int
    linear: tuple[int, ...]
    diagonal: tuple[int, ...]
    cross: tuple[int, ...]

    @property
    def coefficient_count(self) -> int:
        return 1 + 2 * self.n + self.n * (self.n - 1) // 2


def expected_coefficient_count(n: int) -> int:
    return (n + 1) * (n + 2) // 2


def _encode_coefficient(value: int, n: int) -> bytes:
    if value < 0 or value >= (1 << n):
        raise ValueError("coefficient is outside F_2^n")
    if n % 8:
        raise ValueError("this reproducer requires a byte-aligned n")
    return value.to_bytes(n // 8, "little")


def write_public_key(path: Path, key: PublicKey) -> None:
    if key.q != 2 or key.n != 128 or key.d != 6 or key.t != 64:
        raise ValueError("not the frozen q=2,n=128,d=6,t=64 row")
    if len(key.linear) != key.n or len(key.diagonal) != key.n:
        raise ValueError("wrong linear/diagonal coefficient count")
    if len(key.cross) != key.n * (key.n - 1) // 2:
        raise ValueError("wrong cross coefficient count")
    if key.coefficient_count != expected_coefficient_count(key.n):
        raise AssertionError("formal public-key coefficient count mismatch")

    coefficients = (key.constant,) + key.linear + key.diagonal + key.cross
    header = HEADER.pack(
        MAGIC,
        key.q,
        key.n,
        key.d,
        key.t,
        len(coefficients),
        key.modulus_low.to_bytes(16, "little"),
    )
    payload = b"".join(_encode_coefficient(c, key.n) for c in coefficients)
    path.write_bytes(header + payload)


def load_public_key(path: Path) -> PublicKey:
    blob = path.read_bytes()
    if len(blob) < HEADER.size:
        raise ValueError("truncated public key header")
    magic, q, n, d, t, count, modulus_bytes = HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise ValueError("wrong public key magic")
    if (q, n, d, t) != (2, 128, 6, 64):
        raise ValueError("wrong parameter row")
    if count != expected_coefficient_count(n):
        raise ValueError("wrong formal coefficient count")
    coefficient_bytes = n // 8
    expected_size = HEADER.size + count * coefficient_bytes
    if len(blob) != expected_size:
        raise ValueError("wrong public key byte length")
    coefficients = tuple(
        int.from_bytes(blob[offset : offset + coefficient_bytes], "little")
        for offset in range(HEADER.size, len(blob), coefficient_bytes)
    )
    linear_start = 1
    diagonal_start = linear_start + n
    cross_start = diagonal_start + n
    return PublicKey(
        q=q,
        n=n,
        d=d,
        t=t,
        modulus_low=int.from_bytes(modulus_bytes, "little"),
        constant=coefficients[0],
        linear=coefficients[linear_start:diagonal_start],
        diagonal=coefficients[diagonal_start:cross_start],
        cross=coefficients[cross_start:],
    )


def evaluate_public(key: PublicKey, signature: int) -> int:
    """Evaluate the public multivariate polynomials on a vector."""
    if signature < 0 or signature >= (1 << key.n):
        raise ValueError("signature vector is outside F_2^n")

    result = key.constant
    active = [i for i in range(key.n) if (signature >> i) & 1]
    for i in active:
        result ^= key.linear[i]
        result ^= key.diagonal[i]  # x_i^2 = x_i for inputs in F_2.

    active_set = set(active)
    cross_index = 0
    for i in range(key.n):
        i_active = i in active_set
        for j in range(i + 1, key.n):
            if i_active and j in active_set:
                result ^= key.cross[cross_index]
            cross_index += 1
    if cross_index != len(key.cross):
        raise AssertionError("cross coefficient traversal mismatch")
    return result


def ordinary_verify(key: PublicKey, message: bytes, signature: bytes) -> bool:
    """The paper/patent verifier: accept iff P(signature) equals message."""
    vector_bytes = key.n // 8
    if len(message) != vector_bytes or len(signature) != vector_bytes:
        return False
    signature_value = int.from_bytes(signature, "little")
    expected_message = evaluate_public(key, signature_value)
    return expected_message.to_bytes(vector_bytes, "little") == message


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
