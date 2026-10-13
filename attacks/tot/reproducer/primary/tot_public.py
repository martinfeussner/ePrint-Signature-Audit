#!/usr/bin/env python3
"""Minimal public-key machinery for the literal TOT verifier.

The public-key encoding stores coefficient vectors rather than one polynomial
at a time.  For every monomial, one 128-bit block contains its coefficient in
all 128 output coordinates.  This is only a transpose of the paper's public
quadratic-polynomial representation.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


N = 128
MASK = (1 << N) - 1
# x^128 + x^7 + x^2 + x + 1, the irreducible polynomial used by GCM.
REDUCTION_LOW = 0x87
PK_MAGIC = b"TOTPK128"
PK_HEADER = struct.Struct("<8sII")
BLOCK_BYTES = N // 8


class StableRng:
    """Small SHA-256 counter generator used only for reproducible fixtures."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0

    def bytes(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            out.extend(
                hashlib.sha256(
                    self.seed + self.counter.to_bytes(16, "little")
                ).digest()
            )
            self.counter += 1
        return bytes(out[:length])

    def bits(self, width: int) -> int:
        return int.from_bytes(self.bytes((width + 7) // 8), "little") & (
            (1 << width) - 1
        )

    def below(self, limit: int) -> int:
        if limit <= 0:
            raise ValueError("limit must be positive")
        width = limit.bit_length()
        while True:
            value = self.bits(width)
            if value < limit:
                return value


def gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^128) in the polynomial basis fixed above."""

    a &= MASK
    b &= MASK
    out = 0
    for _ in range(N):
        if b & 1:
            out ^= a
        b >>= 1
        carry = a >> (N - 1)
        a = (a << 1) & MASK
        if carry:
            a ^= REDUCTION_LOW
    return out


def gf_pow(base: int, exponent: int) -> int:
    out = 1
    while exponent:
        if exponent & 1:
            out = gf_mul(out, base)
        exponent >>= 1
        if exponent:
            base = gf_mul(base, base)
    return out


def frobenius_64(value: int) -> int:
    for _ in range(6):
        value = gf_mul(value, value)
    return value


def poly_from_roots(value: int, roots: Sequence[int]) -> int:
    out = 1
    for root in roots:
        out = gf_mul(out, value ^ root)
    return out


def linear_apply(columns: Sequence[int], value: int) -> int:
    out = 0
    while value:
        low = value & -value
        out ^= columns[low.bit_length() - 1]
        value ^= low
    return out


def invert_columns(columns: Sequence[int], n: int = N) -> list[int]:
    if len(columns) != n:
        raise ValueError("wrong matrix width")
    rows: list[int] = []
    for out_bit in range(n):
        left = 0
        for in_bit, column in enumerate(columns):
            if (column >> out_bit) & 1:
                left |= 1 << in_bit
        rows.append(left | (1 << (n + out_bit)))

    for pivot in range(n):
        selected = next((r for r in range(pivot, n) if (rows[r] >> pivot) & 1), None)
        if selected is None:
            raise ValueError("singular matrix")
        rows[pivot], rows[selected] = rows[selected], rows[pivot]
        for r in range(n):
            if r != pivot and ((rows[r] >> pivot) & 1):
                rows[r] ^= rows[pivot]

    inverse_rows = [(row >> n) & ((1 << n) - 1) for row in rows]
    inverse_columns = []
    for in_bit in range(n):
        column = 0
        for out_bit, row in enumerate(inverse_rows):
            column |= ((row >> in_bit) & 1) << out_bit
        inverse_columns.append(column)
    return inverse_columns


def random_invertible_columns(rng: StableRng, n: int = N) -> list[int]:
    columns = [1 << i for i in range(n)]
    # Every operation is an invertible elementary column operation.  The
    # sequence is long enough to make the fixture dense without rejection.
    for step in range(16 * n):
        i = rng.below(n)
        j = rng.below(n - 1)
        if j >= i:
            j += 1
        if step % 5 == 0:
            columns[i], columns[j] = columns[j], columns[i]
        else:
            columns[i] ^= columns[j]
    return columns


@dataclass(frozen=True)
class AffineMap:
    columns: tuple[int, ...]
    offset: int

    def __call__(self, value: int) -> int:
        return linear_apply(self.columns, value) ^ self.offset

    def inverse(self) -> "AffineMap":
        inverse_columns = tuple(invert_columns(self.columns))
        return AffineMap(
            inverse_columns,
            linear_apply(inverse_columns, self.offset),
        )


@dataclass(frozen=True)
class PublicKey:
    n: int
    constant: int
    linear: tuple[int, ...]
    quadratic: tuple[int, ...]

    @property
    def coefficient_blocks(self) -> int:
        return 1 + self.n + self.n * (self.n + 1) // 2

    def evaluate(self, value: int) -> int:
        if value < 0 or value >= (1 << self.n):
            raise ValueError("signature is outside F_2^n")
        out = self.constant
        for i in range(self.n):
            if (value >> i) & 1:
                out ^= self.linear[i]
        cursor = 0
        for i in range(self.n):
            bit_i = (value >> i) & 1
            for j in range(i, self.n):
                if bit_i and ((value >> j) & 1):
                    out ^= self.quadratic[cursor]
                cursor += 1
        return out

    def blocks(self) -> Iterable[int]:
        yield self.constant
        yield from self.linear
        yield from self.quadratic


def interpolate_public_map(function) -> PublicKey:
    """Recover the canonical Boolean ANF of a promised quadratic map."""

    constant = function(0)
    basis_values = [function(1 << i) for i in range(N)]
    linear = tuple(value ^ constant for value in basis_values)
    quadratic: list[int] = []
    for i in range(N):
        for j in range(i, N):
            if i == j:
                # Over F_2, x_i^2 and x_i are the same function.  We choose
                # the canonical representation with zero diagonal slots and
                # put their combined coefficient in the linear slot.
                quadratic.append(0)
            else:
                quadratic.append(
                    function((1 << i) ^ (1 << j))
                    ^ basis_values[i]
                    ^ basis_values[j]
                    ^ constant
                )
    return PublicKey(N, constant, linear, tuple(quadratic))


def write_public_key(path: Path, public_key: PublicKey) -> None:
    blocks = list(public_key.blocks())
    with path.open("wb") as stream:
        stream.write(PK_HEADER.pack(PK_MAGIC, public_key.n, len(blocks)))
        for block in blocks:
            stream.write(block.to_bytes(BLOCK_BYTES, "little"))


def read_public_key(path: Path) -> PublicKey:
    payload = path.read_bytes()
    if len(payload) < PK_HEADER.size:
        raise ValueError("truncated public key")
    magic, n, count = PK_HEADER.unpack_from(payload)
    if magic != PK_MAGIC or n != N:
        raise ValueError("wrong TOT public-key header")
    expected_count = 1 + n + n * (n + 1) // 2
    if count != expected_count:
        raise ValueError("wrong coefficient count")
    expected_bytes = PK_HEADER.size + count * BLOCK_BYTES
    if len(payload) != expected_bytes:
        raise ValueError("wrong public-key length")
    blocks = [
        int.from_bytes(payload[offset : offset + BLOCK_BYTES], "little")
        for offset in range(PK_HEADER.size, len(payload), BLOCK_BYTES)
    ]
    quadratic_start = 1 + n
    return PublicKey(
        n=n,
        constant=blocks[0],
        linear=tuple(blocks[1:quadratic_start]),
        quadratic=tuple(blocks[quadratic_start:]),
    )


def encode_vector(value: int) -> str:
    return value.to_bytes(BLOCK_BYTES, "little").hex()


def decode_vector(encoded: str) -> int:
    raw = bytes.fromhex(encoded)
    if len(raw) != BLOCK_BYTES:
        raise ValueError("wrong vector length")
    return int.from_bytes(raw, "little")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
