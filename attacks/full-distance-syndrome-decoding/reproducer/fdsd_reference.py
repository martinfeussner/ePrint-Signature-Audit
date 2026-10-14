#!/usr/bin/env python3
"""Minimal paper-faithful Full-Distance Syndrome Decoding Level-I model.

This module implements only the frozen ePrint 2023/1956 KeyGen, Sign, and
Verify boundary.  GF(2) vectors are Python integers whose bit i is coordinate
i+1.  Public matrices are stored internally by columns.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, Sequence


N = 1600
K = 400
ROWS = N - K
L = 125
EPSILON = 5
THETA = 25
D = 343
ELL = THETA * (1 << EPSILON)
M1 = L
M2 = (N - M1) // 2
M0 = N - M1 - M2
TAU = tuple([14] * 18 + [13] * 7)


class CounterXOF:
    """Deterministic test RNG with independently derived labeled streams."""

    def __init__(self, seed: bytes):
        if len(seed) < 16:
            raise ValueError("seed must contain at least 16 bytes")
        self._seed = bytes(seed)
        self._counter = 0
        self._buffer = bytearray()

    @classmethod
    def derive(cls, root_seed: bytes, label: str) -> "CounterXOF":
        label_bytes = label.encode("utf-8")
        child = hashlib.shake_256(
            b"FDSD-2023-1956-DETERMINISTIC-STREAM-v1\x00"
            + len(label_bytes).to_bytes(2, "big")
            + label_bytes
            + len(root_seed).to_bytes(2, "big")
            + root_seed
        ).digest(32)
        return cls(child)

    def _refill(self) -> None:
        block = hashlib.shake_256(
            b"FDSD-2023-1956-BLOCK-v1\x00"
            + self._seed
            + self._counter.to_bytes(8, "big")
        ).digest(64)
        self._counter += 1
        self._buffer.extend(block)

    def bytes(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("negative byte request")
        while len(self._buffer) < size:
            self._refill()
        out = bytes(self._buffer[:size])
        del self._buffer[:size]
        return out

    def randbits(self, bits: int) -> int:
        if bits < 0:
            raise ValueError("negative bit request")
        if bits == 0:
            return 0
        value = int.from_bytes(self.bytes((bits + 7) // 8), "big")
        return value & ((1 << bits) - 1)

    def randbelow(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        bits = (bound - 1).bit_length()
        while True:
            candidate = self.randbits(bits)
            if candidate < bound:
                return candidate

    def shuffle(self, values: list[int]) -> None:
        for i in range(len(values) - 1, 0, -1):
            j = self.randbelow(i + 1)
            values[i], values[j] = values[j], values[i]

    def sample(self, values: Sequence[int], size: int) -> list[int]:
        if size < 0 or size > len(values):
            raise ValueError("invalid sample size")
        work = list(values)
        for i in range(size):
            j = i + self.randbelow(len(work) - i)
            work[i], work[j] = work[j], work[i]
        return work[:size]


def inverse_permutation(perm: Sequence[int]) -> list[int]:
    result = [0] * len(perm)
    for source, target in enumerate(perm):
        result[target] = source
    return result


def random_permutation(size: int, rng: CounterXOF) -> list[int]:
    perm = list(range(size))
    rng.shuffle(perm)
    return perm


def invert_binary_matrix(rows: Sequence[int], size: int) -> list[int] | None:
    """Return inverse rows, or None when the square GF(2) matrix is singular."""

    mask = (1 << size) - 1
    work = [(row & mask) | (1 << (size + i)) for i, row in enumerate(rows)]
    for col in range(size):
        pivot = None
        for row_index in range(col, size):
            if (work[row_index] >> col) & 1:
                pivot = row_index
                break
        if pivot is None:
            return None
        if pivot != col:
            work[col], work[pivot] = work[pivot], work[col]
        pivot_row = work[col]
        for row_index in range(size):
            if row_index != col and ((work[row_index] >> col) & 1):
                work[row_index] ^= pivot_row
    return [(row >> size) & mask for row in work]


def random_invertible_matrix(
    size: int, rng: CounterXOF
) -> tuple[list[int], list[int], int]:
    attempts = 0
    while True:
        attempts += 1
        rows = [rng.randbits(size) for _ in range(size)]
        inverse = invert_binary_matrix(rows, size)
        if inverse is not None:
            return rows, inverse, attempts


def rows_to_columns(rows: Sequence[int], size: int) -> list[int]:
    columns = [0] * size
    for row_index, row in enumerate(rows):
        remaining = row
        row_bit = 1 << row_index
        while remaining:
            low = remaining & -remaining
            col = low.bit_length() - 1
            columns[col] |= row_bit
            remaining ^= low
    return columns


def xor_selected(columns: Sequence[int], selector: int) -> int:
    result = 0
    remaining = selector
    while remaining:
        low = remaining & -remaining
        result ^= columns[low.bit_length() - 1]
        remaining ^= low
    return result


def iter_set_bits(value: int) -> Iterable[int]:
    remaining = value
    while remaining:
        low = remaining & -remaining
        yield low.bit_length() - 1
        remaining ^= low


def hash_message(message: bytes, output_bits: int = L) -> int:
    raw = hashlib.shake_256(message).digest((output_bits + 7) // 8)
    result = 0
    for index in range(output_bits):
        bit = (raw[index // 8] >> (7 - (index % 8))) & 1
        result |= bit << index
    return result


def pack_vector(vector: int, length: int) -> bytes:
    if vector < 0 or vector >> length:
        raise ValueError("vector does not fit declared length")
    out = bytearray((length + 7) // 8)
    for index in iter_set_bits(vector):
        out[index // 8] |= 1 << (7 - (index % 8))
    return bytes(out)


def unpack_vector(data: bytes, length: int, require_zero_padding: bool = True) -> int:
    if len(data) != (length + 7) // 8:
        raise ValueError("wrong vector encoding length")
    if require_zero_padding and length % 8:
        unused = 8 - (length % 8)
        if data[-1] & ((1 << unused) - 1):
            raise ValueError("nonzero vector padding")
    result = 0
    for index in range(length):
        bit = (data[index // 8] >> (7 - (index % 8))) & 1
        result |= bit << index
    return result


def pack_matrix_row_major(
    columns: Sequence[int], row_count: int, column_count: int
) -> bytes:
    if len(columns) != column_count:
        raise ValueError("wrong matrix column count")
    out = bytearray((row_count * column_count + 7) // 8)
    flat_index = 0
    for row in range(row_count):
        for col in range(column_count):
            if (columns[col] >> row) & 1:
                out[flat_index // 8] |= 1 << (7 - (flat_index % 8))
            flat_index += 1
    return bytes(out)


def unpack_matrix_row_major(
    data: bytes, row_count: int, column_count: int
) -> list[int]:
    bit_count = row_count * column_count
    if len(data) != (bit_count + 7) // 8:
        raise ValueError("wrong matrix encoding length")
    if bit_count % 8:
        unused = 8 - (bit_count % 8)
        if data[-1] & ((1 << unused) - 1):
            raise ValueError("nonzero matrix padding")
    columns = [0] * column_count
    flat_index = 0
    for row in range(row_count):
        row_bit = 1 << row
        for col in range(column_count):
            bit = (data[flat_index // 8] >> (7 - (flat_index % 8))) & 1
            if bit:
                columns[col] |= row_bit
            flat_index += 1
    return columns


@dataclass(slots=True)
class PublicKey:
    hstar_columns: list[int]
    r_columns: list[int]
    n: int = N
    k: int = K
    output_bits: int = L
    epsilon: int = EPSILON
    theta: int = THETA
    weight: int = D


@dataclass(slots=True)
class SecretKey:
    u_columns: list[int]
    s_groups: list[tuple[int, ...]]
    g_columns: list[int]
    t_columns: list[int]
    n_mask: int
    nstar_mask: int


@dataclass(slots=True)
class KeyGenerationEvidence:
    block_inversion_attempts: tuple[int, int, int]
    basic_identity_checks: int
    advanced_identity_checks: int
    n_size: int
    nstar_size: int
    te_size: int
    tau_sum: int


def _block_for_coordinate(
    coordinate: int,
    blocks: Sequence[tuple[int, int, Sequence[int]]],
) -> tuple[int, Sequence[int]]:
    for offset, size, columns in blocks:
        if offset <= coordinate < offset + size:
            return offset, columns
    raise ValueError("coordinate outside blocks")


def keygen(root_seed: bytes) -> tuple[PublicKey, SecretKey, KeyGenerationEvidence]:
    if len(TAU) != THETA or sum(TAU) != D:
        raise AssertionError("invalid frozen tau partition")

    f_perm = random_permutation(N, CounterXOF.derive(root_seed, "F"))
    p_perm = random_permutation(N, CounterXOF.derive(root_seed, "P"))
    f_inv = inverse_permutation(f_perm)
    p_inv = inverse_permutation(p_perm)

    block_specs = (("C0", M0), ("C1", M1), ("C2", M2))
    block_rows: list[list[int]] = []
    block_inverse_rows: list[list[int]] = []
    inversion_attempts: list[int] = []
    for label, size in block_specs:
        rows, inverse_rows, attempts = random_invertible_matrix(
            size, CounterXOF.derive(root_seed, label)
        )
        block_rows.append(rows)
        block_inverse_rows.append(inverse_rows)
        inversion_attempts.append(attempts)

    block_columns = [
        rows_to_columns(rows, size)
        for rows, (_, size) in zip(block_rows, block_specs)
    ]
    block_inverse_columns = [
        rows_to_columns(rows, size)
        for rows, (_, size) in zip(block_inverse_rows, block_specs)
    ]
    offsets = (0, M0, M0 + M1)
    inverse_blocks = [
        (offset, size, cols)
        for offset, (_, size), cols in zip(offsets, block_specs, block_inverse_columns)
    ]

    b_rng = CounterXOF.derive(root_seed, "B")
    b_columns = [b_rng.randbits(ROWS) for _ in range(N)]

    middle_coordinates = range(M0, M0 + M1)
    tr = sorted(f_perm[index] for index in middle_coordinates)
    te = sorted(p_perm[f_perm[index]] for index in middle_coordinates)
    te_mask = sum(1 << index for index in te)

    r_columns = [b_columns[index] for index in tr]

    c1_columns = block_columns[1]
    u_columns: list[int] = []
    for tr_coordinate in tr:
        source = f_inv[tr_coordinate]
        if not (M0 <= source < M0 + M1):
            raise AssertionError("F inverse did not return the middle block")
        local_column = c1_columns[source - M0]
        output = 0
        for local_index in iter_set_bits(local_column):
            global_index = M0 + local_index
            output |= 1 << p_perm[f_perm[global_index]]
        u_columns.append(output)

    h0_columns: list[int] = []
    for public_column in range(N):
        after_p_inverse = p_inv[public_column]
        after_f_inverse = f_inv[after_p_inverse]
        offset, inverse_columns = _block_for_coordinate(
            after_f_inverse, inverse_blocks
        )
        local_column = inverse_columns[after_f_inverse - offset]
        h0_column = 0
        for local_index in iter_set_bits(local_column):
            base_coordinate = offset + local_index
            h0_column ^= b_columns[f_perm[base_coordinate]]
        h0_columns.append(h0_column)

    for index, u_column in enumerate(u_columns):
        if xor_selected(h0_columns, u_column) != r_columns[index]:
            raise AssertionError(f"basic identity failed at hash column {index}")

    advanced_rng = CounterXOF.derive(root_seed, "advanced-partitions")
    complement = [index for index in range(N) if not ((te_mask >> index) & 1)]
    advanced_rng.shuffle(complement)
    n_coordinates = complement[:ELL]
    n_mask = sum(1 << index for index in n_coordinates)
    nstar_coordinates = [index for index in range(N) if not ((n_mask >> index) & 1)]
    advanced_rng.shuffle(n_coordinates)
    advanced_rng.shuffle(nstar_coordinates)
    n_groups = [n_coordinates[i * 32 : (i + 1) * 32] for i in range(THETA)]
    nstar_groups = [
        nstar_coordinates[i * 32 : (i + 1) * 32] for i in range(THETA)
    ]

    s_pool = list(te)
    advanced_rng.shuffle(s_pool)
    s_groups = [
        tuple(sorted(s_pool[i * EPSILON : (i + 1) * EPSILON]))
        for i in range(THETA)
    ]

    t_rng = CounterXOF.derive(root_seed, "Tmat")
    t_columns = [t_rng.randbits(THETA) for _ in range(ELL)]
    a_rng = CounterXOF.derive(root_seed, "a-vectors")
    a_vectors = [a_rng.randbits(ROWS) for _ in range(THETA - 1)]
    a_vectors.append(xor_selected(a_vectors, (1 << (THETA - 1)) - 1))

    candidate_rng = CounterXOF.derive(root_seed, "advanced-candidates")
    hstar_columns = list(h0_columns)
    g_columns = [0] * ELL

    for group in range(THETA):
        alpha_order = list(n_groups[group])
        candidate_rng.shuffle(alpha_order)
        for j in range(1 << EPSILON):
            column = group * (1 << EPSILON) + j
            alpha = alpha_order[j]
            o_mask = 0
            for bit_index, coordinate in enumerate(s_groups[group]):
                if (j >> bit_index) & 1:
                    o_mask |= 1 << coordinate

            if j == 0:
                p_size = TAU[group] - 1
                q_mask = 1 << alpha
            else:
                p_size = TAU[group] - 2
                alpha_prime = alpha_order[candidate_rng.randbelow(j)]
                q_mask = (1 << alpha) | (1 << alpha_prime)

            p_candidates = [
                coordinate
                for coordinate in nstar_groups[group]
                if not ((o_mask >> coordinate) & 1)
            ]
            p_coordinates = candidate_rng.sample(p_candidates, p_size)
            p_mask = sum(1 << coordinate for coordinate in p_coordinates)
            i_mask = o_mask | p_mask | q_mask
            g_columns[column] = i_mask

            b_column = a_vectors[group] ^ xor_selected(
                r_columns[:THETA], t_columns[column]
            )
            rhs = b_column ^ xor_selected(hstar_columns, i_mask ^ (1 << alpha))
            hstar_columns[alpha] = rhs

    for group in range(THETA):
        for j in range(1 << EPSILON):
            column = group * (1 << EPSILON) + j
            expected = a_vectors[group] ^ xor_selected(
                r_columns[:THETA], t_columns[column]
            )
            actual = xor_selected(hstar_columns, g_columns[column])
            if actual != expected:
                raise AssertionError(
                    f"advanced identity failed at group={group + 1}, j={j}"
                )

    public_key = PublicKey(hstar_columns=hstar_columns, r_columns=r_columns)
    secret_key = SecretKey(
        u_columns=u_columns,
        s_groups=s_groups,
        g_columns=g_columns,
        t_columns=t_columns,
        n_mask=n_mask,
        nstar_mask=((1 << N) - 1) ^ n_mask,
    )
    evidence = KeyGenerationEvidence(
        block_inversion_attempts=tuple(inversion_attempts),
        basic_identity_checks=L,
        advanced_identity_checks=ELL,
        n_size=n_mask.bit_count(),
        nstar_size=N - n_mask.bit_count(),
        te_size=te_mask.bit_count(),
        tau_sum=sum(TAU),
    )
    return public_key, secret_key, evidence


def sign(secret_key: SecretKey, message: bytes) -> tuple[int, int, int]:
    message_hash = hash_message(message)
    basic_signature = xor_selected(secret_key.u_columns, message_hash)
    sigma = basic_signature
    zeta = 0
    for group, s_group in enumerate(secret_key.s_groups):
        j = 0
        for bit_index, coordinate in enumerate(s_group):
            j |= ((basic_signature >> coordinate) & 1) << bit_index
        column = group * (1 << EPSILON) + j
        sigma ^= secret_key.g_columns[column]
        zeta ^= secret_key.t_columns[column]
    return message_hash, sigma, zeta


def verify_hash(
    public_key: PublicKey, message_hash: int, sigma: int, zeta: int
) -> bool:
    if message_hash < 0 or message_hash >> public_key.output_bits:
        return False
    if sigma < 0 or sigma >> public_key.n:
        return False
    if zeta < 0 or zeta >> public_key.theta:
        return False
    if sigma.bit_count() != public_key.weight:
        return False
    left = xor_selected(public_key.hstar_columns, sigma)
    right = xor_selected(public_key.r_columns, message_hash)
    right ^= xor_selected(public_key.r_columns[: public_key.theta], zeta)
    return left == right


def verify(public_key: PublicKey, message: bytes, sigma: int, zeta: int) -> bool:
    return verify_hash(public_key, hash_message(message), sigma, zeta)


def public_key_fingerprint(public_key: PublicKey) -> str:
    digest = hashlib.sha256()
    digest.update(pack_matrix_row_major(public_key.hstar_columns, ROWS, N))
    digest.update(pack_matrix_row_major(public_key.r_columns, ROWS, L))
    digest.update(bytes((public_key.theta,)))
    digest.update(public_key.weight.to_bytes(2, "big"))
    return digest.hexdigest()
