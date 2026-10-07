#!/usr/bin/env python3
"""Full Level-I reference forgery for Miraidon-S's zero-witness flaw.

This implements the algebra of ePrint 2026/997 v4 Algorithms 4--6 over the
exact Level-I row.  It applies the evident Algorithm-6 correction identified
in MIR-EXP-002: c0 is checked as a Merkle root and c1 as a flat aggregate.
The paper leaves byte encodings, Fiat--Shamir expansion, and tree encodings
abstract; this reference uses SHAKE256 with length-prefixing, an ordinary
binary Merkle multiproof, and direct seed leaves for the abstract SeedPath.

The attack itself is independent of those choices: set a=0, E=Q=L=R=0.
Then v=u and both verifier branches compute the same y commitment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


Matrix = list[list[int]]


@dataclass(frozen=True)
class Params:
    name: str = "Miraidon-S-L1"
    lam: int = 128
    q: int = 127
    m: int = 10
    n: int = 10
    k: int = 44
    r: int = 4
    t: int = 180
    w: int = 121


P = Params()
ZERO32 = b"\0" * 32


def lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def encode_int(value: int) -> bytes:
    return value.to_bytes(8, "big")


def encode_matrix(matrix: Matrix) -> bytes:
    rows = len(matrix)
    cols = len(matrix[0]) if rows else 0
    return rows.to_bytes(2, "big") + cols.to_bytes(2, "big") + bytes(
        value for row in matrix for value in row
    )


def hash_parts(label: bytes, *parts: bytes, length: int = 32) -> bytes:
    h = hashlib.shake_256()
    h.update(lp(b"Miraidon-reference-v1"))
    h.update(lp(label))
    for part in parts:
        h.update(lp(part))
    return h.digest(length)


def field_values(seed: bytes, label: bytes, count: int, q: int) -> list[int]:
    """Deterministically sample unbiased values in [0,q)."""
    if not 1 < q < 256:
        raise ValueError("this compact reference supports q < 256")
    limit = 256 - (256 % q)
    size = max(64, count * 3)
    while True:
        stream = hash_parts(b"field-stream", seed, label, length=size)
        values = [byte % q for byte in stream if byte < limit]
        if len(values) >= count:
            return values[:count]
        size *= 2


def zero_matrix(rows: int, cols: int) -> Matrix:
    return [[0] * cols for _ in range(rows)]


def identity(size: int) -> Matrix:
    out = zero_matrix(size, size)
    for i in range(size):
        out[i][i] = 1
    return out


def matrix_from_values(values: list[int], rows: int, cols: int) -> Matrix:
    return [values[i * cols : (i + 1) * cols] for i in range(rows)]


def matmul(left: Matrix, right: Matrix, q: int) -> Matrix:
    rows, inner, cols = len(left), len(right), len(right[0])
    assert inner == len(left[0])
    out = zero_matrix(rows, cols)
    for i in range(rows):
        for h in range(inner):
            coefficient = left[i][h]
            if coefficient:
                for j in range(cols):
                    out[i][j] = (out[i][j] + coefficient * right[h][j]) % q
    return out


def linear_combo(coefficients: list[int], matrices: list[Matrix], q: int) -> Matrix:
    rows, cols = len(matrices[0]), len(matrices[0][0])
    out = zero_matrix(rows, cols)
    for coefficient, matrix in zip(coefficients, matrices):
        if coefficient:
            for i in range(rows):
                for j in range(cols):
                    out[i][j] = (out[i][j] + coefficient * matrix[i][j]) % q
    return out


def matadd(left: Matrix, right: Matrix, q: int, right_scale: int = 1) -> Matrix:
    return [
        [(a + right_scale * b) % q for a, b in zip(row_a, row_b)]
        for row_a, row_b in zip(left, right)
    ]


def rank(matrix: Matrix, q: int) -> int:
    work = [row[:] for row in matrix]
    rows = len(work)
    cols = len(work[0]) if rows else 0
    pivot_row = 0
    for col in range(cols):
        pivot = next((i for i in range(pivot_row, rows) if work[i][col]), None)
        if pivot is None:
            continue
        work[pivot_row], work[pivot] = work[pivot], work[pivot_row]
        inverse = pow(work[pivot_row][col], q - 2, q)
        work[pivot_row] = [(x * inverse) % q for x in work[pivot_row]]
        for i in range(rows):
            if i != pivot_row and work[i][col]:
                scale = work[i][col]
                work[i] = [
                    (x - scale * y) % q
                    for x, y in zip(work[i], work[pivot_row])
                ]
        pivot_row += 1
        if pivot_row == rows:
            break
    return pivot_row


def solve_unique_overdetermined(matrix: Matrix, rhs: list[int], q: int) -> list[int] | None:
    rows = [row[:] + [value] for row, value in zip(matrix, rhs)]
    nrows, ncols = len(rows), len(matrix[0])
    pivots: list[int] = []
    pivot_row = 0
    for col in range(ncols):
        pivot = next((i for i in range(pivot_row, nrows) if rows[i][col]), None)
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inverse = pow(rows[pivot_row][col], q - 2, q)
        rows[pivot_row] = [(x * inverse) % q for x in rows[pivot_row]]
        for i in range(nrows):
            if i != pivot_row and rows[i][col]:
                scale = rows[i][col]
                rows[i] = [
                    (x - scale * y) % q
                    for x, y in zip(rows[i], rows[pivot_row])
                ]
        pivots.append(col)
        pivot_row += 1
    if len(pivots) != ncols:
        return None
    if any(all(x == 0 for x in row[:ncols]) and row[ncols] != 0 for row in rows):
        return None
    solution = [0] * ncols
    for i, col in enumerate(pivots):
        solution[col] = rows[i][ncols]
    return solution


def split_lr(matrix: Matrix, r: int) -> tuple[Matrix, Matrix]:
    cut = len(matrix[0]) - r
    return ([row[:cut] for row in matrix], [row[cut:] for row in matrix])


def join_lr(left: Matrix, right: Matrix) -> Matrix:
    return [a + b for a, b in zip(left, right)]


def colmajor_get(matrix: Matrix, index: int) -> int:
    rows = len(matrix)
    return matrix[index % rows][index // rows]


def colmajor_set(matrix: Matrix, index: int, value: int) -> None:
    rows = len(matrix)
    matrix[index % rows][index // rows] = value


def generate_public_material(seed_pk: bytes, params: Params) -> tuple[Matrix, list[Matrix]]:
    q, m, n, k, r = params.q, params.m, params.n, params.k, params.r
    mk_right = matrix_from_values(
        field_values(seed_pk, b"Mk-right", m * r, q), m, r
    )
    matrices: list[Matrix] = []
    for i in range(k - 1):
        values = field_values(seed_pk, b"M" + encode_int(i), m * n, q)
        matrix = matrix_from_values(values, m, n)
        left, _ = split_lr(matrix, r)
        for j in range(k):
            colmajor_set(left, j, int(i == j))
        matrices.append(join_lr(left, split_lr(matrix, r)[1]))
    return mk_right, matrices


def keygen(params: Params, master: bytes) -> dict[str, Any]:
    """Instantiate Algorithm 5's evident canonical-form interpretation."""
    q, m, n, k, r = params.q, params.m, params.n, params.k, params.r
    for attempt in range(1, 20_000):
        seed_pk = hash_parts(b"keygen-pk", master, encode_int(attempt), length=params.lam // 8)
        seed_sk = hash_parts(b"keygen-sk", master, encode_int(attempt), length=params.lam // 8)
        mk_right, matrices = generate_public_material(seed_pk, params)
        K = matrix_from_values(
            field_values(seed_sk, b"K", r * (n - r), q), r, n - r
        )
        mk_right_k = matmul(mk_right, K, q)
        mi_right_k: list[Matrix] = []
        for matrix in matrices:
            _, right = split_lr(matrix, r)
            mi_right_k.append(matmul(right, K, q))
        system = []
        rhs = []
        for j in range(k):
            system.append(
                [
                    (int(i == j) - colmajor_get(mi_right_k[i], j)) % q
                    for i in range(k - 1)
                ]
            )
            rhs.append(colmajor_get(mk_right_k, j))
        ratios = solve_unique_overdetermined(system, rhs, q)
        if ratios is None:
            continue
        er = mk_right
        for coefficient, matrix in zip(ratios, matrices):
            _, right = split_lr(matrix, r)
            er = matadd(er, right, q, coefficient)
        if rank(er, q) != r:
            continue
        mk_left = matmul(er, K, q)
        for coefficient, matrix in zip(ratios, matrices):
            left, _ = split_lr(matrix, r)
            mk_left = matadd(mk_left, left, q, -coefficient)
        assert all(colmajor_get(mk_left, j) == 0 for j in range(k))
        mk = join_lr(mk_left, mk_right)
        public_matrices = matrices + [mk]
        witness = ratios + [1]
        e = linear_combo(witness, public_matrices, q)
        rbase = join_lr(K, identity(r))
        assert e == matmul(er, rbase, q)
        assert rank(e, q) == r
        return {
            "seed_pk": seed_pk,
            "seed_sk": seed_sk,
            "matrices": public_matrices,
            "witness": witness,
            "left_factor": er,
            "right_factor": rbase,
            "attempts": attempt,
            "compressed_tail": [
                colmajor_get(mk_left, j) for j in range(k, m * (n - r))
            ],
        }
    raise RuntimeError("Algorithm-5 key generation did not succeed")


def random_invertible(seed: bytes, label: bytes, size: int, q: int) -> Matrix:
    for attempt in range(256):
        values = field_values(seed, label + encode_int(attempt), size * size, q)
        matrix = matrix_from_values(values, size, size)
        if rank(matrix, q) == size:
            return matrix
    raise RuntimeError("failed to sample an invertible matrix")


def expand_round_seed(seed: bytes, params: Params) -> tuple[list[int], Matrix, Matrix]:
    u = field_values(seed, b"u", params.k, params.q)
    S = random_invertible(seed, b"S", params.m, params.q)
    T = random_invertible(seed, b"T", params.n, params.q)
    return u, S, T


def transform(S: Matrix, matrix: Matrix, T: Matrix, q: int) -> Matrix:
    return matmul(matmul(S, matrix, q), T, q)


def com_c0(X: Matrix, Q: Matrix, salt: bytes, index: int) -> bytes:
    return hash_parts(b"com", encode_matrix(X), encode_matrix(Q), salt, encode_int(index))


def com_c1(S: Matrix, T: Matrix, salt: bytes, index: int) -> bytes:
    return hash_parts(b"com", encode_matrix(S), encode_matrix(T), salt, encode_int(index))


def com_y(matrix: Matrix) -> bytes:
    return hash_parts(b"com", encode_matrix(matrix))


def aggregate(digests: list[bytes]) -> bytes:
    return hash_parts(b"com", *digests)


def fs1(c0: bytes, c1: bytes, message: bytes, salt: bytes, params: Params) -> list[int]:
    seed = hash_parts(b"FS1", c0, c1, message, salt)
    return [x + 1 for x in field_values(seed, b"nonzero", params.t, params.q - 1)]


def fs2(
    c0: bytes,
    c1: bytes,
    message: bytes,
    salt: bytes,
    xis: list[int],
    Y: bytes,
    params: Params,
) -> set[int]:
    seed = hash_parts(
        b"FS2", c0, c1, message, salt, bytes(xis), Y
    )
    priorities = hash_parts(b"fixed-weight", seed, length=32 * params.t)
    ranked = sorted(
        range(params.t),
        key=lambda i: (priorities[32 * i : 32 * (i + 1)], i),
    )
    return set(ranked[: params.w])


def merkle_parent(left: bytes, right: bytes) -> bytes:
    return hash_parts(b"merkle-node", left, right)


def merkle_tree(leaves: list[bytes]) -> list[list[bytes]]:
    size = 1 << (len(leaves) - 1).bit_length()
    level = leaves[:] + [
        hash_parts(b"merkle-padding", encode_int(i)) for i in range(len(leaves), size)
    ]
    levels = [level]
    while len(level) > 1:
        level = [merkle_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_proof(levels: list[list[bytes]], known_indices: set[int]) -> dict[tuple[int, int], bytes]:
    current = set(known_indices)
    proof: dict[tuple[int, int], bytes] = {}
    for level in range(len(levels) - 1):
        for index in sorted(current):
            sibling = index ^ 1
            if sibling not in current:
                proof[(level, sibling)] = levels[level][sibling]
        current = {index // 2 for index in current}
    return proof


def verify_merkle(
    known_leaves: dict[int, bytes],
    proof: dict[tuple[int, int], bytes],
    leaf_count: int,
) -> bytes | None:
    size = 1 << (leaf_count - 1).bit_length()
    current = dict(known_leaves)
    for i in range(leaf_count, size):
        current[i] = hash_parts(b"merkle-padding", encode_int(i))
    levels = size.bit_length() - 1
    for level in range(levels):
        parents: dict[int, bytes] = {}
        for index in sorted(current):
            sibling = index ^ 1
            sibling_hash = current.get(sibling, proof.get((level, sibling)))
            if sibling_hash is None:
                return None
            left, right = (current[index], sibling_hash) if index % 2 == 0 else (sibling_hash, current[index])
            parent = merkle_parent(left, right)
            parent_index = index // 2
            if parent_index in parents and parents[parent_index] != parent:
                return None
            parents[parent_index] = parent
        current = parents
    return current.get(0)


def make_signature(
    matrices: list[Matrix],
    message: bytes,
    witness: list[int],
    left_factor: Matrix,
    right_factor: Matrix,
    randomness: bytes,
    params: Params,
) -> dict[str, Any]:
    """Run Algorithm 4 for either the honest or the all-zero witness."""
    q = params.q
    salt = hash_parts(b"sign-salt", randomness, message, length=2 * params.lam // 8)
    master_seed = hash_parts(b"sign-master", randomness, message, length=params.lam // 8)
    seeds = [
        hash_parts(b"seed-leaf", master_seed, salt, encode_int(i), length=params.lam // 8)
        for i in range(params.t)
    ]
    rounds: list[dict[str, Any]] = []
    c0_leaves: list[bytes] = []
    c1_leaves: list[bytes] = []
    for i, seed in enumerate(seeds):
        u, S, T = expand_round_seed(seed, params)
        X = transform(S, linear_combo(u, matrices, q), T, q)
        L = matmul(S, left_factor, q)
        R = matmul(right_factor, T, q)
        Q = matmul(L, R, q)
        c0_i = com_c0(X, Q, salt, i)
        c1_i = com_c1(S, T, salt, i)
        rounds.append({"u": u, "S": S, "T": T, "X": X, "L": L, "R": R, "Q": Q})
        c0_leaves.append(c0_i)
        c1_leaves.append(c1_i)
    tree = merkle_tree(c0_leaves)
    c0 = tree[-1][0]
    c1 = aggregate(c1_leaves)
    xis = fs1(c0, c1, message, salt, params)
    ys: list[bytes] = []
    for xi, state in zip(xis, rounds):
        v = [(u + xi * a) % q for u, a in zip(state["u"], witness)]
        state["v"] = v
        y_matrix = transform(state["S"], linear_combo(v, matrices, q), state["T"], q)
        assert y_matrix == matadd(state["X"], state["Q"], q, xi)
        ys.append(com_y(y_matrix))
    Y = aggregate(ys)
    support = fs2(c0, c1, message, salt, xis, Y, params)
    complement = set(range(params.t)) - support
    responses: dict[int, dict[str, Any]] = {}
    for i, state in enumerate(rounds):
        if i in support:
            responses[i] = {"branch": 1, "v": state["v"]}
        else:
            responses[i] = {
                "branch": 0,
                "c1": c1_leaves[i],
                "X": state["X"],
                "L": state["L"],
                "R": state["R"],
            }
    return {
        "c0": c0,
        "c1": c1,
        "salt": salt,
        "Y": Y,
        "path": {i: seeds[i] for i in support},
        "proof": merkle_proof(tree, complement),
        "responses": responses,
    }


def forge_zero_witness(
    matrices: list[Matrix],
    message: bytes,
    public_randomness: bytes,
    params: Params,
) -> dict[str, Any]:
    """Forge using only the public matrices, message, and attacker randomness."""
    return make_signature(
        matrices,
        message,
        [0] * params.k,
        zero_matrix(params.m, params.r),
        zero_matrix(params.r, params.n),
        public_randomness,
        params,
    )


def verify(
    matrices: list[Matrix],
    message: bytes,
    signature: dict[str, Any],
    params: Params,
    enforce_exact_rank: bool = False,
) -> bool:
    try:
        c0, c1 = signature["c0"], signature["c1"]
        salt, Y = signature["salt"], signature["Y"]
        xis = fs1(c0, c1, message, salt, params)
        support = fs2(c0, c1, message, salt, xis, Y, params)
        if set(signature["path"]) != support or set(signature["responses"]) != set(range(params.t)):
            return False
        c0_known: dict[int, bytes] = {}
        c1_leaves: list[bytes | None] = [None] * params.t
        ys: list[bytes] = [b""] * params.t
        for i in range(params.t):
            response = signature["responses"][i]
            xi = xis[i]
            if i not in support:
                if response.get("branch") != 0:
                    return False
                X, L, R = response["X"], response["L"], response["R"]
                if enforce_exact_rank and (rank(L, params.q) != params.r or rank(R, params.q) != params.r):
                    return False
                Q = matmul(L, R, params.q)
                c0_known[i] = com_c0(X, Q, salt, i)
                c1_leaves[i] = response["c1"]
                ys[i] = com_y(matadd(X, Q, params.q, xi))
            else:
                if response.get("branch") != 1:
                    return False
                _, S, T = expand_round_seed(signature["path"][i], params)
                c1_leaves[i] = com_c1(S, T, salt, i)
                value = transform(
                    S,
                    linear_combo(response["v"], matrices, params.q),
                    T,
                    params.q,
                )
                ys[i] = com_y(value)
        root = verify_merkle(c0_known, signature["proof"], params.t)
        return (
            root == c0
            and all(value is not None for value in c1_leaves)
            and aggregate([value for value in c1_leaves if value is not None]) == c1
            and aggregate(ys) == Y
        )
    except (AssertionError, KeyError, TypeError, ValueError, IndexError):
        return False


def signature_digest(signature: dict[str, Any], params: Params) -> str:
    h = hashlib.sha256()
    for name in ("c0", "c1", "salt", "Y"):
        h.update(lp(signature[name]))
    for i in sorted(signature["path"]):
        h.update(encode_int(i) + lp(signature["path"][i]))
    for (level, index), value in sorted(signature["proof"].items()):
        h.update(encode_int(level) + encode_int(index) + lp(value))
    for i in range(params.t):
        response = signature["responses"][i]
        h.update(bytes([response["branch"]]))
        if response["branch"] == 0:
            h.update(lp(response["c1"]))
            h.update(lp(encode_matrix(response["X"])))
            h.update(lp(encode_matrix(response["L"])))
            h.update(lp(encode_matrix(response["R"])))
        else:
            h.update(lp(bytes(response["v"])))
    return h.hexdigest()


def public_key_digest(matrices: list[Matrix]) -> str:
    h = hashlib.sha256()
    for matrix in matrices:
        h.update(lp(encode_matrix(matrix)))
    return h.hexdigest()


def run() -> dict[str, Any]:
    started = time.perf_counter()
    master = bytes.fromhex("4d69726169646f6e2d4c312d726570726f64756365722d323032362d31302d3037")
    key_started = time.perf_counter()
    key = keygen(P, master)
    key_seconds = time.perf_counter() - key_started

    honest_message = b"Miraidon-S reference calibration message"
    forged_message = b"Miraidon-S fresh attacker-chosen message"
    mutated_message = forged_message + b"!"

    honest_started = time.perf_counter()
    honest_signature = make_signature(
        key["matrices"],
        honest_message,
        key["witness"],
        key["left_factor"],
        key["right_factor"],
        hash_parts(b"honest-randomness", master),
        P,
    )
    honest_seconds = time.perf_counter() - honest_started

    attack_started = time.perf_counter()
    # This value is public attacker-chosen randomness and is deliberately
    # independent of the deterministic key-generation master seed.
    attacker_randomness = hashlib.sha256(
        b"Miraidon-S public zero-witness forgery randomness"
    ).digest()
    forged_signature = forge_zero_witness(
        key["matrices"],
        forged_message,
        attacker_randomness,
        P,
    )
    attack_seconds = time.perf_counter() - attack_started

    checks = {
        "legitimate_key_has_rank_r_witness": rank(
            linear_combo(key["witness"], key["matrices"], P.q), P.q
        ) == P.r,
        "honest_signature_accepts": verify(key["matrices"], honest_message, honest_signature, P),
        "honest_signature_accepts_hardened_rank_check": verify(
            key["matrices"], honest_message, honest_signature, P, enforce_exact_rank=True
        ),
        "zero_witness_forgery_accepts": verify(
            key["matrices"], forged_message, forged_signature, P
        ),
        "zero_witness_forgery_rejected_by_hardened_rank_check": not verify(
            key["matrices"], forged_message, forged_signature, P, enforce_exact_rank=True
        ),
        "mutated_message_rejects": not verify(
            key["matrices"], mutated_message, forged_signature, P
        ),
        "forged_message_was_not_honestly_signed": forged_message != honest_message,
        "attack_uses_no_signing_query": True,
        "attack_witness_is_all_zero": True,
    }
    if not all(checks.values()):
        raise AssertionError(checks)

    return {
        "experiment_id": "MIR-EXP-004",
        "target": "Miraidon-S ePrint 2026/997 v4",
        "parameters": P.__dict__,
        "model": {
            "algorithm_6_correction": "Merkle-verify c0 leaves; flat-aggregate c1 leaves",
            "commitment_and_fiat_shamir": "SHAKE256, length-prefixed, domain-labelled",
            "merkle_proof": "ordinary binary multiproof",
            "seed_path": "direct revealed leaf seeds implementing abstract FormTree semantics",
            "wire_compatibility": "paper supplies no concrete wire encoding or full implementation",
        },
        "attack": {
            "witness": "a=0",
            "E": "0",
            "per_round": "Q=0, L=0, R=0, v=u",
            "inputs": ["public matrices", "fresh message", "attacker randomness"],
            "secret_key_material_passed": False,
            "signing_queries": 0,
            "success_probability": 1,
            "expected_work": "polynomial; one ordinary signing pass",
        },
        "keygen": {
            "algorithm_5_attempts": key["attempts"],
            "compressed_tail_elements": len(key["compressed_tail"]),
            "seconds": key_seconds,
        },
        "checks": checks,
        "trials": {"keys": 1, "forgeries": 1, "accepted": 1},
        "digests": {
            "public_key_sha256": public_key_digest(key["matrices"]),
            "honest_signature_sha256": signature_digest(honest_signature, P),
            "forged_signature_sha256": signature_digest(forged_signature, P),
            "honest_message_sha256": hashlib.sha256(honest_message).hexdigest(),
            "forged_message_sha256": hashlib.sha256(forged_message).hexdigest(),
        },
        "timing": {
            "honest_sign_seconds": honest_seconds,
            "forge_seconds": attack_seconds,
            "total_seconds": time.perf_counter() - started,
        },
        "environment": {"python": platform.python_version(), "workers": 1},
        "result": "FULL_PARAMETER_PUBLIC_KEY_ONLY_FRESH_MESSAGE_FORGERY",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
