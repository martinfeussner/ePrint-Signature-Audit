#!/usr/bin/env python3
"""Independent Miraidon-S zero-witness forgery harness.

This instantiates the abstract hashes, seed tree, Merkle tree, finite-field
matrix operations, honest signer, attacker, and the natural corrected
Algorithm-6 verifier using only the Python standard library.  All proposed
parameter rows use prime q, so integer arithmetic modulo q suffices.

The attack never receives the generated secret key or public matrices.  It
sets a*=u=v=0 and, in every parallel round, X=Q=L=R=0.  Thus both response
branches hash the zero matrix for every first challenge xi and every key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Set, Tuple


Matrix = List[List[int]]
Node = Tuple[int, int]


PARAMETERS = {
    "L1": {"lambda": 128, "q": 127, "m": 10, "n": 10, "k": 44, "r": 4, "t": 180, "w": 121},
    "L3": {"lambda": 192, "q": 257, "m": 12, "n": 12, "k": 45, "r": 6, "t": 317, "w": 248},
    "L5": {"lambda": 256, "q": 509, "m": 13, "n": 13, "k": 50, "r": 7, "t": 512, "w": 435},
}


def h_n(outlen: int, domain: bytes, *parts: bytes) -> bytes:
    hh = hashlib.shake_256()
    hh.update(len(domain).to_bytes(2, "big"))
    hh.update(domain)
    for part in parts:
        hh.update(len(part).to_bytes(8, "big"))
        hh.update(part)
    return hh.digest(outlen)


def h(domain: bytes, *parts: bytes) -> bytes:
    return h_n(32, domain, *parts)


def xof_ints(domain: bytes, seed: bytes, count: int, modulus: int) -> List[int]:
    # 256-bit chunks make modulo bias cryptographically irrelevant for this
    # concrete test instantiation.  The attack is algebraic and does not use it.
    out = []
    for i in range(count):
        z = h(domain, seed, i.to_bytes(8, "big"))
        out.append(int.from_bytes(z, "big") % modulus)
    return out


def enc_int(x: int, width: int = 4) -> bytes:
    return int(x).to_bytes(width, "big")


def enc_vector(v: Sequence[int], q: int) -> bytes:
    width = max(1, (q.bit_length() + 7) // 8)
    return enc_int(len(v)) + b"".join(enc_int(x % q, width) for x in v)


def enc_matrix(a: Matrix, q: int) -> bytes:
    rows = len(a)
    cols = len(a[0]) if rows else 0
    width = max(1, (q.bit_length() + 7) // 8)
    return enc_int(rows) + enc_int(cols) + b"".join(
        enc_int(x % q, width) for row in a for x in row
    )


def zeros(rows: int, cols: int) -> Matrix:
    return [[0] * cols for _ in range(rows)]


def mat_add(a: Matrix, b: Matrix, q: int) -> Matrix:
    return [[(x + y) % q for x, y in zip(ra, rb)] for ra, rb in zip(a, b)]


def mat_scale_add(acc: Matrix, scalar: int, a: Matrix, q: int) -> None:
    scalar %= q
    for i in range(len(acc)):
        ar, rr = a[i], acc[i]
        for j in range(len(rr)):
            rr[j] = (rr[j] + scalar * ar[j]) % q


def mat_mul(a: Matrix, b: Matrix, q: int) -> Matrix:
    rows, inner = len(a), len(b)
    cols = len(b[0]) if inner else 0
    bt = list(zip(*b))
    return [[sum(x * y for x, y in zip(a[i], bt[j])) % q for j in range(cols)] for i in range(rows)]


def lincomb(coeffs: Sequence[int], matrices: Sequence[Matrix], q: int) -> Matrix:
    acc = zeros(len(matrices[0]), len(matrices[0][0]))
    for c, a in zip(coeffs, matrices):
        mat_scale_add(acc, c, a, q)
    return acc


def rank_mod(a: Matrix, q: int) -> int:
    x = [[v % q for v in row] for row in a]
    rows = len(x)
    cols = len(x[0]) if rows else 0
    rank = 0
    for col in range(cols):
        pivot = next((i for i in range(rank, rows) if x[i][col]), None)
        if pivot is None:
            continue
        x[rank], x[pivot] = x[pivot], x[rank]
        inv = pow(x[rank][col], -1, q)
        x[rank] = [(v * inv) % q for v in x[rank]]
        for i in range(rows):
            if i != rank and x[i][col]:
                f = x[i][col]
                x[i] = [(u - f * v) % q for u, v in zip(x[i], x[rank])]
        rank += 1
        if rank == rows:
            break
    return rank


def random_matrix(seed: bytes, label: bytes, rows: int, cols: int, q: int) -> Matrix:
    vals = xof_ints(label, seed, rows * cols, q)
    return [vals[i * cols:(i + 1) * cols] for i in range(rows)]


def random_invertible(seed: bytes, label: bytes, dim: int, q: int) -> Matrix:
    for attempt in range(256):
        a = random_matrix(seed + enc_int(attempt), label, dim, dim, q)
        if rank_mod(a, q) == dim:
            return a
    raise RuntimeError("failed to expand an invertible matrix")


def commit_c0(x: Matrix, qmat: Matrix, salt: bytes, index: int, q: int, lambda_bits: int) -> bytes:
    return h_n(2 * lambda_bits // 8, b"Miraidon/c0", enc_matrix(x, q), enc_matrix(qmat, q), salt, enc_int(index))


def commit_c1(s: Matrix, tmat: Matrix, salt: bytes, index: int, q: int, lambda_bits: int) -> bytes:
    return h_n(2 * lambda_bits // 8, b"Miraidon/c1", enc_matrix(s, q), enc_matrix(tmat, q), salt, enc_int(index))


def commit_y(x: Matrix, q: int, lambda_bits: int) -> bytes:
    return h_n(2 * lambda_bits // 8, b"Miraidon/y", enc_matrix(x, q))


def aggregate(domain: bytes, values: Sequence[bytes]) -> bytes:
    if not values:
        raise ValueError("cannot aggregate an empty sequence")
    return h_n(len(values[0]), domain, *values)


def fs1(c0: bytes, c1: bytes, msg: bytes, salt: bytes, t: int, q: int, lambda_bits: int) -> List[int]:
    seed = h_n(2 * lambda_bits // 8, b"Miraidon/FS1", c0, c1, msg, salt)
    return [1 + x for x in xof_ints(b"Miraidon/FS1/item", seed, t, q - 1)]


def fs2(c0: bytes, c1: bytes, msg: bytes, salt: bytes, xis: Sequence[int], yroot: bytes,
        t: int, w: int, lambda_bits: int) -> List[int]:
    outlen = 2 * lambda_bits // 8
    seed = h_n(outlen, b"Miraidon/FS2", c0, c1, msg, salt, enc_vector(xis, 1 << 32), yroot)
    scored = [(h_n(outlen, b"Miraidon/FS2/item", seed, enc_int(i)), i) for i in range(t)]
    chosen = {i for _, i in sorted(scored)[:w]}
    return [int(i in chosen) for i in range(t)]


def next_power_of_two(x: int) -> int:
    return 1 << (x - 1).bit_length()


def merkle_leaf(value: bytes, index: int) -> bytes:
    return h_n(len(value), b"Miraidon/MerkleLeaf", enc_int(index), value)


def merkle_pad(index: int, outlen: int) -> bytes:
    return h_n(outlen, b"Miraidon/MerklePad", enc_int(index))


def merkle_parent(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("Merkle child lengths differ")
    return h_n(len(left), b"Miraidon/MerkleNode", left, right)


def merkle_levels(values: Sequence[bytes]) -> List[List[bytes]]:
    size = next_power_of_two(len(values))
    level = [merkle_leaf(v, i) for i, v in enumerate(values)]
    level.extend(merkle_pad(i, len(values[0])) for i in range(len(values), size))
    levels = [level]
    while len(level) > 1:
        level = [merkle_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_proof(levels: Sequence[Sequence[bytes]], known_indices: Set[int]) -> Dict[Node, bytes]:
    known = set(known_indices)
    proof: Dict[Node, bytes] = {}
    for depth in range(len(levels) - 1):
        for idx in sorted(known):
            sibling = idx ^ 1
            if sibling not in known:
                proof[(depth, sibling)] = levels[depth][sibling]
        known = {i // 2 for i in known}
    return proof


def merkle_reconstruct(values: Mapping[int, bytes], proof: Mapping[Node, bytes], total: int) -> bytes:
    size = next_power_of_two(total)
    depth_max = int(math.log2(size))
    nodes: Dict[int, bytes] = {i: merkle_leaf(v, i) for i, v in values.items()}
    for depth in range(depth_max):
        parents: Dict[int, bytes] = {}
        for parent in sorted({i // 2 for i in nodes}):
            li, ri = 2 * parent, 2 * parent + 1
            left = nodes.get(li, proof.get((depth, li)))
            right = nodes.get(ri, proof.get((depth, ri)))
            if left is None or right is None:
                raise ValueError("incomplete Merkle proof")
            parents[parent] = merkle_parent(left, right)
        nodes = parents
    if set(nodes) != {0}:
        raise ValueError("Merkle proof did not yield a unique root")
    return nodes[0]


def seed_children(seed: bytes, salt: bytes, depth: int, index: int) -> Tuple[bytes, bytes]:
    tag = enc_int(depth) + enc_int(index)
    return h_n(len(seed), b"Miraidon/SeedLeft", seed, salt, tag), h_n(len(seed), b"Miraidon/SeedRight", seed, salt, tag)


def seed_leaves(root: bytes, salt: bytes, total: int) -> List[bytes]:
    size = next_power_of_two(total)
    nodes = [root]
    depth_max = int(math.log2(size))
    for depth in range(depth_max):
        nxt = []
        for index, seed in enumerate(nodes):
            nxt.extend(seed_children(seed, salt, depth, index))
        nodes = nxt
    return nodes[:total]


def seed_path(root: bytes, salt: bytes, selected: Set[int], total: int) -> Dict[Node, bytes]:
    size = next_power_of_two(total)
    depth_max = int(math.log2(size))
    path: Dict[Node, bytes] = {}

    def walk(seed: bytes, depth: int, index: int, lo: int, hi: int) -> None:
        real_hi = min(hi, total)
        real = set(range(lo, real_hi))
        if not real:
            return
        if real <= selected:
            path[(depth, index)] = seed
            return
        if real.isdisjoint(selected):
            return
        if depth == depth_max:
            raise AssertionError("partial selection at leaf")
        left, right = seed_children(seed, salt, depth, index)
        mid = (lo + hi) // 2
        walk(left, depth + 1, 2 * index, lo, mid)
        walk(right, depth + 1, 2 * index + 1, mid, hi)

    walk(root, 0, 0, 0, size)
    return path


def form_seed_path(path: Mapping[Node, bytes], salt: bytes, selected: Set[int], total: int) -> Dict[int, bytes]:
    size = next_power_of_two(total)
    depth_max = int(math.log2(size))
    leaves: Dict[int, bytes] = {}

    def expand(seed: bytes, depth: int, index: int) -> None:
        if depth == depth_max:
            if index < total:
                if index in leaves:
                    raise ValueError("overlapping seed path")
                leaves[index] = seed
            return
        left, right = seed_children(seed, salt, depth, index)
        expand(left, depth + 1, 2 * index)
        expand(right, depth + 1, 2 * index + 1)

    for (depth, index), seed in path.items():
        if depth < 0 or depth > depth_max or index < 0 or index >= (1 << depth):
            raise ValueError("invalid seed-tree node")
        expand(seed, depth, index)
    if set(leaves) != selected:
        raise ValueError("seed path reveals the wrong leaf set")
    return leaves


def expand_round(seed: bytes, salt: bytes, params: Mapping[str, int]) -> Tuple[List[int], Matrix, Matrix]:
    q, m, n, k = (params[x] for x in ("q", "m", "n", "k"))
    u = xof_ints(b"Miraidon/u", seed + salt, k, q)
    s = random_invertible(seed + salt, b"Miraidon/S", m, q)
    tmat = random_invertible(seed + salt, b"Miraidon/T", n, q)
    return u, s, tmat


def transformed_sum(coeffs: Sequence[int], matrices: Sequence[Matrix], s: Matrix, tmat: Matrix, q: int) -> Matrix:
    return mat_mul(mat_mul(s, lincomb(coeffs, matrices, q), q), tmat, q)


@dataclass
class KeyPair:
    public_matrices: List[Matrix]
    secret_a: List[int]
    secret_l: Matrix
    secret_r: Matrix


def keygen_expanded(params: Mapping[str, int], seed: bytes) -> KeyPair:
    """Generate a target-shaped valid expanded public key.

    This uses the equivalent uncompressed construction described in v4
    Section 5.2: sample a with a_k != 0, exact-rank E, M_1..M_{k-1}, and
    derive M_k.  Algorithm 6 consumes only the resulting public matrices.
    """
    q, m, n, k, r = (params[x] for x in ("q", "m", "n", "k", "r"))
    a = xof_ints(b"Miraidon/key/a", seed, k, q)
    a[-1] = 1
    lbase = random_matrix(seed, b"Miraidon/key/L", m, r, q)
    for i in range(r):
        for j in range(r):
            lbase[i][j] = int(i == j)
    rbase = random_matrix(seed, b"Miraidon/key/R", r, n, q)
    for i in range(r):
        for j in range(r):
            rbase[i][j] = int(i == j)
    e = mat_mul(lbase, rbase, q)
    if rank_mod(e, q) != r:
        raise AssertionError("key generator failed exact-rank invariant")
    matrices = [random_matrix(seed, b"Miraidon/key/M/" + enc_int(i), m, n, q) for i in range(k - 1)]
    mk = [[x for x in row] for row in e]
    for ai, mi in zip(a[:-1], matrices):
        mat_scale_add(mk, -ai, mi, q)
    matrices.append(mk)
    if lincomb(a, matrices, q) != e:
        raise AssertionError("key relation failure")
    return KeyPair(matrices, a, lbase, rbase)


def base_rounds(params: Mapping[str, int], matrices: Sequence[Matrix], master: bytes, salt: bytes):
    leaves = seed_leaves(master, salt, params["t"])
    rounds = []
    for seed in leaves:
        u, s, tmat = expand_round(seed, salt, params)
        x = transformed_sum(u, matrices, s, tmat, params["q"])
        rounds.append({"seed": seed, "u": u, "S": s, "T": tmat, "X": x})
    return rounds


def finish_signature(params: Mapping[str, int], matrices: Sequence[Matrix], msg: bytes, salt: bytes,
                     master: bytes, rounds: List[dict], c0leaves: List[bytes], c1leaves: List[bytes],
                     yleaves: List[bytes], vs: List[List[int]], ls: List[Matrix], rs: List[Matrix]) -> dict:
    levels = merkle_levels(c0leaves)
    c0 = levels[-1][0]
    c1 = aggregate(b"Miraidon/c1/all", c1leaves)
    xis = fs1(c0, c1, msg, salt, params["t"], params["q"], params["lambda"])
    # Callers supplied y/v values that may depend on xi.  For clarity they
    # install a closure-like marker and recompute before this routine.
    yroot = aggregate(b"Miraidon/Y", yleaves)
    bits = fs2(c0, c1, msg, salt, xis, yroot, params["t"], params["w"], params["lambda"])
    selected = {i for i, bit in enumerate(bits) if bit}
    known = set(range(params["t"])) - selected
    responses = []
    for i, bit in enumerate(bits):
        if bit:
            responses.append({"v": vs[i]})
        else:
            responses.append({"c1": c1leaves[i], "X": rounds[i]["X"], "L": ls[i], "R": rs[i]})
    return {
        "c0": c0,
        "c1": c1,
        "salt": salt,
        "Y": yroot,
        "seed_path": seed_path(master, salt, selected, params["t"]),
        "proof": merkle_proof(levels, known),
        "responses": responses,
    }


def sign_honest(params: Mapping[str, int], key: KeyPair, msg: bytes, nonce: bytes) -> dict:
    q, t = params["q"], params["t"]
    master = h_n(params["lambda"] // 8, b"Miraidon/honest/master", nonce)
    salt = h_n(2 * params["lambda"] // 8, b"Miraidon/honest/salt", nonce)
    rounds = base_rounds(params, key.public_matrices, master, salt)
    e = mat_mul(key.secret_l, key.secret_r, q)
    ls, rs, c0leaves, c1leaves = [], [], [], []
    for i, rd in enumerate(rounds):
        li = mat_mul(rd["S"], key.secret_l, q)
        ri = mat_mul(key.secret_r, rd["T"], q)
        qi = mat_mul(li, ri, q)
        if qi != mat_mul(mat_mul(rd["S"], e, q), rd["T"], q):
            raise AssertionError("honest factorization mismatch")
        ls.append(li)
        rs.append(ri)
        c0leaves.append(commit_c0(rd["X"], qi, salt, i, q, params["lambda"]))
        c1leaves.append(commit_c1(rd["S"], rd["T"], salt, i, q, params["lambda"]))
    levels = merkle_levels(c0leaves)
    c0 = levels[-1][0]
    c1 = aggregate(b"Miraidon/c1/all", c1leaves)
    xis = fs1(c0, c1, msg, salt, t, q, params["lambda"])
    vs, yleaves = [], []
    for rd, xi, li, ri in zip(rounds, xis, ls, rs):
        v = [(u + xi * a) % q for u, a in zip(rd["u"], key.secret_a)]
        vs.append(v)
        yleaves.append(commit_y(transformed_sum(v, key.public_matrices, rd["S"], rd["T"], q), q, params["lambda"]))
    return finish_signature(params, key.public_matrices, msg, salt, master, rounds, c0leaves, c1leaves, yleaves, vs, ls, rs)


def forge_zero_witness(params: Mapping[str, int], msg: bytes, nonce: bytes) -> dict:
    """Forge without a secret key or even reading the public matrices.

    A malicious prover may choose the masking vector u=0.  Hence X=0 and,
    for the zero witness a*=0, v=u=0.  Only valid S,T seed expansions are
    needed to authenticate the b=1 commitment branch.
    """
    q, m, n, k, r, t = (params[x] for x in ("q", "m", "n", "k", "r", "t"))
    master = h_n(params["lambda"] // 8, b"Miraidon/forge/master", nonce)
    salt = h_n(2 * params["lambda"] // 8, b"Miraidon/forge/salt", nonce)
    leaves = seed_leaves(master, salt, t)
    zx = zeros(m, n)
    rounds = []
    for seed in leaves:
        _, s, tmat = expand_round(seed, salt, params)
        rounds.append({"seed": seed, "S": s, "T": tmat, "X": [row[:] for row in zx]})
    zq = zeros(m, n)
    zl = zeros(m, r)
    zr = zeros(r, n)
    ls = [[row[:] for row in zl] for _ in range(t)]
    rs = [[row[:] for row in zr] for _ in range(t)]
    c0leaves = [commit_c0(rd["X"], zq, salt, i, q, params["lambda"]) for i, rd in enumerate(rounds)]
    c1leaves = [commit_c1(rd["S"], rd["T"], salt, i, q, params["lambda"]) for i, rd in enumerate(rounds)]
    # Choose u=0 and a*=0.  Then v=0 and both branch equations equal the
    # zero matrix for every xi and every public-key matrix tuple.
    vs = [[0] * k for _ in range(t)]
    yleaves = [commit_y(zx, q, params["lambda"]) for _ in range(t)]
    return finish_signature(params, [], msg, salt, master, rounds, c0leaves, c1leaves, yleaves, vs, ls, rs)


def verify(params: Mapping[str, int], public_matrices: Sequence[Matrix], msg: bytes, sig: Mapping,
           strict_exact_rank: bool = False) -> Tuple[bool, dict]:
    q, t, r = params["q"], params["t"], params["r"]
    try:
        xis = fs1(sig["c0"], sig["c1"], msg, sig["salt"], t, q, params["lambda"])
        bits = fs2(sig["c0"], sig["c1"], msg, sig["salt"], xis, sig["Y"], t, params["w"], params["lambda"])
        selected = {i for i, bit in enumerate(bits) if bit}
        seeds = form_seed_path(sig["seed_path"], sig["salt"], selected, t)
        c0_known: Dict[int, bytes] = {}
        c1leaves: List[bytes] = [b""] * t
        yleaves: List[bytes] = [b""] * t
        rank_checks = []
        for i, bit in enumerate(bits):
            resp = sig["responses"][i]
            if not bit:
                qmat = mat_mul(resp["L"], resp["R"], q)
                rq = rank_mod(qmat, q)
                rank_checks.append(rq)
                if strict_exact_rank and rq != r:
                    return False, {"reason": "non-exact Q rank", "round": i, "rank": rq}
                c0_known[i] = commit_c0(resp["X"], qmat, sig["salt"], i, q, params["lambda"])
                c1leaves[i] = resp["c1"]
                yleaves[i] = commit_y(mat_add(resp["X"], [[xis[i] * x % q for x in row] for row in qmat], q), q, params["lambda"])
            else:
                _, s, tmat = expand_round(seeds[i], sig["salt"], params)
                c1leaves[i] = commit_c1(s, tmat, sig["salt"], i, q, params["lambda"])
                val = transformed_sum(resp["v"], public_matrices, s, tmat, q)
                yleaves[i] = commit_y(val, q, params["lambda"])
        root = merkle_reconstruct(c0_known, sig["proof"], t)
        checks = {
            "c0_merkle": root == sig["c0"],
            "c1_aggregate": aggregate(b"Miraidon/c1/all", c1leaves) == sig["c1"],
            "Y_aggregate": aggregate(b"Miraidon/Y", yleaves) == sig["Y"],
        }
        detail = {
            "checks": checks,
            "b0_rounds": bits.count(0),
            "b1_rounds": bits.count(1),
            "xi_nonzero": all(x != 0 for x in xis),
            "opened_Q_ranks": sorted(set(rank_checks)),
            "commitment_bytes": len(sig["c0"]),
            "salt_bytes": len(sig["salt"]),
        }
        return all(checks.values()), detail
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return False, {"reason": type(exc).__name__ + ": " + str(exc)}


def run_row(name: str, params: Mapping[str, int], include_honest: bool = True) -> dict:
    start = time.monotonic()
    key = keygen_expanded(params, h(b"Miraidon/test/key", name.encode()))
    relation_rank = rank_mod(lincomb(key.secret_a, key.public_matrices, params["q"]), params["q"])
    msg = b"fresh-message/zero-witness/" + name.encode()
    forged = forge_zero_witness(params, msg, h(b"Miraidon/test/forge", name.encode()))
    forged_ok, forged_detail = verify(params, key.public_matrices, msg, forged)
    wrong_msg_ok, wrong_msg_detail = verify(params, key.public_matrices, msg + b"/changed", forged)
    strict_ok, strict_detail = verify(params, key.public_matrices, msg, forged, strict_exact_rank=True)
    # A second fresh message establishes reusable universal signing, rather
    # than an accidental accepting transcript for one message.
    msg2 = b"independent-fresh-message/zero-witness/" + name.encode()
    forged2 = forge_zero_witness(params, msg2, h(b"Miraidon/test/forge2", name.encode()))
    forged2_ok, forged2_detail = verify(params, key.public_matrices, msg2, forged2)
    result = {
        "parameter_row": name,
        "parameters": dict(params),
        "valid_key_relation_rank": relation_rank,
        "attack_inputs": ["public parameter row", "fresh message", "attacker nonce"],
        "public_matrices_read_by_attacker": False,
        "secret_key_passed_to_attacker": False,
        "forged_signature_accepts": forged_ok,
        "forged_branch_detail": forged_detail,
        "same_signature_changed_message_accepts": wrong_msg_ok,
        "changed_message_detail": wrong_msg_detail,
        "independently_forged_second_fresh_message_accepts": forged2_ok,
        "second_forge_branch_detail": forged2_detail,
        "strict_exact_rank_verifier_accepts_forgery": strict_ok,
        "strict_detail": strict_detail,
    }
    if include_honest:
        honest = sign_honest(params, key, b"honest-control/" + name.encode(), h(b"Miraidon/test/honest", name.encode()))
        honest_ok, honest_detail = verify(params, key.public_matrices, b"honest-control/" + name.encode(), honest)
        honest_strict_ok, honest_strict_detail = verify(
            params, key.public_matrices, b"honest-control/" + name.encode(), honest, strict_exact_rank=True
        )
        result.update({
            "honest_signature_accepts": honest_ok,
            "honest_strict_exact_rank_accepts": honest_strict_ok,
            "honest_detail": honest_detail,
            "honest_strict_detail": honest_strict_detail,
        })
    result["elapsed_seconds"] = time.monotonic() - start
    expected = (
        relation_rank == params["r"] and forged_ok and forged2_ok and not wrong_msg_ok and not strict_ok
        and (not include_honest or (result["honest_signature_accepts"] and result["honest_strict_exact_rank_accepts"]))
    )
    result["all_expected_checks_pass"] = expected
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", nargs="+", choices=sorted(PARAMETERS), default=sorted(PARAMETERS))
    parser.add_argument("--skip-honest", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    results = [run_row(name, PARAMETERS[name], not args.skip_honest) for name in args.rows]
    report = {
        "experiment_id": "MIR-EXP-004",
        "description": "zero-witness universal fresh-message forgery against natural corrected Algorithm 6",
        "results": results,
        "all_rows_pass": all(row["all_expected_checks_pass"] for row in results),
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    print(text, end="")
    if not report["all_rows_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
