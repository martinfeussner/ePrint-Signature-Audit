#!/usr/bin/env python3
"""Full-parameter public SSD1760 forgery reproduction.

This standard-library module reconstructs the standard-mode Gen1/Gen2 algebra
printed in IACR ePrint 2022/1698.  Matrices over F_2 are lists of integer row
bitsets.  The attack stage receives only the public matrices, hashes distinct
candidate-message byte strings, and invokes the ordinary Algorithm-4 verifier.
"""

from __future__ import annotations

from decimal import Decimal, getcontext
import hashlib
import math
import random


N = 1760
GAMMA = 4
K = 440
L = 396
L_HALF = 198
K_PRIME = 242
DISTANCE = 502
OMEGA = 484
MU = 11
LOW = OMEGA - MU
HIGH = DISTANCE + MU
R_ORDER = 15
M_ORDER = 30
FREE_ONES = OMEGA - K_PRIME // 2
PAPER_SHA256 = "619903383e40bed6320d1fc0a17c61553073d11545eb12302cafe6a84cfbd80e"
SCHEMA = "eprint-audit.ssd1760.public-reproduction.v1"


def eye(size: int) -> list[int]:
    return [1 << i for i in range(size)]


def linear_map(rows: list[int], vector: int) -> int:
    answer = 0
    for i, row in enumerate(rows):
        answer |= ((row & vector).bit_count() & 1) << i
    return answer


def product(left: list[int], right: list[int]) -> list[int]:
    answer: list[int] = []
    for left_row in left:
        value = 0
        while left_row:
            bit = left_row & -left_row
            value ^= right[bit.bit_length() - 1]
            left_row ^= bit
        answer.append(value)
    return answer


def matrix_xor(*matrices: list[int]) -> list[int]:
    answer = [0] * len(matrices[0])
    for matrix in matrices:
        answer = [x ^ y for x, y in zip(answer, matrix)]
    return answer


def matrix_power(matrix: list[int], exponent: int) -> list[int]:
    answer = eye(len(matrix))
    base = matrix[:]
    while exponent:
        if exponent & 1:
            answer = product(answer, base)
        base = product(base, base)
        exponent >>= 1
    return answer


def inverse(matrix: list[int]) -> list[int] | None:
    size = len(matrix)
    low_mask = (1 << size) - 1
    work = [matrix[i] | (1 << (size + i)) for i in range(size)]
    for column in range(size):
        pivot = next(
            (row for row in range(column, size) if (work[row] >> column) & 1),
            None,
        )
        if pivot is None:
            return None
        work[column], work[pivot] = work[pivot], work[column]
        for row in range(size):
            if row != column and ((work[row] >> column) & 1):
                work[row] ^= work[column]
    if [row & low_mask for row in work] != eye(size):
        raise AssertionError("Gauss-Jordan inverse did not reach identity")
    return [row >> size for row in work]


def draw_gl(size: int, rng: random.Random) -> tuple[list[int], list[int], int]:
    draws = 0
    while True:
        draws += 1
        candidate = [rng.getrandbits(size) for _ in range(size)]
        candidate_inverse = inverse(candidate)
        if candidate_inverse is not None:
            return candidate, candidate_inverse, draws


def block_diagonal(blocks: list[list[int]]) -> list[int]:
    answer: list[int] = []
    offset = 0
    for block in blocks:
        width = len(block)
        if any(row >> width for row in block):
            raise ValueError("block is not square")
        answer.extend(row << offset for row in block)
        offset += width
    return answer


def rank(rows: list[int]) -> int:
    leaders: dict[int, int] = {}
    for value in rows:
        while value:
            leader = value.bit_length() - 1
            if leader in leaders:
                value ^= leaders[leader]
            else:
                leaders[leader] = value
                break
    return len(leaders)


def independent_rows(rows: list[int], count: int) -> tuple[list[int], list[int]]:
    leaders: dict[int, int] = {}
    chosen: list[int] = []
    indices: list[int] = []
    for index, original in enumerate(rows):
        value = original
        while value:
            leader = value.bit_length() - 1
            if leader in leaders:
                value ^= leaders[leader]
            else:
                leaders[leader] = value
                chosen.append(original)
                indices.append(index)
                break
        if len(chosen) == count:
            return chosen, indices
    raise ValueError(f"only {len(chosen)} independent rows, need {count}")


def columns(rows: list[int], width: int) -> list[int]:
    answer = [0] * width
    for row_index, row in enumerate(rows):
        while row:
            bit = row & -row
            answer[bit.bit_length() - 1] |= 1 << row_index
            row ^= bit
    return answer


def independent_vectors(vectors: list[int], count: int) -> list[int]:
    leaders: dict[int, int] = {}
    answer: list[int] = []
    for original in vectors:
        value = original
        while value:
            leader = value.bit_length() - 1
            if leader in leaders:
                value ^= leaders[leader]
            else:
                leaders[leader] = value
                answer.append(original)
                break
        if len(answer) == count:
            return answer
    raise ValueError("insufficient independent vectors")


def reduced_basis(vectors: list[int], width: int) -> tuple[list[int], list[int]]:
    work = vectors[:]
    pivots: list[int] = []
    next_row = 0
    for column in range(width):
        pivot = next(
            (i for i in range(next_row, len(work)) if (work[i] >> column) & 1),
            None,
        )
        if pivot is None:
            continue
        work[next_row], work[pivot] = work[pivot], work[next_row]
        for i in range(len(work)):
            if i != next_row and ((work[i] >> column) & 1):
                work[i] ^= work[next_row]
        pivots.append(column)
        next_row += 1
        if next_row == len(work):
            break
    if next_row != len(work):
        raise ValueError("dependent basis")
    return work, pivots


def public_rref(rows: list[int], width: int) -> tuple[list[int], list[int], list[int]]:
    """Return RREF(H), its left row transform, and pivot columns."""
    count = len(rows)
    work = rows[:]
    transform = eye(count)
    pivots: list[int] = []
    next_row = 0
    for column in range(width):
        pivot = next(
            (i for i in range(next_row, count) if (work[i] >> column) & 1),
            None,
        )
        if pivot is None:
            continue
        work[next_row], work[pivot] = work[pivot], work[next_row]
        transform[next_row], transform[pivot] = transform[pivot], transform[next_row]
        for i in range(count):
            if i != next_row and ((work[i] >> column) & 1):
                work[i] ^= work[next_row]
                transform[i] ^= transform[next_row]
        pivots.append(column)
        next_row += 1
        if next_row == count:
            break
    if next_row != count:
        raise ValueError(f"H has rank {next_row}, expected {count}")
    return work, transform, pivots


def matrix_digest(rows: list[int], width: int) -> str:
    digest = hashlib.sha256()
    octets = (width + 7) // 8
    for row in rows:
        digest.update(row.to_bytes(octets, "little"))
    return digest.hexdigest()


def hash_blocks(message: bytes) -> tuple[int, list[int], int]:
    output = int.from_bytes(hashlib.shake_256(message).digest(N // 8), "little")
    block_mask = (1 << K) - 1
    pieces = [(output >> (i * K)) & block_mask for i in range(GAMMA)]
    folded = 0
    for piece in pieces:
        folded ^= piece
    return output, pieces, folded


def verify(message: bytes, signature: int, public: dict[str, list[int]]) -> bool:
    if signature < 0 or signature >> N:
        return False
    if not LOW <= signature.bit_count() <= HIGH:
        return False
    _, _, folded = hash_blocks(message)
    return linear_map(public["H"], signature) == linear_map(public["Y"], folded)


def permutation_matrices(size: int, rng: random.Random) -> tuple[list[int], list[int]]:
    permutation = list(range(size))
    rng.shuffle(permutation)
    inverse_permutation = [0] * size
    for i, image in enumerate(permutation):
        inverse_permutation[image] = i
    p = [1 << permutation[i] for i in range(size)]
    p_inverse = [1 << inverse_permutation[i] for i in range(size)]
    if product(p, p_inverse) != eye(size):
        raise AssertionError("invalid permutation inverse")
    return p, p_inverse


def generate_ssd1760(seed: int) -> tuple[dict[str, list[int]], dict[str, object]]:
    """Reconstruct one fresh full advertised standard-mode key."""
    rng = random.Random(seed)

    # A companion orientation for x^4+x+1; it has exact order 15.
    c4 = [0b0010, 0b0100, 0b1000, 0b0011]
    if matrix_power(c4, R_ORDER) != eye(4):
        raise AssertionError("order-15 block failed")
    if any(matrix_power(c4, divisor) == eye(4) for divisor in (1, 3, 5)):
        raise AssertionError("order-15 block has a proper-divisor order")
    c = block_diagonal([c4[:] for _ in range((K - L) // 4)])

    d_blocks = []
    d_variant_ones = 0
    for _ in range(L // 2):
        variant = rng.randrange(2)
        d_variant_ones += variant
        d_blocks.append([0b11, 0b10] if variant == 0 else [0b01, 0b11])
    d_matrix = block_diagonal(d_blocks)
    g = block_diagonal([d_matrix, c])

    f, f_inverse, f_draws = draw_gl(K, rng)
    m = product(f_inverse, product(g, f))
    identity = eye(K)
    if matrix_power(m, M_ORDER) != identity or matrix_power(m, R_ORDER) == identity:
        raise AssertionError("M does not have the required even order")
    q = matrix_xor(identity, matrix_power(m, R_ORDER))
    if rank(q) != L_HALF or product(q, q) != [0] * K:
        raise AssertionError("Q has the wrong rank or is not square-zero")
    if product(m, q) != q or product(q, m) != q:
        raise AssertionError("M does not fix the noise space pointwise")

    r_left, _, r_draws = draw_gl(K, rng)
    gen1_draws = 0
    while True:
        gen1_draws += 1
        r0, _, _ = draw_gl(K, rng)
        alpha0 = 2 * rng.randrange(R_ORDER) + 1
        middle = matrix_xor(identity, matrix_power(m, alpha0), product(r0, q))
        y_tilde = product(r_left, middle)
        if rank(y_tilde) == K_PRIME:
            break
        if gen1_draws == 64:
            raise RuntimeError("Gen1 did not produce the rank required by Gen2")

    y, selected = independent_rows(y_tilde, K_PRIME)
    # Section V-4's storage optimization chooses one odd alpha_1 in
    # [1, phi-9] and then four consecutive odd exponents.
    alpha1 = 2 * rng.randrange((M_ORDER - 9 + 1) // 2) + 1
    alphas = [alpha1 + 2 * index for index in range(GAMMA)]
    power_blocks = [matrix_power(m, alpha) for alpha in alphas]
    s_rows = [
        sum(power_blocks[block][i] << (block * K) for block in range(GAMMA))
        for i in range(K)
    ]
    p, p_inverse = permutation_matrices(N, rng)
    h = product(product(y, s_rows), p_inverse)
    if rank(y) != K_PRIME or rank(h) != K_PRIME:
        raise AssertionError("public matrices are not full row rank")

    noise_basis = independent_vectors(columns(q, K), L_HALF)
    noise_rref, noise_pivots = reduced_basis(noise_basis, K)

    public = {"H": h, "Y": y}
    private: dict[str, object] = {
        "M": m,
        "Q": q,
        "alphas": alphas,
        "P": p,
        "noise_rref": noise_rref,
        "noise_pivots": noise_pivots,
        "alpha0": alpha0,
        "selected_rows": selected,
        "f_draws": f_draws,
        "r_draws": r_draws,
        "gen1_draws": gen1_draws,
        "d_variant_ones": d_variant_ones,
    }
    return public, private


def reduce_mod_noise(vector: int, basis: list[int], pivots: list[int]) -> int:
    for row, pivot in zip(basis, pivots):
        if (vector >> pivot) & 1:
            vector ^= row
    return vector


def honest_signature(
    public: dict[str, list[int]], private: dict[str, object]
) -> tuple[bytes, int, int]:
    m = private["M"]
    alphas = private["alphas"]
    p = private["P"]
    basis = private["noise_rref"]
    pivots = private["noise_pivots"]
    assert all(isinstance(value, list) for value in (m, alphas, p, basis, pivots))
    inverse_powers = [matrix_power(m, (-alpha) % M_ORDER) for alpha in alphas]

    # The lower bound 491 also satisfies the literal second comparison in
    # Algorithm 3's printed while-condition; Algorithm 4 itself starts at 473.
    signing_low = max(LOW, DISTANCE - MU)
    for counter in range(256):
        message = f"SSD1760 independent honest signature {counter}".encode()
        _, pieces, _ = hash_blocks(message)
        reduced = []
        for inverse_power, piece in zip(inverse_powers, pieces):
            u_piece = linear_map(inverse_power, piece)
            reduced.append(reduce_mod_noise(u_piece, basis, pivots))
        u_prime = sum(piece << (i * K) for i, piece in enumerate(reduced))
        signature = linear_map(p, u_prime)
        if signing_low <= signature.bit_count() <= HIGH:
            if not verify(message, signature, public):
                raise AssertionError("honest signing relation failed ordinary verification")
            return message, signature, counter + 1
    raise RuntimeError("no in-range honest signature found")


def prepare_public_solve(public_h: list[int]) -> dict[str, object]:
    """Prepare two independently checked public affine-completion paths."""
    reduced_h, transform, pivots = public_rref(public_h, N)
    pivot_set = set(pivots)
    free_positions = [index for index in range(N) if index not in pivot_set]
    if len(pivots) != K_PRIME or len(free_positions) != N - K_PRIME:
        raise AssertionError("unexpected pivot/free-coordinate dimensions")

    # Extract the original 242-by-242 pivot-column submatrix and invert it.
    pivot_matrix = [
        sum(((row >> pivot) & 1) << index for index, pivot in enumerate(pivots))
        for row in public_h
    ]
    pivot_inverse = inverse(pivot_matrix)
    if pivot_inverse is None:
        raise AssertionError("pivot-column submatrix is singular")
    if product(pivot_matrix, pivot_inverse) != eye(K_PRIME):
        raise AssertionError("pivot-column inverse check failed")
    if product(transform, public_h) != reduced_h:
        raise AssertionError("tracked RREF transform check failed")
    for row_index, pivot in enumerate(pivots):
        for column_index, other_pivot in enumerate(pivots):
            expected = int(row_index == column_index)
            if ((reduced_h[row_index] >> other_pivot) & 1) != expected:
                raise AssertionError("RREF pivot columns are not the identity")
    return {
        "reduced_h": reduced_h,
        "transform": transform,
        "pivots": pivots,
        "free_positions": free_positions,
        "pivot_inverse": pivot_inverse,
    }


def completion(
    public_h: list[int], prepared: dict[str, object], target: int, free_mask: int
) -> int:
    reduced_h = prepared["reduced_h"]
    transform = prepared["transform"]
    pivots = prepared["pivots"]
    pivot_inverse = prepared["pivot_inverse"]
    assert all(
        isinstance(value, list)
        for value in (reduced_h, transform, pivots, pivot_inverse)
    )

    transformed_target = linear_map(transform, target)
    signature = free_mask
    for index, pivot in enumerate(pivots):
        bit = ((transformed_target >> index) & 1) ^ (
            (reduced_h[index] & free_mask).bit_count() & 1
        )
        signature |= bit << pivot

    # Cross-check through a separate inverse of the original pivot columns.
    right_hand_side = target ^ linear_map(public_h, free_mask)
    direct_pivots = linear_map(pivot_inverse, right_hand_side)
    direct_signature = free_mask
    for index, pivot in enumerate(pivots):
        direct_signature |= ((direct_pivots >> index) & 1) << pivot
    if direct_signature != signature:
        raise AssertionError("RREF and pivot-submatrix completions disagree")
    if linear_map(public_h, signature) != target:
        raise AssertionError("public affine completion failed its equation")
    return signature


def candidate_message(label: bytes, counter: int) -> bytes:
    return (
        b"ePrintAudit/SSD1760/public-reproducer/v1/"
        + label
        + b"/"
        + counter.to_bytes(8, "big")
    )


def forge(
    public: dict[str, list[int]], prepared: dict[str, object], limit: int
) -> tuple[bytes, int, dict[str, object]]:
    free_positions = prepared["free_positions"]
    pivots = prepared["pivots"]
    assert isinstance(free_positions, list) and isinstance(pivots, list)
    free_mask = sum(1 << index for index in free_positions[:FREE_ONES])

    for counter in range(limit):
        message = candidate_message(b"attack", counter)
        _, _, folded = hash_blocks(message)
        target = linear_map(public["Y"], folded)
        signature = completion(public["H"], prepared, target, free_mask)
        if verify(message, signature, public):
            return message, signature, {
                "public_hash_queries": counter + 1,
                "distinct_candidate_messages": counter + 1,
                "free_variables": len(free_positions),
                "pivots": len(pivots),
                "fixed_free_weight": FREE_ONES,
                "pivot_weight": signature.bit_count() - FREE_ONES,
                "signature_weight": signature.bit_count(),
                "timer_start_semantics": "immediately before prepare_public_solve/RREF",
                "timer_end_semantics": "after ordinary verifier accepts the first candidate",
            }
    raise RuntimeError(f"no accepted completion in {limit} candidate messages")


def exact_weight_control(
    public: dict[str, list[int]],
    prepared: dict[str, object],
    desired_weight: int,
    limit: int = 4096,
) -> dict[str, object]:
    free_positions = prepared["free_positions"]
    assert isinstance(free_positions, list)
    free_weight = desired_weight - K_PRIME // 2
    if not 0 <= free_weight <= len(free_positions):
        raise AssertionError("endpoint diagnostic requested an invalid free weight")
    free_mask = sum(1 << index for index in free_positions[:free_weight])
    for counter in range(limit):
        message = candidate_message(f"endpoint-{desired_weight}".encode(), counter)
        _, _, folded = hash_blocks(message)
        target = linear_map(public["Y"], folded)
        signature = completion(public["H"], prepared, target, free_mask)
        if signature.bit_count() == desired_weight:
            return {
                "equation_holds": linear_map(public["H"], signature) == target,
                "ordinary_verifier_accepts": verify(message, signature, public),
                "message_trials": counter + 1,
                "free_weight": free_weight,
                "pivot_weight": signature.bit_count() - free_weight,
                "signature_weight": signature.bit_count(),
                "message_sha256": hashlib.sha256(message).hexdigest(),
            }
    raise RuntimeError(f"no exact-weight {desired_weight} diagnostic in {limit} messages")


def choose_in_range_flip(signature: int, h: list[int]) -> int:
    original_weight = signature.bit_count()
    for column in range(N):
        next_weight = original_weight + (1 if ((signature >> column) & 1) == 0 else -1)
        nonzero_column = any((row >> column) & 1 for row in h)
        if LOW <= next_weight <= HIGH and nonzero_column:
            return column
    raise RuntimeError("no usable one-bit control found")


def binomial_acceptance_probability() -> dict[str, object]:
    numerator = sum(
        math.comb(K_PRIME, weight)
        for weight in range(LOW - FREE_ONES, HIGH - FREE_ONES + 1)
    )
    denominator = 1 << K_PRIME
    getcontext().prec = 60
    probability = Decimal(numerator) / Decimal(denominator)
    expected = Decimal(denominator) / Decimal(numerator)
    return {
        "numerator": numerator,
        "denominator": denominator,
        "decimal": format(probability, ".16f"),
        "expected_message_queries": format(expected, ".10f"),
    }


def gen1_alpha_r_diagnostic(private: dict[str, object], seed: int) -> dict[str, object]:
    m = private["M"]
    q = private["Q"]
    assert isinstance(m, list) and isinstance(q, list)
    identity = eye(K)
    if matrix_xor(identity, matrix_power(m, R_ORDER)) != q:
        raise AssertionError("Q != I+M^r")
    rng = random.Random(seed)
    r0, _, draws = draw_gl(K, rng)
    candidate = matrix_xor(identity, matrix_power(m, R_ORDER), product(r0, q))
    candidate_rank = rank(candidate)
    if candidate_rank > L_HALF or candidate_rank >= K_PRIME:
        raise AssertionError("alpha_0=r diagnostic did not expose the rank ceiling")
    return {
        "allowed_alpha0": R_ORDER,
        "candidate_rank": candidate_rank,
        "rank_upper_bound": L_HALF,
        "required_rank": K_PRIME,
        "cannot_supply_required_rows": True,
        "diagnostic_full_rank_draws": draws,
    }


def execute(seed: int, wrong_key_seed: int, message_limit: int = 64) -> dict[str, object]:
    public, private = generate_ssd1760(seed)
    honest_message, honest_sig, honest_trials = honest_signature(public, private)

    # The attack-stage timing boundary is immediately before this public RREF.
    # Runtime is measured externally so committed reference JSON stays stable.
    prepared = prepare_public_solve(public["H"])
    attack_message, forged_sig, attack_metrics = forge(public, prepared, message_limit)
    if attack_message == honest_message:
        raise AssertionError("forgery message is not fresh")

    changed_message = attack_message + b"/changed"
    if hash_blocks(changed_message)[2] == hash_blocks(attack_message)[2]:
        raise AssertionError("changed-message control collided after folding")
    changed_message_rejected = not verify(changed_message, forged_sig, public)

    flip = choose_in_range_flip(forged_sig, public["H"])
    changed_signature = forged_sig ^ (1 << flip)
    changed_signature_rejected = not verify(attack_message, changed_signature, public)

    wrong_public, _ = generate_ssd1760(wrong_key_seed)
    wrong_key_rejected = not verify(attack_message, forged_sig, wrong_public)
    zero_signature_rejected = not verify(attack_message, 0, public)
    controls = {
        "changed_message_rejected": changed_message_rejected,
        "changed_in_range_signature_rejected": changed_signature_rejected,
        "independent_wrong_key_rejected": wrong_key_rejected,
        "zero_signature_rejected": zero_signature_rejected,
    }
    if not all(controls.values()):
        raise AssertionError(f"ordinary-verifier control failed: {controls}")

    endpoints = {
        str(weight): exact_weight_control(public, prepared, weight)
        for weight in (LOW - 1, LOW, HIGH, HIGH + 1)
    }
    expected_endpoint_results = {
        str(LOW - 1): False,
        str(LOW): True,
        str(HIGH): True,
        str(HIGH + 1): False,
    }
    for weight, expected in expected_endpoint_results.items():
        if endpoints[weight]["ordinary_verifier_accepts"] is not expected:
            raise AssertionError(f"ordinary-verifier endpoint {weight} disagrees")
        if endpoints[weight]["equation_holds"] is not True:
            raise AssertionError(f"endpoint {weight} does not isolate the weight check")

    probability = binomial_acceptance_probability()
    pivots = prepared["pivots"]
    free_positions = prepared["free_positions"]
    assert isinstance(pivots, list) and isinstance(free_positions, list)
    result: dict[str, object] = {
        "schema": SCHEMA,
        "status": "PASS",
        "banner": "ATTACK REPRODUCTION: PASS",
        "scheme": "SSD / IACR ePrint 2022/1698",
        "target_pdf_sha256": PAPER_SHA256,
        "parameter_set": "SSD1760 standard mode",
        "parameters": {
            "n": N,
            "gamma": GAMMA,
            "k": K,
            "k_prime": K_PRIME,
            "d": DISTANCE,
            "omega": OMEGA,
            "mu": MU,
            "ordinary_verifier_weight_interval": [LOW, HIGH],
        },
        "seeds": {
            "primary_structured_key": seed,
            "independent_wrong_key": wrong_key_seed,
        },
        "workers": 1,
        "key_generation": {
            "construction": "independent reconstruction of printed standard-mode Gen1/Gen2",
            "hash_instantiation": "SHAKE256 with explicit message bytes, 1760-bit output",
            "H_rank": rank(public["H"]),
            "Y_rank": rank(public["Y"]),
            "fold_rank": K,
            "Y_after_fold_rank": rank(public["Y"]),
            "H_sha256": matrix_digest(public["H"], N),
            "Y_sha256": matrix_digest(public["Y"], K),
            "wrong_H_sha256": matrix_digest(wrong_public["H"], N),
            "alpha0": private["alpha0"],
            "consecutive_odd_alphas": private["alphas"],
            "F_full_rank_draws": private["f_draws"],
            "R_full_rank_draws": private["r_draws"],
            "Gen1_rank_draws": private["gen1_draws"],
            "D_second_variant_blocks": private["d_variant_ones"],
        },
        "honest_conformance": {
            "separate_from_attack_stage": True,
            "ordinary_verifier_accepted": True,
            "message_trials": honest_trials,
            "signature_weight": honest_sig.bit_count(),
            "satisfies_both_algorithm_3_lower_bound_readings": (
                honest_sig.bit_count() >= max(LOW, DISTANCE - MU)
            ),
            "message_sha256": hashlib.sha256(honest_message).hexdigest(),
        },
        "attack": {
            "classification": "zero-signing-query existential fresh-message forgery",
            "signing_queries": 0,
            "secret_key_used": False,
            "uses_only_public_key_and_message_hashes": True,
            "ordinary_verifier_accepted": True,
            "message_sha256": hashlib.sha256(attack_message).hexdigest(),
            "signature_sha256": hashlib.sha256(
                forged_sig.to_bytes(N // 8, "little")
            ).hexdigest(),
            "random_oracle_probability": probability,
            "accepted_pivot_weight_interval": [LOW - FREE_ONES, HIGH - FREE_ONES],
            "rref_and_pivot_inverse_agree": True,
            **attack_metrics,
        },
        "controls": controls,
        "control_details": {
            "changed_signature_bit": flip,
            "changed_signature_weight": changed_signature.bit_count(),
            "equation_valid_weight_endpoints": endpoints,
        },
        "specification_diagnostics": {
            "gen1_alpha0_equals_r": gen1_alpha_r_diagnostic(private, seed ^ 0x535344),
            "algorithm_3_lower_bound": (
                "printed while-condition uses both omega-mu and d-mu; prose discusses omega-mu"
            ),
            "ssd2744_table_inconsistency": "k_prime is printed as both 377 and 337",
            "concrete_hash_unspecified": True,
            "author_implementation_available": False,
        },
        "timer_semantics": {
            "attack_stage": (
                "start immediately before public RREF; stop after the first candidate "
                "passes ordinary verification"
            ),
            "complete_process": (
                "includes structured primary key, honest conformance, public attack, "
                "independent wrong key, and equation-valid endpoint controls"
            ),
            "committed_json_contains_wall_clock_values": False,
            "reason": "external timing keeps reference output deterministic",
        },
        "claim_scope": {
            "proved_in_random_oracle_model": (
                "constant-probability existential forgery by distinct-message search"
            ),
            "valid_key_condition": "rank(H)=rank(Y)=242",
            "not_claimed": [
                "universal forgery",
                "forgery for every fixed preselected message",
                "LVK mode",
                "rank-deficient or malformed keys",
                "an unconditional property of SHAKE256",
            ],
        },
        "public_linear_algebra": {
            "pivots": len(pivots),
            "free_coordinates": len(free_positions),
            "technique": "Gaussian elimination/systematic-form affine completion",
            "technique_novelty_claimed": False,
        },
    }
    return result
