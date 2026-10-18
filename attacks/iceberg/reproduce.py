#!/usr/bin/env python3
"""Self-contained, source-faithful scalar reproduction of the Iceberg attack.

No external elliptic-curve package is used.  The attacker computation receives
only public transcript data, the corrupted member-1 scalar shares, the three
honest oracle responses, and secrets of the attacker-controlled outer signer.
Fixture-wide secrets are used only for post-recovery assertions.
"""

from hashlib import sha256
from itertools import combinations
import json


FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
INF = None


def inv(x, modulus):
    return pow(x % modulus, -1, modulus)


def point_add(p, q):
    if p is INF:
        return q
    if q is INF:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % FIELD_P == 0:
            return INF
        slope = (3 * x1 * x1) * inv(2 * y1, FIELD_P) % FIELD_P
    else:
        slope = (y2 - y1) * inv(x2 - x1, FIELD_P) % FIELD_P
    x3 = (slope * slope - x1 - x2) % FIELD_P
    y3 = (slope * (x1 - x3) - y1) % FIELD_P
    return (x3, y3)


def point_neg(p):
    return INF if p is INF else (p[0], (-p[1]) % FIELD_P)


def point_mul(k, p=G):
    k %= ORDER_N
    out = INF
    addend = p
    while k:
        if k & 1:
            out = point_add(out, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return out


def b32(x):
    return int(x).to_bytes(32, "big")


def compressed(p):
    assert p is not INF
    return bytes((2 | (p[1] & 1),)) + b32(p[0])


def extended(p):
    return bytes(33) if p is INF else compressed(p)


def xonly(p):
    assert p is not INF
    return b32(p[0])


def lift_x_even(x):
    if x >= FIELD_P:
        return INF
    c = (pow(x, 3, FIELD_P) + 7) % FIELD_P
    y = pow(c, (FIELD_P + 1) // 4, FIELD_P)
    if pow(y, 2, FIELD_P) != c:
        return INF
    if y & 1:
        y = FIELD_P - y
    return (x, y)


def tagged_hash(tag, data):
    tag_hash = sha256(tag.encode("ascii")).digest()
    return sha256(tag_hash + tag_hash + data).digest()


def tagged_scalar(tag, data):
    return int.from_bytes(tagged_hash(tag, data), "big") % ORDER_N


def deterministic_nonzero(tag, data):
    value = tagged_scalar(tag, data)
    assert value != 0
    return value


def interpolate_at_zero(indices, values):
    assert len(indices) == len(values) and len(set(indices)) == len(indices)
    result = 0
    for j, xj in enumerate(indices):
        weight = 1
        for k, xk in enumerate(indices):
            if j != k:
                weight = weight * (-xk) * inv(xj - xk, ORDER_N) % ORDER_N
        result = (result + weight * values[j]) % ORDER_N
    return result


def rank_mod(matrix):
    a = [[v % ORDER_N for v in row] for row in matrix]
    rows = len(a)
    cols = len(a[0]) if rows else 0
    pivot_row = 0
    for col in range(cols):
        pivot = next((r for r in range(pivot_row, rows) if a[r][col]), None)
        if pivot is None:
            continue
        a[pivot_row], a[pivot] = a[pivot], a[pivot_row]
        scale = inv(a[pivot_row][col], ORDER_N)
        a[pivot_row] = [(scale * v) % ORDER_N for v in a[pivot_row]]
        for r in range(rows):
            if r != pivot_row and a[r][col]:
                factor = a[r][col]
                a[r] = [(a[r][c] - factor * a[pivot_row][c]) % ORDER_N for c in range(cols)]
        pivot_row += 1
        if pivot_row == rows:
            break
    return pivot_row


def solve_square(matrix, rhs):
    size = len(matrix)
    assert size and all(len(row) == size for row in matrix) and len(rhs) == size
    a = [[v % ORDER_N for v in row] + [rhs[r] % ORDER_N] for r, row in enumerate(matrix)]
    for col in range(size):
        pivot = next((r for r in range(col, size) if a[r][col]), None)
        assert pivot is not None
        a[col], a[pivot] = a[pivot], a[col]
        scale = inv(a[col][col], ORDER_N)
        a[col] = [(scale * v) % ORDER_N for v in a[col]]
        for r in range(size):
            if r != col and a[r][col]:
                factor = a[r][col]
                a[r] = [(a[r][c] - factor * a[col][c]) % ORDER_N for c in range(size + 1)]
    return [a[r][-1] for r in range(size)]


def matrix_vector(matrix, vector):
    return [sum(a * b for a, b in zip(row, vector)) % ORDER_N for row in matrix]


def bip340_verify(pubkey_x32, message32, signature64):
    if len(pubkey_x32) != 32 or len(message32) != 32 or len(signature64) != 64:
        return False
    px = int.from_bytes(pubkey_x32, "big")
    r = int.from_bytes(signature64[:32], "big")
    s = int.from_bytes(signature64[32:], "big")
    if px >= FIELD_P or r >= FIELD_P or s >= ORDER_N:
        return False
    public = lift_x_even(px)
    if public is INF:
        return False
    challenge = tagged_scalar("BIP0340/challenge", signature64[:32] + pubkey_x32 + message32)
    nonce = point_add(point_mul(s), point_mul(-challenge, public))
    return nonce is not INF and nonce[1] % 2 == 0 and nonce[0] == r


def bip340_sign_with_scalar(adjusted_secret, public_x32, message32):
    assert point_mul(adjusted_secret) == lift_x_even(int.from_bytes(public_x32, "big"))
    aux = sha256(b"Iceberg independent reproduction BIP340 aux").digest()
    mask = tagged_hash("BIP0340/aux", aux)
    t = bytes(a ^ b for a, b in zip(b32(adjusted_secret), mask))
    k0 = tagged_scalar("BIP0340/nonce", t + public_x32 + message32)
    assert k0 != 0
    nonce0 = point_mul(k0)
    k = (-k0) % ORDER_N if nonce0[1] & 1 else k0
    nonce = point_mul(k)
    challenge = tagged_scalar("BIP0340/challenge", xonly(nonce) + public_x32 + message32)
    signature = xonly(nonce) + b32((k + challenge * adjusted_secret) % ORDER_N)
    assert bip340_verify(public_x32, message32, signature)
    return signature


def dealer_seeds():
    root = sha256(b"Iceberg independent reproduction dealer root").digest()
    # For t=2, lexicographic subset ranks 0..3 are singleton members 1..4.
    return {
        member: tagged_hash("Iceberg/dealer", root + bytes((4, 2)) + (member - 1).to_bytes(4, "big"))
        for member in range(1, 5)
    }


def rss_summands(seeds, label):
    return {a: tagged_scalar("VPSS/prf", seeds[a] + label) for a in range(1, 5)}


def rss_share(summands, member):
    # L_{\{a\}}(member)=(a-member)/a; member does not hold seed a=member.
    return sum(
        value * (a - member) * inv(a, ORDER_N)
        for a, value in summands.items()
        if a != member
    ) % ORDER_N


def sharing_for(seeds, label):
    summands = rss_summands(seeds, label)
    secret = sum(summands.values()) % ORDER_N
    shares = {member: rss_share(summands, member) for member in range(1, 5)}
    assert all(interpolate_at_zero(pair, [shares[i] for i in pair]) == secret
               for pair in combinations(range(1, 5), 2))
    assert interpolate_at_zero([2, 3, 4], [shares[2], shares[3], shares[4]]) == secret
    return secret, shares


def keyagg(group_public, cosigner_public):
    key_list = compressed(group_public) + compressed(cosigner_public)
    pks_hash = tagged_hash("KeyAgg list", key_list)
    # With two distinct keys, BIP327 makes the second distinct key coefficient 1.
    assert group_public != cosigner_public
    group_coef = tagged_scalar("KeyAgg coefficient", pks_hash + compressed(group_public))
    aggregate = point_add(point_mul(group_coef, group_public), cosigner_public)
    assert aggregate is not INF and group_coef != 0
    return group_coef, aggregate


def make_context(candidate_id, group_r1_point, group_r2_point, b1, aggregate_public, message):
    label = candidate_id.to_bytes(4, "big")
    u1 = deterministic_nonzero("Iceberg/review-cosigner-nonce-1", label)
    u2 = deterministic_nonzero("Iceberg/review-cosigner-nonce-2", label)
    total1 = point_add(group_r1_point, point_mul(u1))
    total2 = point_add(point_mul(b1, group_r2_point), point_mul(u2))
    assert total1 is not INF and total2 is not INF
    b0 = tagged_scalar(
        "MuSig/noncecoef",
        extended(total1) + extended(total2) + xonly(aggregate_public) + message,
    )
    raw_final_nonce = point_add(total1, point_mul(b0, total2))
    # libsecp256k1 substitutes G on infinity; deterministic contexts avoid it.
    assert raw_final_nonce is not INF
    eta = -1 if raw_final_nonce[1] & 1 else 1
    challenge = tagged_scalar(
        "BIP0340/challenge",
        xonly(raw_final_nonce) + xonly(aggregate_public) + message,
    )
    return {
        "candidate_id": candidate_id,
        "u1": u1,
        "u2": u2,
        "b0": b0,
        "eta": eta,
        "challenge": challenge,
        "raw_final_nonce": raw_final_nonce,
    }


def run():
    seeds = dealer_seeds()
    sid = sha256(b"Iceberg independent reproduction single SID").digest()
    queried_message = sha256(b"Iceberg independent reproduction queried message").digest()
    fresh_message = sha256(b"Iceberg independent reproduction fresh message").digest()
    assert queried_message != fresh_message

    group_secret, key_shares = sharing_for(seeds, b"Iceberg/keygen")
    nonce1_label = (1).to_bytes(32, "big") + sid
    nonce2_label = (2).to_bytes(32, "big") + sid
    group_r1, nonce1_shares = sharing_for(seeds, nonce1_label)
    group_r2, nonce2_shares = sharing_for(seeds, nonce2_label)
    assert group_secret and group_r1 and group_r2

    group_public = point_mul(group_secret)
    group_r1_public = point_mul(group_r1)
    group_r2_public = point_mul(group_r2)

    # PreRound oracle outputs for honest 2,3,4 form valid degree-one codewords.
    honest_members = [2, 3, 4]
    aggregate_r1_public = point_mul(
        interpolate_at_zero(honest_members, [nonce1_shares[i] for i in honest_members])
    )
    aggregate_r2_public = point_mul(
        interpolate_at_zero(honest_members, [nonce2_shares[i] for i in honest_members])
    )
    assert aggregate_r1_public == group_r1_public
    assert aggregate_r2_public == group_r2_public

    b1 = tagged_scalar(
        "Iceberg/noncecoef",
        extended(aggregate_r1_public) + extended(aggregate_r2_public) + extended(group_public),
    )
    assert b1 != 0

    cosigner_secret = deterministic_nonzero("Iceberg/review-cosigner-key", b"controlled signer")
    cosigner_public = point_mul(cosigner_secret)
    group_coef, aggregate_public = keyagg(group_public, cosigner_public)
    key_sign = -1 if aggregate_public[1] & 1 else 1

    # Select the first lexicographic triple of deterministic, distinct attacker
    # contexts that is full-rank and exercises both nonce-parity branches.
    candidates = []
    chosen = None
    for candidate_id in range(64):
        context = make_context(
            candidate_id,
            aggregate_r1_public,
            aggregate_r2_public,
            b1,
            aggregate_public,
            queried_message,
        )
        context["row"] = [
            context["eta"] % ORDER_N,
            (context["eta"] * b1 * context["b0"]) % ORDER_N,
            (key_sign * context["challenge"] * group_coef) % ORDER_N,
        ]
        candidates.append(context)
        for triple in combinations(candidates, 3):
            rows = [entry["row"] for entry in triple]
            if rank_mod(rows) == 3 and len({entry["eta"] for entry in triple}) == 2:
                chosen = list(triple)
                break
        if chosen is not None:
            break
    assert chosen is not None

    matrix = [entry["row"] for entry in chosen]
    true_unknowns = [group_r1, group_r2, group_secret]
    full_group_partials = []
    honest_responses = []
    outer_signatures = []

    # One different honest SignRound oracle is consumed for each context.
    for context, honest_member in zip(chosen, honest_members):
        eta = context["eta"]
        b0 = context["b0"]
        challenge = context["challenge"]

        def member_partial(member):
            return (
                eta * nonce1_shares[member]
                + eta * b1 * b0 * nonce2_shares[member]
                + key_sign * challenge * group_coef * key_shares[member]
            ) % ORDER_N

        corrupt_partial = member_partial(1)
        honest_partial = member_partial(honest_member)
        honest_responses.append(honest_partial)

        # Exact t=2 weights at zero for the pair {1,i}:
        # lambda_1=i/(i-1), lambda_i=-1/(i-1).
        lambda_corrupt = honest_member * inv(honest_member - 1, ORDER_N) % ORDER_N
        lambda_honest = (-inv(honest_member - 1, ORDER_N)) % ORDER_N
        group_partial = (
            lambda_corrupt * corrupt_partial + lambda_honest * honest_partial
        ) % ORDER_N
        assert group_partial == interpolate_at_zero(
            [1, honest_member], [corrupt_partial, honest_partial]
        )
        assert group_partial == sum(a * b for a, b in zip(context["row"], true_unknowns)) % ORDER_N
        full_group_partials.append(group_partial)

        cosigner_partial = (
            eta * (context["u1"] + b0 * context["u2"])
            + key_sign * challenge * cosigner_secret
        ) % ORDER_N
        final_s = (group_partial + cosigner_partial) % ORDER_N
        observed_signature = xonly(context["raw_final_nonce"]) + b32(final_s)
        assert bip340_verify(xonly(aggregate_public), queried_message, observed_signature)
        outer_signatures.append(observed_signature)

    recovered = solve_square(matrix, full_group_partials)
    assert recovered == true_unknowns
    recovered_r1, recovered_r2, recovered_group_secret = recovered
    assert point_mul(recovered_r1) == aggregate_r1_public
    assert point_mul(recovered_r2) == aggregate_r2_public
    assert point_mul(recovered_group_secret) == group_public

    aggregate_secret = (group_coef * recovered_group_secret + cosigner_secret) % ORDER_N
    adjusted_aggregate_secret = aggregate_secret if key_sign == 1 else (-aggregate_secret) % ORDER_N
    fresh_signature = bip340_sign_with_scalar(
        adjusted_aggregate_secret, xonly(aggregate_public), fresh_message
    )
    fresh_valid = bip340_verify(xonly(aggregate_public), fresh_message, fresh_signature)
    assert fresh_valid and len(fresh_signature) == 64

    # Negative control 1: two generic equations leave one scalar dimension.
    two_equation_rank = rank_mod(matrix[:2])
    assert two_equation_rank == 2

    # Negative control 2: repeating an outer context cannot give rank three.
    repeated_context_rank = rank_mod([matrix[0], matrix[0], matrix[1]])
    assert repeated_context_rank == 2

    # Negative control 3: ignoring BIP340 final-nonce parity changes the public
    # equations on this mixed-parity transcript.
    parity_blind_matrix = [
        [1, (b1 * entry["b0"]) % ORDER_N,
         (key_sign * entry["challenge"] * group_coef) % ORDER_N]
        for entry in chosen
    ]
    parity_blind_true_residual = [
        (lhs - rhs) % ORDER_N
        for lhs, rhs in zip(matrix_vector(parity_blind_matrix, true_unknowns), full_group_partials)
    ]
    assert any(parity_blind_true_residual)

    # Negative control 4: an individual honest response is not the group's
    # partial.  Treating it as such yields a scalar inconsistent with X_group.
    wrong_recovery = solve_square(matrix, honest_responses)
    assert wrong_recovery != true_unknowns
    assert point_mul(wrong_recovery[2]) != group_public

    game_accounting = {
        "corrupt_members": [1],
        "threshold_t": 2,
        "pre_round_queries": [
            {"member": member, "sid": sid.hex()} for member in honest_members
        ],
        "sign_round_queries": [
            {
                "member": member,
                "sid": sid.hex(),
                "message": queried_message.hex(),
                "outer_context_candidate": context["candidate_id"],
            }
            for member, context in zip(honest_members, chosen)
        ],
        "queried_message_honest_signers": honest_members,
        "forgery_message": fresh_message.hex(),
        "forgery_message_honest_signers": [],
        "win_bound_t_minus_corrupt": 1,
        "win_inequality": "0 < 2 - 1",
        "zero_honest_participation_in_forgery": True,
    }

    attack_checks = {
        "selected_context_candidates": [entry["candidate_id"] for entry in chosen],
        "selected_nonce_parities": [entry["eta"] for entry in chosen],
        "three_by_three_rank": rank_mod(matrix),
        "group_nonce_1_recovered": recovered_r1 == group_r1,
        "group_nonce_2_recovered": recovered_r2 == group_r2,
        "group_signing_secret_recovered": recovered_group_secret == group_secret,
        "all_three_queried_outer_signatures_valid": all(
            bip340_verify(xonly(aggregate_public), queried_message, signature)
            for signature in outer_signatures
        ),
        "fresh_signature_bytes": len(fresh_signature),
        "fresh_signature_valid": fresh_valid,
    }
    negative_controls = {
        "two_equation_rank": two_equation_rank,
        "repeated_context_rank": repeated_context_rank,
        "parity_blind_true_solution_has_nonzero_residual": any(parity_blind_true_residual),
        "raw_honest_responses_do_not_recover_group_key": point_mul(wrong_recovery[2]) != group_public,
    }
    output = {
        "result": "PASS: three same-message contexts recovered the Iceberg group key and produced a fresh BIP340 forgery",
        "verdict": "PASS",
        "profile": "ICEBERG-SECP256K1-T2-N4-MU3-NU2-DEPTH2-BIP327-BIP340-SID32-ARTIFACT-B2F87CB",
        "checks": {
            "all_three_queried_outer_signatures_valid": attack_checks["all_three_queried_outer_signatures_valid"],
            "fresh_message_bip340_forgery_valid": attack_checks["fresh_signature_valid"],
            "group_signing_secret_recovered": attack_checks["group_signing_secret_recovered"],
            "one_sign_query_per_honest_member": all(
                sum(query["member"] == member for query in game_accounting["sign_round_queries"]) == 1
                for member in (2, 3, 4)
            ),
            "ordinary_bip340_verifier_used": True,
            "same_message_and_sid_across_queries": True,
            "three_by_three_system_full_rank": attack_checks["three_by_three_rank"] == 3,
            "zero_honest_participation_on_forged_message": game_accounting["zero_honest_participation_in_forgery"],
        },
        "digests": {
            "fresh_signature_sha256": sha256(fresh_signature).hexdigest(),
            "queried_message_sha256": sha256(queried_message).hexdigest(),
        },
        "environment": {
            "dependencies": "Python 3.8+ standard library",
            "workers": 1,
        },
        "attack": {
            "corrupt_members": 1,
            "honest_pre_round_queries": 3,
            "honest_signing_queries_on_forged_message": 0,
            "signing_queries": 3,
        },
        "construction_checks": {
            "dealer_and_vpss_tags_source_faithful": True,
            "inner_nonce_transcript_source_order": "ext33(R1)||ext33(R2)||ext33(X_group)",
            "outer_nonce_transcript": "ext33(T1)||ext33(T2)||xonly32(P)||msg32",
            "challenge_transcript": "xonly32(R)||xonly32(P)||msg32",
            "group_key_coefficient_bip327": True,
            "aggregate_key_and_nonce_parities_applied": True,
            "honest_nonce_codeword_indices": honest_members,
        },
        "attack_checks": attack_checks,
        "negative_controls": negative_controls,
        "game_accounting": game_accounting,
        "public_fingerprints": {
            "group_public_compressed": compressed(group_public).hex(),
            "aggregate_public_xonly": xonly(aggregate_public).hex(),
            "fresh_signature_sha256": sha256(fresh_signature).hexdigest(),
        },
    }
    return output


def main():
    print(json.dumps(run(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
