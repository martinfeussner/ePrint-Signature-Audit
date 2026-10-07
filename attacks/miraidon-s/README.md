# Miraidon-S zero-witness forgery

Miraidon-S in ePrint 2026/997 v4 admits a public-key-only universal forgery.
The verifier accepts a factorization `Q=LR`, which proves only
`rank(Q)<=r`, without checking that `Q` has exact rank `r` or that the
MinRank coefficient vector is nonzero. Setting the coefficient vector and
rank factors to zero, then taking `v=u`, answers both protocol branches and
removes the advertised Fiat--Shamir guessing cost.

Status: **AI-discovered and independently AI-reproduced; independent human
verification pending.**

| Field | Result |
|---|---|
| Scheme | Miraidon-S |
| Paper | ePrint 2026/997 v4 |
| Attack paper | [PDF](paper/attack.pdf) and [LaTeX source](paper/attack.tex) |
| Authors | Ryann Cartor and Freeman Slaughter |
| Family | MinRank identification Fiat--Shamir signature |
| Competition history | No direct NIST or NGCC submission located; MIRA/MiRitH/Mirath and CROSS are distinct related schemes |
| Attack | Public-key-only universal fresh-message forgery |
| Technique | Conventional zero-witness/missing exact-membership check; no technique originality claimed |
| Affected rows | Levels I, III, and V |
| Signing queries | 0 |
| Level-I forge time | 0.49 seconds |
| Full Level-I reproduction | 4.94 seconds, including honest key generation and controls |
| Peak RAM | 22 MiB |
| CPU / workers | AMD EPYC Processor under KVM / 1 |
| Layer | Design |
| Conditions | The intended verifier with Algorithm 6's evident `c0`/`c1` aggregate correction |
| Independent reproduction | Passed on all three rows in the checked-in standard-library implementation |
| Human verification | Pending |
| Last attack-history search | 2026-10-07 |

## Impact

An attacker can choose any fresh message and create a signature accepted by
the intended ordinary verifier without a secret key, a signing oracle, hash
grinding, or exponential computation.  The attack works for every public key
and every published parameter row.

## Why the verifier accepts

The intended witness is a nonzero vector `a` for which

```text
E = sum_i a_i M_i
```

has exact rank `r`.  In a protocol round, the honest prover commits to
`Q=S E T` and factors it as `Q=LR`.  The verifier's `b=0` branch reconstructs
`Q` from `L` and `R`, but it performs no exact-rank or full-rank-factor check.
Problem 1 is also stated with `rank(E)<=r` and omits `a!=0`, making the zero
vector a solution to the printed homogeneous relation.

The attacker sets

```text
a = 0,  E = 0,  Q = 0,  L = 0,  R = 0,  v = u.
```

For arbitrary valid invertible `S,T`, arbitrary `u`, and every nonzero first
challenge `xi`, define

```text
X = sum_i u_i S M_i T.
```

Both verifier branches then compute the same delayed response:

```text
sum_i v_i S M_i T = X = X + xi Q.
```

The attacker can therefore prepare a transcript that can answer either second
challenge.  Parallel repetition, fixed-weight challenges, Fiat--Shamir hashes,
the seed tree, and the Merkle tree do not restore soundness.

The paper itself exposes the mismatch: its completeness argument describes
`Q=LR` as having rank *at most* `r`, while the soundness discussion relies on
`Q` being constrained to exact rank `r`.

## Verifier correction used by the reproducers

Algorithm 6 swaps its two final commitment checks.  Signing makes `c0` a
Merkle root of the `c0_i` leaves and `c1` a flat aggregate of the `c1_i`
values, while the printed verifier applies the operations in the opposite
order. Literal Algorithm 6 is undefined on the declared signature: it requests
unavailable `c0_i` leaves and applies a proof from the `c0` tree to `c1_i`
values.

The reproducers apply the evident consistency correction:

```text
c0 = VerifyTree({c0_i}_{i not in I}, Proof)
c1 = com(c1_1, ..., c1_t).
```

The zero-witness forgery then passes.  This is the verifier behavior required
for the honest scheme to work and is also consistent with the optimization
text surrounding Algorithms 4--6.

## Reproduction

Both reproducers use only Python's standard library. The primary run builds an
exact compressed Algorithm-5 Level-I key and cleanly separates attacker inputs
from the secret key:

```bash
python3 attacks/miraidon-s/reproduce.py \
  --output attacks/miraidon-s/result.json
```

It performs the following full Level-I checks:

1. generate a valid compressed Algorithm-5 public key with an exact-rank
   secret relation;
2. produce and verify an honest signature;
3. forge a signature on a distinct attacker-chosen message without giving the
   attacker the secret key;
4. invoke the same ordinary verifier and require acceptance;
5. mutate the message and require rejection; and
6. enable an exact-rank factor check, require rejection of the forgery, and
   require continued acceptance of the honest signature.

Successful output contains:

```json
{
  "honest_signature_accepts": true,
  "zero_witness_forgery_accepts": true,
  "mutated_message_rejects": true,
  "zero_witness_forgery_rejected_by_hardened_rank_check": true
}
```

The checked-in `reference-output.json` records the deterministic public-key,
message, and signature digests.  Its timing fields are machine-dependent.

The independent all-row run uses a separately implemented signer, attacker,
and verifier, forges two fresh messages at every published row, and exercises
message-mutation and exact-rank controls:

```bash
python3 attacks/miraidon-s/reproduce-all-rows.py \
  --rows L1 L3 L5 \
  --output attacks/miraidon-s/all-rows-result.json
```

It should report `"all_rows_pass": true`. The checked-in
`all-rows-reference-output.json` records the complete expected checks; timing
fields are machine-dependent.

## Scope and repair

The paper specifies the signature at the algorithm level and provides no full
Sign/Verify implementation or byte encoding.  The reproducer instantiates the
abstract hashes, seed path, and Merkle proof with unambiguous conventional
encodings.  The attack is algebraic and does not depend on those choices.  It
also passes both branches of the authors' pinned interactive proof-of-concept
at the exact Level-I dimensions.

A verifier can block this attack by requiring exact rank `r` for every opened
`Q`, for example by checking that both disclosed factors have rank `r`.
Honest responses pass this check in the reproducer.  A complete repair should
also require a nonzero or projectively normalized coefficient vector in
Problem 1, correct Algorithm 6's swapped commitment checks, and update the
soundness proof.

## Prior art and provenance

The project located no previous public attack against exact Miraidon-S in its
searches as of 2026-10-07.  Generic MinRank algorithms and the published
fixed-weight five-pass forgery methods were already known and were accounted
for by the target; this attack does not use them.  No technique-originality
claim is made for noticing a missing nonzero or exact-membership check.

- Target paper: [Miraidon: MinRank Identification](https://eprint.iacr.org/2026/997)
- Pinned source: [FreemanSlaughter/Miraidon at `289beaa`](https://github.com/FreemanSlaughter/Miraidon/tree/289beaa76a75e8500faa6fa75e9c76796fe9f633)
- Attack paper: [PDF](paper/attack.pdf) and [LaTeX source](paper/attack.tex)

Discovery, attack-history search, cryptanalysis, implementation, adversarial
review, and independent reproduction were AI-assisted.  The independent
reproduction used a separate specialist agent and implementation.  Independent
human verification is pending.
