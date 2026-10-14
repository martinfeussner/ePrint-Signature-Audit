# Full Distance, Short Detour: A One-Query Forgery against FDSD

> **Status: `VERIFIED_ATTACK`.** The full-parameter retained-key attack,
> adversarial review, five-key fresh-context independent reproduction, final
> exact-target history recheck, and independent Publication Reviewer gate
> passed. All required publication gates passed.
>
> **AI disclosure and review status.** This audit used the OpenAI model
> Daybreak Blue at the ultra reasoning level. OpenAI Codex generated and
> selected this title and intentionally chose “Full Distance, Short Detour” as
> wordplay contrasting the scheme's full-distance decoding premise with the
> short public linear detour used by the forgery. OpenAI Codex performed the
> reconstruction, cryptanalysis, implementation, experiments, and technical
> writing. A separately tasked AI agent performed adversarial review on the
> retained key, and a fresh-context AI agent independently reproduced the
> attack on five fresh keys. This is AI review and AI reproduction, not human
> verification. No independent human verification was performed or required.

This report records a practical public-only, one-signing-query fresh-message
forgery against the complete Level-I row of Abdelhaliem Babiker's
[*A Signature Scheme from Full-Distance Syndrome Decoding*](https://eprint.iacr.org/2023/1956),
IACR ePrint 2023/1956.

The report is at [`paper/attack.pdf`](paper/attack.pdf), and the self-contained
public reproducer is under [`reproducer/`](reproducer/).

| Field | Result |
|---|---|
| Publication status | `VERIFIED_ATTACK`; all required publication gates passed |
| Scheme | Full-Distance Syndrome Decoding signature (FDSD) |
| Target | IACR ePrint 2023/1956, sole 2023-12-24 object observed as of 2026-10-14 |
| Target author | Abdelhaliem Babiker |
| Construction family | Binary code-based hash-and-sign signature with a structured public parity-check matrix |
| Competition history | No exact NIST, NGCC, or other signature-competition identity located |
| Attack result | Public-only one-query fresh-message forgery |
| Technique | Recover the hidden 125-column support by membership in `Col(R)`, reconstruct a public map `U` with `Hstar*U=R`, transfer one queried signature, then search a 25-bit weight-correction space |
| Technique provenance | Standard GF(2) elimination, affine transformation, and Gray-code search concretely applied to FDSD; no general-method novelty claim |
| Affected parameters | Level I: `(n,k,L,epsilon,theta,d)=(1600,400,125,5,25,343)` |
| Signing queries | 1 ordinary signature on a non-target message; 0 target-message queries |
| Primary result | 1/1 retained fresh key; target forgery accepted after 3,657 candidates |
| Adversarial review | 8/8 additional frozen targets accepted on the retained key; 1,337 solutions in one complete `2^25` probe |
| Independent cross-key result | 5/5 fresh OS-random keys forged; one query/key; 0 target queries; all controls rejected |
| Independent cost | 0.829--13.376 s attack/key; 41.85 s complete five-key wrapper; 22,016 KiB peak RSS; 1 worker |
| Primary cost | 0.627329 s internal attack time; 1.70 s measured wall; 19,456 KiB peak RSS; 1 worker |
| Public reproducer smoke test | Fresh Level-I key generated; public-only forgery accepted; four controls rejected; 1 worker |
| Recorded CPU/workers | AMD EPYC Processor; 1 worker for every reported run |
| Layer | Design-level structured public key and ordinary verification equation |
| Source status | No author implementation or test vectors located; the audit uses an explicitly identified independent mathematical reconstruction |
| Reproduction status | Primary replay, retained-key adversarial review, and five-key fresh-context independent reproduction passed |
| AI provenance | Daybreak Blue at ultra reasoning; AI cryptanalysis, implementation, adversarial review, and technical writing |
| Human verification | Not performed; not required for classification or publication |
| Last attack-history search | 2026-10-14; no previous public attack against the exact scheme located; bounded moderate-high confidence |

## Impact

The public matrix exposes the part of the signing map needed to move an
ordinary signature from one message syndrome to another. On the retained full
Level-I key, an attacker used one signature on an unrelated message and
produced a weight-343 signature accepted on a source-frozen message that had
not been signed. The route bypasses the advertised syndrome-decoding problem.

The result is classified as `VERIFIED_ATTACK`. Its evidence covers one
retained key, five fresh independent keys, and a separate public-package smoke
key. The technical, practical, adversarial, independent-reproduction,
final-history, and independent Publication Reviewer gates all passed.

## Attack at a glance

The ordinary verifier checks, over GF(2),

```text
weight(sigma) = 343
Hstar * sigma = R * h + R_head * zeta,
```

where `R_head` is the first 25 columns of `R`.

Key generation leaves 125 columns of `Hstar` unchanged. Those columns span
exactly the public 125-dimensional space `Col(R)`. The attacker builds a basis
for `R`, tests all 1,600 public columns for membership, and obtains the hidden
coordinate set. Solving 125 public linear systems yields columns `U_j` with

```text
Hstar * U_j = R_j.
```

Given one queried signature `(sigma0,zeta0)` on hash `h0` and a fresh target
hash `h1`, choose any 25-bit `a`, set the tail of `delta` to
`h0_tail + h1_tail`, and compute

```text
sigma1 = sigma0 + U * delta
zeta1  = zeta0 + h0_head + h1_head + a.
```

Every `a` satisfies the target syndrome equation. A single-worker reflected
Gray-code walk over at most `2^25` values finds an `a` for which `sigma1` has
the required weight 343.

## Exact target and scope

The target PDF has SHA-256
`394b7a3e4f8d935cfabffd90e17b4c8cdd5708267a14ede67b39c49ab9ead822`;
its extracted text has SHA-256
`8763cd064947c50af81e487a9f7abf294b86893d2596cdff94bb199db33e460a`.

No author implementation, source repository, test vector, or external byte
format was located. The paper is authoritative. The reproducer's
`fdsd_reference.py` is the audit's independently documented paper-level
reconstruction; it is not presented as author code. The attack uses the
ordinary mathematical Verify relation and does not depend on the chosen byte
adapter, a parser, malformed inputs, faults, timing leakage, or weak
randomness.

## Experimental evidence

The primary forger read exactly four public files and exactly one signature
record. An audit hook blocked any other read. It found rank 125 for `R`, found
exactly 125 rank-125 `Hstar` columns in `Col(R)`, and checked all 125 recovered
identities. The forged target passed ordinary Verify. Reusing the query on the
target, changing the message, changing `sigma`, and changing `zeta` rejected.

A separately written adversarial implementation used a different elimination
orientation and both row- and column-oriented verifiers. The same one query
yielded accepted signatures for eight separately frozen targets, requiring
6,351 to 88,507 candidates. A complete `2^25` sweep for one target found 1,337
accepted weight-343 representatives. All weight-preserving signature and
message/`zeta` controls rejected.

A fresh-context AI agent independently implemented the route before reading
the primary lane. It generated five distinct full Level-I keys with separate
OS-random roots, obtained one non-target signature per key, and forged all five
source-frozen targets. Every key had rank 125 for `R` and the recovered
restriction, and exactly 125 public columns in `Col(R)`. Candidate counts were
303, 1,014, 3,865, 199,806, and 19,856,417. The slowest attack took 13.376
seconds; the complete sequential wrapper took 41.85 seconds and 22,016 KiB
peak RSS on one worker. Changed-message, changed-signature, changed-`zeta`,
wrong-key, and unchanged-query-on-target controls rejected for every key.

## Relationship to known techniques and attack history

This report makes no novelty claim for subspace membership, GF(2) linear
algebra, affine signature transformation, or Gray-code enumeration. Its
contribution is their concrete full-parameter application to the preserved
column space in FDSD's public key.

We located no previous public attack against Abdelhaliem Babiker's exact
ePrint 2023/1956 scheme in the searches completed on 14 October 2026. The
official landing page still lists receipt on 24 December 2023 and approval on
25 December 2023, and a current mirror PDF downloaded on 14 October 2026 was
byte-for-byte identical to the frozen target; we located no later revision.

This is a bounded negative result. It cannot exclude private, deleted, or
unindexed work. OpenAlex did not index the target; Semantic Scholar returned
HTTP 429; unauthenticated GitHub code search returned HTTP 401; and the
official all-versions endpoint returned HTTP 403. The final-history handoff
has SHA-256
`623f30f514d8095d558b27475dd6fe8cc122b41f84f455f02bbc79f5707d150c`;
the prior-art manifest has SHA-256
`5ffc63c382d18d2d3437092c8a0f637b256d1269f8f3120455334cc5947f0a25`.

## Reproduction

From the attack package, run:

```bash
python3 reproduce.py
```

`python3 reproduce-all-rows.py` runs the complete affected-row set, which is
the demonstrated Level-I row. The lower-level command
`./reproducer/reproduce.sh` prints the full step-by-step PASS banner.

For compatibility with the repository's metadata schema,
`independent_reproducer_sha256` pins `reproduce-all-rows.py`. That script is an
affected-row wrapper around this package's public implementation; it is not the
separately written five-key implementation. The fresh-context 5/5 result comes
from separately sealed private campaign evidence identified by its handoff,
package-manifest, and run-manifest hashes in `metadata.json`.

The standard-library-only pipeline generates a fresh full Level-I key, retains
no seed or secret, exports only the public key and one ordinary signature,
runs the public forger in a separate process, and submits the result to the
ordinary verifier. A successful run ends with:

```text
================================================
ATTACK REPRODUCTION: PASS
Scheme: Full-Distance Syndrome Decoding
Result: one-query fresh-message forgery
Fresh full Level-I key: GENERATED
Ordinary signing queries: 1
Target-message queries: 0
Public-only attack boundary: PASS
Fresh-message forgery: ACCEPTED
Negative controls: REJECTED
...
================================================
```

See [`reproducer/README.md`](reproducer/README.md) for the exact process and
input boundary. Stable canonical summaries are retained in
[`reference-output.json`](reference-output.json) and
[`all-rows-reference-output.json`](all-rows-reference-output.json).

## Limitations

- The empirical evidence covers the complete Level-I row on one primary and
  five independent fresh keys; it is not a proof of success for every key.
- The attack aborts if `R` lacks rank 125 or if the number/rank of public
  `Hstar` columns in `Col(R)` differs from 125.
- The result is fresh-message forgery, not nominal secret-key recovery.
- No claim is made for the Level-III or Level-V rows.
- No author-standardized implementation or external signature encoding exists
  to test; the reconstruction and adapter choices are explicit.

## Provenance and verification

The technical, practical, adversarial, fresh-context independent-reproduction,
final-history, and independent Publication Reviewer gates passed. The paper,
metadata, reproducer, and canonical reference outputs are covered by
[`SHA256SUMS`](SHA256SUMS). The result is classified as `VERIFIED_ATTACK`.
