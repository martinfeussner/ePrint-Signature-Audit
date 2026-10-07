# ePrint Signature Audit

An AI-assisted campaign to identify and practically audit digital signature schemes
published on the IACR Cryptology ePrint Archive for which no prior public attack
against the scheme was located.

The project counts only practical, full-parameter, design-level signing compromises:
secret-key recovery with fresh signing, equivalent signing-key or witness recovery
with fresh signing, or efficient fresh-message forgery. Known cryptanalytic methods
are welcome when their application to the target scheme appears previously
unreported.

## Dashboard

| Metric | Count |
|---|---:|
| Schemes identified | 8 |
| Known attacks excluded | 1 |
| Schemes audited | 7 |
| No practical attack found | 5 |
| Practical design attacks | 2 |
| Independently reproduced attacks | 2 |

## Practical design attacks

| Scheme | ePrint | Family | Result | Technique | Parameters | Cost | Status |
|---|---|---|---|---|---|---|---|
| [D-James](attacks/d-james/) | 2026/1650 v5 | HFE-minus-IP with Dragon bilinear terms | Equivalent signing-key recovery with fresh signing | Hidden matrix-Gabidulin recovery and rank-metric completion | q5/128 | about 490 s, 224.28 MB, 1 worker | AI-reproduced; human review pending |
| [Miraidon-S](attacks/miraidon-s/) | 2026/997 v4 | MinRank identification | Universal fresh-message forgery | Zero witness and rank-zero factors | Levels I, III, V | 0.49 s Level-I forge | AI-reproduced; human review pending |

The first catalog record is ATLAS (ePrint 2026/2323), excluded because it is
the published form of MORNING-ATLAS/NGCC sign-15 and a practical ATLAS-128
equivalent-key recovery with fresh-message forgery is already public.

ECLIPSE (ePrint 2026/2312) received a scoped paper-level audit after a
scheme-specific search, including its unnamed Section 5 PRISM identity, located
no prior public attack as of 2026-10-07. Tests of its structured-primality,
scalar-verifier, canonical-encoding, derived-key, and deterministic-stream
surfaces found no practical full-parameter signing compromise. The exact
implementation remains private, so source-specific decoder and serializer
checks are reserved for a release-time recheck.

ASTRA-Sign (ePrint 2026/1290 v2) completed a scoped audit with no practical
signing compromise. QC-pooled transcript statistics, sparse-ratio and CRT
recovery, exact coordinate descent, and refined q-ary PGE/GBA/dissection
estimates all screened negative under the project gate. Its only nominal
sub-128 list-work point requires about `2^126.90` stored entries, and
memory-feasible variants remain above `2^132.85` elementary work.

miniMEDS (ePrint 2026/1323 v1) completed a scoped audit with no practical
signing compromise. Its source accepts internally dependent, Scale-compatible
walks that paper Algorithm 6 rejects, but full-dimension controls retained
key-dependent canonical forms and supplied no dual response or fresh-message
forgery. Direct transfers of the public MEDS and tensor/MCE attacks remained
impractical at the exact parameter sets.

[D-James](attacks/d-james/) (ePrint 2026/1650 v5) exposes an expanded
two-dimensional generalized Gabidulin code in its public Dragon cross tensor.
A public three-column pencil recovers the hidden field basis; rank decoding
and linear completion then recover an equivalent HFE-IP/Dragon signer for the
advertised q5/128 row. The primary execution and two independently generated
fresh keys each produced a nonzero fresh-message signature accepted by all 73
public equations, while the same signature failed all 256 salts of a changed
message. A full run takes about 490 seconds on one worker and at most 224.28 MB
in the recorded executions. The result is scoped to the literal v5 algebra and
all-ones target under a pinned nonnormative transcript interface because no
conforming v5 implementation or byte format is public.

[Miraidon-S](attacks/miraidon-s/) (ePrint 2026/997 v4) admits a
public-key-only universal fresh-message forgery because verification accepts
the zero MinRank witness and rank-zero factors without enforcing the stated
nonzero, exact-rank relation. Independent implementations reproduced the
attack at Levels I, III, and V. The result is independently AI-reproduced;
independent human verification is pending.

Lithium (ePrint 2026/1790 v1) completed a scoped audit with no practical
signing compromise. Its mode-260 challenge sampler uses one-byte indices at
degree 512, making 198 challenge positions unreachable and lowering a generic
zero-response target-preimage forgery to about `2^203.66` message trials. This
is a specification-level claim-margin failure, but it remains computationally
infeasible and is not classified as a successful attack by this project.

UFOs (ePrint 2026/1607 v1) keeps the publicly attacked Frobenius-UOV
construction but replaces the exponent schedules used by the known forgery.
The predecessor attack was reproduced at reduced characteristic, then the
replacement Level-I schedule was exhaustively screened under the published
attack model. No practical full-parameter signing compromise was found. The
catalog preserves the attacked lineage and a narrow recheck for the unpublished
hardening analysis.

See [methodology](METHODOLOGY.md), [attack-history methodology](docs/attack-history-methodology.md), [publication policy](docs/publication-policy.md), [reproducibility](REPRODUCIBILITY.md), and [AI disclosure](AI_DISCLOSURE.md).
