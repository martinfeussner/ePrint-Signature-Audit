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
| Schemes identified | 20 |
| Known attacks excluded | 1 |
| Schemes audited | 19 |
| No practical attack found | 13 |
| Practical design attacks | 6 |
| Verified practical design attacks | 6 |
| Independently reproduced attacks | 6 |

## Practical design attacks

| Scheme | ePrint | Family | Result | Technique | Parameters | Cost | Status |
|---|---|---|---|---|---|---|---|
| [D-James](attacks/d-james/) | 2026/1650 v5 | HFE-minus-IP with Dragon bilinear terms | Equivalent signing-key recovery with fresh signing | Hidden matrix-Gabidulin recovery and rank-metric completion | q5/128 | about 490 s, 224.28 MB, 1 worker | Verified; independently AI-reproduced |
| [Miraidon-S](attacks/miraidon-s/) | 2026/997 v4 | MinRank identification | Universal fresh-message forgery | Zero witness and rank-zero factors | Levels I, III, V | 0.49 s Level-I forge | Verified; independently AI-reproduced |
| [Bittersweet](attacks/bittersweet/) | 2026/397 v1 | LWR-based MPC-in-the-head | Exact secret-key recovery with fresh signing | Accepted carry comparisons, interval intersection, and weighted LLL/Babai CVP | Level I `d=32` | 313.95 s public pipeline, 236,760 KiB, 1 worker | Verified; independently AI-reproduced |
| [Poulakis--Rolland v2](attacks/poulakis-rolland-v2/) | 2012/134 v2 | Composite-order pairing signature | One-query universal fresh-message forgery | Public-scalar point transport with pairing-factor compensation | 2046-bit group order, 2048-bit field | 2.35 s transport, 17.5 MB peak, 1 worker | Verified; independently AI-reproduced |
| [Yagisawa quaternion signature](attacks/yagisawa-order-four/) | 2010/352 final | Multivariate quaternion-ring signature | Zero-query fresh-message forgery | Order-four challenge orbit and a vanishing homogeneous perturbation | `d=2`, `r=3`, `m=448`, 21-bit `q` | 1.79 ms forge; 113 s full setup/control; 19.5 MiB, 1 worker | Verified; independently AI-reproduced |
| [Random-split St-Gen](attacks/random-split-stgen/) | 2016/391 | Random-split Staircase-Generator code signature | Zero-query existential fresh-message forgery | Verification-first affine cancellation in the public valid-error relation | PS1 and PS2 | At most 1.867 ms forge; 20.5 MiB peak, 1 worker | Verified; independently AI-reproduced |

## Known attack exclusions

The first catalog record is ATLAS (ePrint 2026/2323), excluded because it is
the published form of MORNING-ATLAS/NGCC sign-15 and a practical ATLAS-128
equivalent-key recovery with fresh-message forgery is already public.

## Completed audits without a practical attack

| Scheme | ePrint | Scope | Disposition |
|---|---|---|---|
| ECLIPSE | 2026/2312 v1 | Paper-level construction; private implementation unavailable | No practical signing compromise; source recheck if released |
| ASTRA-Sign | 2026/1290 v2 | Exact QC-MDGM parameter and recovery screens | Best memory-feasible routes remain infeasible |
| miniMEDS | 2026/1323 v1 | Paper and pinned source, including MEDS attack transfers | Source/paper mismatch found; no signer or forgery |
| Lithium | 2026/1790 v1 | IRS, transcript, DSD, and encoding paths | Challenge-index margin loss remains infeasible |
| UFOs | 2026/1607 v1 | Hardened exponent schedules and predecessor transfer | No practical transfer to the replacement schedules |
| FALCON++ | 2026/2226 v1 | Both advertised rows; sampler moment and recovery studies | No practical basis or signing recovery |
| SOLMAE | 2026/817 v1 | Both full rows; sampler, verifier, and NTRU recovery studies | No practical current-design signing compromise |
| HFE-IP-minus | 2024/1706 v2 | Primary HFEfIP-128 row under a reviewed research-profile completion | No practical signer; exact implementation unavailable |
| Plover | 2024/401 v1 | RLWE and NTRU variants, including a `2^20`-signature study | No practical completion or forgery |
| KuMQuat | 2024/490 v3 | Paper binding and four size-matched Level-I source profiles | No practical witness recovery or forgery |
| MandaRain | 2024/490 v3 | Rain-3/Rain-4 relations and transcript routes | No practical key recovery or forgery |
| SPECK | 2025/923 v2 | Five Low source profiles and the paper-only High family | No practical secret permutation or forgery |
| Loquat / Loquat* | 2024/868 v1 | Intended paper design across Legendre, FRI/BCS, binding, and Griffin routes | No practical faithful-design signing compromise |

### Audit summaries

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

FALCON++ (ePrint 2026/2226 v1) completed a scoped audit of both advertised
rows with no practical signing compromise. Two of 16 ordinary V-117 keys
falsified the stated support-wide `tau_B <= 1` premise and showed near-total
correction clipping. Independent full-row moment and recovery studies did not
turn that calibration failure into an attacker-visible NTRU basis, equivalent
signer, or fresh-message forgery.

SOLMAE (ePrint 2026/817 v1) completed a scoped audit of both full parameter
rows with no practical current-design signing compromise. The audit replayed
20,480 accepted signatures, screened verifier algebra, and profiled 8,192
completed keys. Ordinary-signature sampler tests and NTRU recovery estimates
produced no secret key, publicly constructible equivalent signer, or efficient
fresh-message forgery.

HFE-IP-minus (ePrint 2024/1706 v2) completed a bounded audit centered on the
HFEfIP-128 row under a reviewed research-profile completion. Public polar,
DGS, MinRank, residual, radical, pencil, and related-HFE transfer routes did
not yield a practical signer. No exact author implementation or known-answer
test was available, so this is a row-level campaign closeout rather than a
security proof or an exhaustive result for all eight rows.

Plover (ePrint 2024/401, operational v1 pin) completed a scoped audit of its
RLWE and NTRU variants with no practical signing compromise. The implemented
row retained material paper/source decomposition, proof-support, and verifier
caveats. Bounded RLWE completion closed negative, while a `2^20`-signature
NTRU study found reproducible public joint moments but no practical phase
recovery, short affine completion, equivalent signer, or fresh-message
forgery.

KuMQuat (ePrint 2024/490 v3) completed a bounded audit under its ordinary
randomized signing model. Paper-level binding and the four size-matched
Level-I profiles in the observed pre-v3 source were reviewed. Direct
hidden-seed routes remained above `2^121` work, tested MQOM and grouping
transfers did not apply, and no MQ preimage, equivalent signing witness, or
efficient fresh-message forgery was obtained. Source-to-v3 conformance remains
a stated caveat.

MandaRain (ePrint 2024/490 v3) completed a bounded audit of Rain-3 and Rain-4
under ordinary randomized signing. The reviewed relations bind any accepted
witness to an actual key preimage, and no transcript route removed the fresh
VOLE mask. The best located Rain-3 route costs about `2^160.6` equivalent Rain
evaluations, no located Rain-4 method beats exhaustive search, and no practical
key recovery, equivalent signer, or fresh-message forgery was obtained.

SPECK (ePrint 2025/923 v2) completed a scoped audit of all five source-supported
Low profiles and the paper-only High family. The most optimistic generic
code-equivalence transfer remains about `2^120.12` modeled operations for Low
with prohibitive storage, and the reviewed PECK/PKP and transcript routes did
not produce a practical secret permutation, reusable signer, or fresh-message
forgery. The conclusion is bounded by the absence of an exact High
implementation or author-bound v2 source release.

Loquat and Loquat* (ePrint 2024/868 v1) completed a scoped intended-design
audit with no practical signing compromise. Review of the cumulative
transcript and all-fold verifier closed the fixed-random-point Legendre,
FRI/BCS, binding, and Griffin routes without a practical endpoint. The
strongest retained paper findings are proof-margin caveats and infeasible
transfers; no secret, equivalent signer, or efficient faithful-paper-verifier
forgery was obtained. The pinned proof of concept materially differs from the
paper and does not establish the design result.

## Verified attack summaries

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
attack at Levels I, III, and V. The result passed the technical, history,
independent-reproduction, and publication-review gates and is verified.

[Bittersweet](attacks/bittersweet/) (ePrint 2026/397 v1) leaks an oriented
strict comparison with a fixed product buffer in every accepted optimized
repetition. Sixteen accepted Level-I `d=32` signatures give 310,752 public
comparisons; intersecting them into 747 modular intervals and solving a
160-row weighted LLL/Babai CVP recovered the complete signing key and enabled
a distinct-message signature. Untouched run-003 and independent fresh-context
run-005 each passed exact 11/11 key comparison, all 747 public interval and
rounded-output checks, and ordinary fresh-signature verification. The result
uses a pinned canonical paper-level realization because no author byte format
or implementation is public. It passed the technical, history,
independent-reproduction, and publication-review gates and is verified.

[Poulakis--Rolland v2](attacks/poulakis-rolland-v2/) (ePrint 2012/134,
revision `20150430:055329`) publishes the scalar representation of every
hash-to-group output. From one ordinary signature, an attacker rescales its
point by a public ratio and a message-dependent power of `g`, while copying
the scalar response unchanged. Full-parameter modified Tate-pairing
implementations accepted fresh-message forgeries at the published 2046-bit
group-order and 2048-bit-field endpoint, including an independent fresh-key
reproduction; strict mutation and subgroup controls rejected. The generic
public-scalar BLS rescaling technique is credited to prior work, and no exact
v2 attack was located in the searches performed as of 2026-10-09.

[Yagisawa's quaternion signature](attacks/yagisawa-order-four/) (ePrint
2010/352, revision `20100627:124304`) lets a signature choose the quaternion
`R` that generates the verifier's challenge points. Setting `R=i` confines
every challenge to the four-point orbit `{1,i,-1,-i}`. For the fresh message
`E=2k`, an attacker publicly composes the public polynomial with left
multiplication by `i` and adds the nonzero homogeneous perturbation
`(x2^13,0,0,0)`, which vanishes on that orbit but makes the verifier's
preliminary inequality pass at `RE=-2j`. Two independent standard-library
implementations generated all 2,240 public coefficients at the claimed
`d=2`, `r=3`, `m=448` row, accepted the zero-query forgery for every challenge
class, accepted an honest signature on the same message, and rejected strict
controls. The report claims no novelty for the general vanishing-polynomial
principle; no exact-target attack was located in searches completed as of
2026-10-09.

[Random-split St-Gen](attacks/random-split-stgen/) (ePrint 2016/391) signs a
raw binary-vector tuple $z=(z_1,z_2)$ and accepts when
$e_i=\sigma G_{i,\mathrm{pub}}+z_i$ belongs blockwise to a public valid-error
relation. A zero-query attacker chooses public valid errors and any $\sigma$,
then solves the same equation for $z$. Characteristic-two cancellation makes
both printed full rows accept, including nonzero-$\sigma$ controls. A 2017
NTNU thesis supervised by target coauthor Danilo Gligoroski confirms that the
raw vectors are the scheme's intended signing and verification interface; the
claim excludes any separately added document-hashing wrapper. The report
credits verification-first existential forgery as a classical technique, and
no exact-target attack was located in searches completed as of 2026-10-09.

See [methodology](METHODOLOGY.md), [attack-history methodology](docs/attack-history-methodology.md), [publication policy](docs/publication-policy.md), [reproducibility](REPRODUCIBILITY.md), and [AI disclosure](AI_DISCLOSURE.md).
