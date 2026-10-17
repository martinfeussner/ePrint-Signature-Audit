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
| Schemes identified | 44 |
| Known attacks excluded | 3 |
| Schemes audited | 41 |
| No practical attack found | 26 |
| Verified and independently reproduced practical design attacks | 15 |

## Practical design attacks

| Scheme | ePrint | Family | Result | Technique | Parameters | Cost | Status |
|---|---|---|---|---|---|---|---|
| [D-James](attacks/d-james/) | 2026/1650 v5 | HFE-minus-IP with Dragon bilinear terms | Equivalent signing-key recovery with fresh signing | Hidden matrix-Gabidulin recovery and rank-metric completion | q5/128 | about 490 s, 224.28 MB, 1 worker | Verified; independently AI-reproduced |
| [Miraidon-S](attacks/miraidon-s/) | 2026/997 v4 | MinRank identification | Universal fresh-message forgery | Zero witness and rank-zero factors | Levels I, III, V | 0.49 s Level-I forge | Verified; independently AI-reproduced |
| [Bittersweet](attacks/bittersweet/) | 2026/397 v1 | LWR-based MPC-in-the-head | Exact secret-key recovery with fresh signing | Accepted carry comparisons, interval intersection, and weighted LLL/Babai CVP | Level I `d=32` | 313.95 s public pipeline, 236,760 KiB, 1 worker | Verified; independently AI-reproduced |
| [Poulakis--Rolland v2](attacks/poulakis-rolland-v2/) | 2012/134 v2 | Composite-order pairing signature | One-query universal fresh-message forgery | Public-scalar point transport with pairing-factor compensation | 2046-bit group order, 2048-bit field | 2.35 s transport, 17.5 MB peak, 1 worker | Verified; independently AI-reproduced |
| [Yagisawa quaternion signature](attacks/yagisawa-order-four/) | 2010/352 final | Multivariate quaternion-ring signature | Zero-query fresh-message forgery | Order-four challenge orbit and a vanishing homogeneous perturbation | `d=2`, `r=3`, `m=448`, 21-bit `q` | 1.79 ms forge; 113 s full setup/control; 19.5 MiB, 1 worker | Verified; independently AI-reproduced |
| [Random-split St-Gen](attacks/random-split-stgen/) | 2016/391 | Random-split Staircase-Generator code signature | Zero-query existential fresh-message forgery | Verification-first affine cancellation in the public valid-error relation | PS1 and PS2 | At most 1.867 ms forge; 20.5 MiB peak, 1 worker | Verified; independently AI-reproduced |
| [GLYPH](attacks/glyph/) | 2017/766 final v3 | Ring-LWE/GLP lattice signature with K-floor compression | Zero-query fresh-message forgery | Strict-interior K-floor fixed point | `m=2048`, `n=1024`, `q=59393`, `B=16383`, `omega=16` | 0.077 ms median forge; 52.5 MiB peak, 1 worker | Verified; independently AI-reproduced |
| [TOT](attacks/tot/) | 2013/771 | Multivariate quadratic trapdoor-inversion signature | Zero-query existential raw-vector forgery | Classical signature-first/no-message public-map evaluation | `q=2`, `n=128`, `d=6`, `t=64` | 5.36 ms forge; 19.0 MiB peak, 1 worker | Verified; independently AI-reproduced |
| [Full-Distance Syndrome Decoding](attacks/full-distance-syndrome-decoding/) | 2023/1956 | Structured binary syndrome-decoding signature | One-query fresh-message forgery | Public preserved-column recovery and 25-bit weight correction | Level I `(1600,400,125,5,25,343)` | 0.627 s primary attack; 19 MiB peak, 1 worker | Verified; independently AI-reproduced |
| [Higher-Bit Approximate-ISIS](attacks/higher-bit-approx-isis/) | 2022/1144 | Lattice hash-and-sign with higher-bit approximate trapdoors | Universal zero-query fresh-message forgery | Zero signature vector covered by the Section 6.4 verifier radius | All three Figure 3 “This work” rows | 11.40 s, 61,072 KiB peak, 1 worker | Verified; independently AI-reproduced |
| [SSD](attacks/ssd/) | 2022/1698 | Binary syndrome-decoding signature | Zero-query existential fresh-message forgery | Public systematic completion into the accepted weight interval | Standard SSD1760 `(1760,242,502,484,11,440)` | at most 0.054 s attack per key; 24,576 KiB peak, 1 worker | Verified; independently AI-reproduced |
| [HPPK DS](attacks/hppk-ds/) | 2023/1768 | Polynomial/multivariate signature over dual hidden rings | Zero-query universal fresh-message forgery | Four all-zero `(F,H)` pairs annihilate Equation (28) | All 3 target rows and all 15 benchmark rows | 0.34 s source run; 7,680 KiB peak, 1 worker | Verified; independently AI-reproduced |
| [Jevil](attacks/jevil/) | 2026/1103 rev. 4 | Few-time polynomial/zk-WHIR signature | Equivalent signing-state recovery with fresh-message forgery | Authenticated width-four openings and four-row Reed--Solomon interpolation | `n_star=1023`, `c=4` | 641 queries; 486.90 s recovery; 143,756 KiB peak, 1 recovery worker | Verified; independently AI-reproduced |
| [EagleSignV3](attacks/eaglesignv3/) | 2024/1234 rev. 2 | Fiat--Shamir-with-aborts lattice signature | Ternary secret and equivalent signing-key recovery with fresh-message forgery | Public-`r` centered-wrap labels and ternary feasibility | Paper-level Ring-L2 `(1,1,1024,59393,16,1,16,16384,16384)` | 40,000 signer outputs; 296.09 s independent pipeline; 221,272 KiB peak, 1 worker | Verified; independently AI-reproduced |
| [DualMS 2.0](attacks/dualms-2/) | 2026/1941 retained current body | Rounded two-round Fiat--Shamir lattice multisignature | Public-key-only fresh-message forgery | Zero responses and verifier-hint absorption of reconstruction | Rounded Table-6 `n=32` and `n=1024` | 4 and 1 `Hsig` queries in the independent reproduction; 28.16 s, 252,432 KiB peak, 1 worker | Verified; independently AI-reproduced |

## Known attack exclusions

Three catalog records are excluded by prior public attacks or substantive
exact-target cryptanalysis:

- ATLAS (ePrint 2026/2323) is the published form of MORNING-ATLAS/NGCC
  sign-15, for which a practical ATLAS-128 equivalent-key recovery with
  fresh-message forgery is already public.
- CMSS (ePrint 2006/320) has an exact-target analytical universal forgery in
  Section 5.1.3 of Aymeric Genet's 2017 EPFL thesis. The attack requires
  induced faults while constructing a non-top CMSS subtree. The thesis's
  practical voltage-glitch demonstration was performed on SPHINCS-256, not
  the archived original CMSS implementation; the explicit CMSS analysis still
  controls this campaign's attack-history gate.
- Ye's temporary-key lattice signature (ePrint 2021/002) has a publicly
  acknowledged exact-target structural cryptanalytic failure. The target
  author's direct successor, ePrint 2022/097, states that the structured-response
  defense against quadratic statistical attacks fails and explains the
  product-statistic mechanism. No public practical endpoint was located, but
  this substantive exact-target analysis controls the campaign's history gate.

## Completed audits without a practical attack

| Scheme | ePrint | Scope | Disposition |
|---|---|---|---|
| ECLIPSE | 2026/2312 v2 | Paper-level ordinary signature and shared-key specification delta; exact implementation unavailable | No practical signing compromise; source/composition recheck if released |
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
| BPORS-C+BFP | 2026/2374 v1 | Complete Section 3.5 standard-128f profile | No practical complete-profile signer or forgery |
| CAPSS-Poseidon-3 Default | 2025/061 current | Exact current Poseidon-3 Default row; proof algebra, transcript binding, and primitive transfer | No practical secret, equivalent witness, or fresh-message forgery |
| NTRU+Sign-972 | 2025/612 current | Exact 193-bit row; relative norms, CRT/challenge structure, transcript binding, and rejection leakage | No practical secret, equivalent signer, or fresh-message forgery |
| NIC signature | 2026/1573 v1 | Exact Level-I core relation, wrapper reconstruction, and public structural and solver routes | No practical witness recovery, equivalent signer, or fresh-message forgery |
| SPHINCS-PE | 2026/1708 v1 | Paper-level, source-independent standard 128f at `q_use=2^8`; advertised source unavailable | No practical signer or forgery; reopen on a material specification/source change or a concrete route within `2^45` work |
| MR-DSS | 2022/973 current | Ordinary Category-I clean-room profile; systematic MinRank and invariant protocol routes | No practical signer or forgery; optimized response profile remains underspecified |
| CUTS | 2026/2455 v1 | Standalone base `cuts-128-smallest` under at most two ordinary signing queries; CUTS+C excluded | No practical signer or forgery; independently checked selector bound remains above the `2^45` campaign gate |
| K-LMS | 2026/2372 v1 | Exact principal `n=32,h=10,w=4,L=1` endpoint at source commit `58be56d022422f2f58c15c3542a6fbc930686086`; correct stateful operation; LSH and CHAM-/LEA-/ARIA-TDM mappings kept separate | No practical signer or forgery; reopen only under the listed exact full-round, binding, revision/vector, or prior-art conditions |
| SigRPO-LDR | 2024/1553 current v2 | Exact Goldilocks `D=2048,q=85,e=3,m=58` LDR profile at source commit `99304c22e3ed384d0e227b670d1d7465ed7c4e98`; RPO and Blake3 BCS endpoints kept separate | No practical signer or forgery; exact RPO quotient-leaf defect remains nonqualifying because no DEEP/Horner signing bridge was found |
| ANSA-IBS | 2026/2134 current 2026-10-12 revision | Paper-level external-message IBS-1 at `N=1536`, `q=8380417`, challenge weight 27, and `ZBOUND=2018750`; claimed artifact unavailable | No practical signer or forgery; closest ordinary-RSIS diagnostic is about `2^50` and has no reverse signing bridge |
| Round-Optimal Pairing-Free Blind Signatures | 2026/091 v1/current | Intended Scheme2 relation with P-256 Nyberg--Rueppel issuance, 32-byte SHA-256 map, T-256, Spartan issuance, and R1CS-IPA final proof at source commit `f040bd34004c17fa475cb03e481e94101a98e886` | No practical design-level signer, fresh-message forgery, or one-more forgery within `2^45`; implementation security is outside this public disposition |
| edaBitE Blind Signature | 2026/2473 initial/current | Paper-level base single-issuer ML-DSA-44 profile with edaBitE conversions and general ORAM; issuer-hiding extensions excluded | No practical one-more forgery or reusable signer; reopen for exact source conformance or a qualifying new route |
| ModFalcon | 2019/1456 current v4 | Paper-level ModFalcon-2-512 at `R=Z[x]/(x^512+1)`, `q=12289`, `rho=1512`; SR and conservative KR profiles kept separate | No practical signer or forgery; reopen for an exact completion-row signing bridge, authoritative current endpoint, or another full-row route within `2^45` work |

### Audit summaries

ECLIPSE (ePrint 2026/2312 v2) remains a bounded paper-level audit. Its
2026-10-14 version and history refresh found no prior public exact-target attack
and confirmed that ordinary Sign/Verify, wire format, and primary rows are
unchanged from v1 apart from domain labels. The added MIKE/ECLIPSE shared-key
mode leaves an open joint-security question but supplies no concrete practical
signing route. Earlier structured-primality, scalar-verifier,
canonical-encoding, derived-key, and deterministic-stream screens found no
full-parameter signing compromise. The cited implementation remains private,
so exact source and composition checks remain reopening conditions.

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

BPORS-C+BFP (ePrint 2026/2374 v1) completed a bounded audit of its complete
Section 3.5 standard-128f profile. Exact coverage, counter and address
grinding, disclosure accumulation, pruning and proof binding, and composition
routes yielded no practical secret key, equivalent signer, or fresh-message
forgery. Joint address/encoding sampling prevents fixed-instance screening
from carrying into the complete profile, and the addressed WOTS+/hypertree
wrapper authenticates the reconstructed bottom key. No author implementation
or concrete primitive suite is available, so implementation conformance
remains a reopening condition.

CAPSS-Poseidon-3 Default (ePrint 2025/061, current 2026-09-10 revision)
completed a bounded audit of the exact 19,616-byte Default row. Current-paper
SmallWood algebra, message and transcript binding, the truncated Poseidon OWF,
and XOF/Jive mode separation produced no practical secret, reusable signing
witness, or ordinary-verifier fresh-message forgery. The strongest intended
selective-opening route costs at least `2^128.332` by the paper's theorem, or
about `2^129.258` raw XOF trials with exact challenge acceptance. The paper's
two capacity definitions disagree: the operational one-field digest has a
generic collision boundary near `2^126.798`, but that does not give a practical
fresh-message endpoint. Figure 7 also states an underdetermined interpolation
line; the signature supplies no values or rule for its two missing
coefficients, so the defect is undefined pseudocode rather than an executable
bypass. The result is a bounded audit, not a security proof, and should be
revisited if an authoritative current-row implementation or material revision
resolves the specification gaps or changes the verifier algebra.

NTRU+Sign-972 (ePrint 2025/612, current 2025-12-17 object) completed a
bounded audit of its exact `(n,q,sigma,tau,d)=(972,9721,260.96,38,8)` row.
All three order-two relative norms, the order-three descent, CRT and challenge
structure, message and transcript binding, direct-forgery routes, and a
4,096-signature first-order rejection-leakage screen produced no practical
secret key, equivalent signer, or ordinary-verifier fresh-message forgery.
The strongest residual norm route, for `x -> -x^-1`, still leaves about `2^62`
heuristic candidates after the identified mod-4 filter and supplies no planted-
vector recognizer, norm factorization, or short lift. This is a bounded
campaign closeout, not a security proof, and should be revisited only when one
of those missing steps or another complete fresh-signing route becomes
practical.

NIC signature (ePrint 2026/1573 v1) completed a bounded paper-level audit
centered on the exact Level-I `(k,n,w)=(210,1050,350)` core relation. Two
independently reviewed full-parameter XOR-SAT lanes, one unrestricted and one
enforcing the promised output weights, both returned `INDETERMINATE` at their
fixed five-minute caps without finding a witness on the same declared local
instance. Restricted-alphabet joint ISD, generic heuristic search, and
structural reductions produced no credible route within `2^45` operations and
12 GiB; the strongest exact reduction still leaves about `2^116.951` marginal
candidates. The paper supplies no implementation and does not uniquely specify
the ordinary TCitH/VOLEitH wrapper, public-key encoding, or Level-I VOLEitH
signature length, so a completion profile remains required. No secret key,
equivalent signing witness, fresh signing ability, or efficient fresh-message
forgery was obtained. This is a bounded campaign closeout, not a security
proof; it should be revisited after an authoritative implementation or
material revision, evidence of exploitable non-random key-generation
structure, or a concrete joint solver within the recorded resource limits.

SPHINCS-PE (ePrint 2026/1708 v1) completed a bounded, source-independent
paper-level audit of the standard 128f row with `q_use=2^8`. The reconstructed
full verifier links the prepared upper certificate and online lower opening
through one global address space, leaving no free boundary root or detachable
certificate. The strongest construction-specific route, pooled FORS coverage
at a reused lower position, has independently reproduced covered mass
`A_PE = 2^-130.701751...` even after granting all `2^56` preparations and
`2^64` signing rows. A `2^45` digest grind therefore contributes at most about
`2^-85.70` success. Other reviewed routes either reduce to the same coverage
event, lack a qualifying endpoint, or require generic component work from
about `2^64` to `2^128`; key recovery remains near `2^128`. Observable episode
collisions and cache, rollback, cloning, and quota-overrun observations do not
produce a conforming fresh-message signer.
The advertised author repository was unavailable, so this
result makes no implementation-conformance or benchmark claim. Reopen only
for a material paper revision, erratum, implementation, or test vector that
changes the verifier semantics; a concrete bias, dependence, alias, or
occupancy error yielding a legitimate fresh-message route within `2^45`
work; a practical full-parameter primitive or composition break; a change to
the fixed-count or state semantics that makes additional pooling, rollback,
cloning, or quota overuse part of ordinary conforming use; or new exact-target
prior art.

MR-DSS (ePrint 2022/973, current 2022-09-21 revision) completed a bounded
audit of the ordinary Category-I row
`(lambda,q,m,n,k,r,tau,s)=(128,16,16,16,142,4,128,256)` under a reviewed
clean-room profile. The best optimistic generic equivalent-witness estimate
was about `2^155.61` bit operations, while invariant cut-and-choose routes
bottomed out at the exact `2^128` soundness boundary. The paper does not fully
specify the optimized response seed, commitment openings, or wire rules, so
the review used a conservative beta-independent completion and makes no
author-implementation compatibility claim. No practical secret recovery,
equivalent signing witness, or efficient fresh-message forgery was obtained.
Reopen after an authoritative implementation, test vector, clarification, or
revision fixes the optimized-response semantics; after a concrete
full-parameter MinRank recovery or public weak-key route enters the `2^45`
campaign region; or when new exact-target prior art appears.

CUTS (ePrint 2026/2455 v1) completed a bounded audit of standalone base
`cuts-128-smallest` at `(n,h,w,L,S,r,s)=(16,15,5,88,176,0,0)`, with at most
two ordinary signing queries; CUTS+C was excluded. Independent exact
arithmetic proves `lambda_2 > 101.25` and `(2^45+1)p_2 < 2^-56`. The paper's
stronger 128.6-bit certificate was not independently reproduced. The direct
two-disclosure, selector, primitive, seed, address, transcript, tree, and
chain routes yielded no secret-key recovery with fresh signing, equivalent
signer, or accepted fresh-message forgery. This is a bounded campaign result,
not a security proof. Reopen on a selector, source, or parameter change; a
concrete `rho`, transcript, or SHAKE failure; a defect in the independent
bound; or an exact full-row endpoint within two signing queries and at most
`2^45` work.

K-LMS (ePrint 2026/2372 v1) completed a bounded source-backed audit of the
exact principal `n=32,h=10,w=4,L=1` endpoint under correct stateful operation,
pinned to commit `58be56d022422f2f58c15c3542a6fbc930686086`. The three LSH
implementations were treated as one byte-identical full-26-step LSH-256
mapping, while the source-defined CHAM-, KISA-LEA-, and ARIA-based Tandem-DM
mappings were reviewed separately. No secret-key recovery with fresh signing,
reusable equivalent signer, or ordinary-verifier accepted fresh-message
forgery was obtained. A reachable `D_MESG` length extension produced a
distinct digest, unchanged signatures were rejected, and no LM-OTS signing
bridge survived the checksum argument. The generic `2^128`, optimistic
`2^118`, and corrected above-`2^236.02` comparisons are stopping estimates,
while the `2^56` and `2^72` fragment enumerations screen only their named
routes; none is a security lower bound. Conformance remains limited by the
absence of a published or source-independent endpoint vector, the paper's
underdefined Tandem-DM byte dialect, out-of-band non-SHA backend identity, the
verifier's missing public-key-length argument, same-process memory-only reload
tests, incomplete primitive/chunking/padding vectors, qualified sanitizer
coverage (including unavailable LeakSanitizer and shift-by-32 behavior in the
auxiliary paper-LEA core), one non-code Cisco line-ending difference despite
all 61 C/H files matching, dual-SHA and backend-matrix coverage supplied only
by independent review, aggregate-only negative-control reporting, the
distinction between 1,169,407 API events and 1,100,799 logical hashes over
62,736,298 logical bytes, and the `void` ARIA callback's inability to propagate
EVP failures, although no normal-path failure was observed. This is a bounded
campaign audit, not a security proof. Reopen for a full-26-step LSH-256 signing
endpoint below `2^45`; a full-round CHAM, LEA, or ARIA Tandem-DM route below
`2^45` with an LM-OTS/LMS signing bridge; a `KLMS_TDM_PAD_V1` padding/domain
alias or same-digest `D_MESG` fixed point; an ordinary-operation state,
transcript, parser, type, backend, path, or root-binding defect yielding an
equivalent signer or accepted fresh-message forgery; a secret-derivation,
deterministic-`C`, namespace, or LM-OTS transformation defeating the reviewed
arguments below the cutoff; or a material paper/source revision, endpoint
vector, or new exact-target prior art.

SigRPO-LDR (ePrint 2024/1553 current v2) completed a bounded source-backed
audit of the exact Goldilocks `D=2048,q=85,e=3,m=58` LDR profile, with no FRI
folds and grinding `(0,0,0,2)`, at paper-branch commit
`99304c22e3ed384d0e227b670d1d7465ed7c4e98`. The source-defined RPO and
Blake3 BCS verifiers were adjudicated separately. Neither endpoint yielded a
secret key, reusable equivalent signer, or ordinary-verifier-accepted
fresh-message forgery within the campaign's `2^45` work boundary.

The RPO endpoint has an exact source-specific commitment defect: every
four-felt digest of a 48-felt quotient leaf has efficient full-round preimages,
arbitrary multicollisions, and a leaf/node alias. A same-digest substituted
opening preserved Merkle reconstruction, but the unchanged verifier rejected
with `DeepCheckFailed` because each queried row must also satisfy a prescribed
cubic-extension DEEP/Horner value. No constructive bridge into that condition
below `2^45` was found. The defect is therefore nonqualifying and is not a
successful signature attack. It does not transfer to Blake3, whose leaves are
tagged and length-bound and whose nodes use a distinct canonical encoding.

The result is limited to the pinned source's salted transcript and BCS byte
dialect, four-canonical-Goldilocks-element message API, CPU/no-default-features
endpoint, explicit Blake3 preset, and out-of-band verifier-type backend
selection. The generated vectors are campaign candidates rather than
pre-existing author KATs; the paper's printed estimates were checked for
consistency, not proved as new soundness theorems. Current v2 was pinned from a
public mirror matched to official metadata, while immutable v1 bytes were
unavailable. This is a bounded campaign result, not a security proof. No attack
package is created. Reopen only for a sub-`2^45` constrained RPO opening,
path/transcript, direct-witness, q85/e3 proof, or packed-Blake3 route; a material
paper/source or parser/profile change; or new exact-target prior art.

ANSA-IBS (ePrint 2026/2134, current 2026-10-12 revision) completed a
bounded paper-level audit of the ordinary external-message IBS-1 profile at
`N=1536`, `q=8380417`, challenge weight 27, `ZBOUND=2018750`, and an 8,488-byte
signature. Exact reconstruction and hostile closeout found no master-key
recovery, reusable equivalent signing witness, or ordinary-verifier-accepted
fresh-message forgery within the campaign's `2^45` work boundary. The closest
numerical observation is the paper's approximately `2^50` auxiliary
ordinary-RSIS diagnostic, but it is only a consequence of two already-valid
same-commitment forks and supplies no reverse construction to a transcript-fixed
signature. Direct BMST, alternate-user-key, challenge-retargeting, identity,
annular, and exact-Galois routes either remain above the cutoff or lack a
signing bridge. No experiment was warranted. The claimed author artifact was
not publicly located, and the public hash suite and several wire encodings are
not byte-exactly specified, so this result makes no source-conformance or
benchmark claim. This is a bounded campaign audit, not a security proof. Reopen
for a concrete sub-`2^45` RSIS-to-transcript, affine-preimage/BMST, annular,
weak-challenge, output-bias, or surviving-symmetry route; a shared-interface
ANSA-IBKEM/Antrag break yielding signing power; a material paper/artifact
change; or new exact-target prior art.

Round-Optimal Pairing-Free Blind Signatures (ePrint 2026/091 v1/current)
completed a bounded audit of the intended Scheme2 relation using P-256
Nyberg--Rueppel issuance, the source's 32-byte SHA-256 map, T-256 proofs,
Spartan issuance, and the 1,349-byte R1CS-IPA final proof at source commit
`f040bd34004c17fa475cb03e481e94101a98e886`. No practical design-level
secret-key recovery, reusable equivalent signing witness, accepted
fresh-message forgery, or one-more forgery was found within the campaign's
`2^45` work boundary. The strongest retained generic stopping estimates are
about `2^125` raw hashes for a selected-map collision, `2^128` work for group
claws, discrete logarithms, or useful nonce relations, `2^248` work for a
fixed mapped-point preimage, and `2^256` work for a statement-complete strong-
Fiat--Shamir fixed point. Exact reblinding simulates concurrent issuance from
ordinary Nyberg--Rueppel signatures, and no intended mixed Sigma/SNARK route
survived the stated binding and soundness assumptions.

This result covers Scheme2 under a competent statement-complete
Fiat--Shamir compilation, canonical encodings, full point equality, and the
paper's proof assumptions. Scheme1, Scheme3/vector credentials, other curve or
proof-system profiles, and external parsing or interoperability are excluded.
The repository has no canonical public outer decoder, stable external wire
contract, or fixed full-scheme known-answer vector, and this public disposition
does not certify the pinned implementation. The paper's displayed proof and
reblinding formulas require competent algebraic interpretation. This is a
bounded campaign result, not a security proof. Reopen for a material paper,
source, profile, endpoint-vector, or intended-relation change; a concrete
sub-`2^45` message-map, nonce, group, concurrent, proof-system, or commitment
route; a deployment that materially changes the reviewed endpoint; or new
exact-target prior art.

edaBitE Blind Signature (ePrint 2026/2473, initial/current 2026-10-14 object)
completed a bounded paper-level audit of the base single-issuer ML-DSA-44
profile. No practical issuer-key recovery, reusable equivalent signer,
zero-query accepted proof, or one-more fresh-message forgery was found within
the campaign's `2^45` work boundary. The claimed eight-bit grinding step is
unverified; omitting its credit leaves aggregate generic soundness at roughly
`2^-120.38`, with no practical accepted-proof route. Theorem 2 states ordinary
final-proof straightline extraction although its proof needs the 256-bit mask
fixed or extractably bound by the first phase before the external hash; the
paper's algorithm and prose expressly select that stronger binding, so the
mismatch is not a demonstrated break of the frozen design. Both advertised
author artifacts returned HTTP 401, so this result makes no source-conformance
claim. Reopen if authoritative source or vectors permit post-hash mask
correction, remapping, or equivocation; omit required statement, circuit,
commitment, conversion, framing, or domain binding; alter generator/order or
the six edaBitE and two ORAM challenge-independence conditions; make the final
`w1` block, second `SampleInBall` squeeze, Algorithm 6 return, canonical values,
SHAKE length, or grinding admit a practical wider relation; or expose
PR-56-style row reuse that reaches a reusable witness or accepted extra
message. Also reopen for a material revision, erratum, authoritative author
statement, practical ML-DSA/proof-system break, stronger full-row route, or new
exact-target prior art.

ModFalcon (ePrint 2019/1456, current fourth revision dated
2024-11-01) completed a bounded paper-level audit of ModFalcon-2-512 over
`R=Z[x]/(x^512+1)` at `q=12289`, `rho=1512`, and a 320-bit salt. Signature
recovery (SR) and key recovery (KR) were treated as separate profiles. No
practical secret-key recovery with fresh signing, reusable equivalent signing
trapdoor, or ordinary-verifier-accepted fresh-message forgery was found within
`2^45` work. In SR, the favorable corrected current-v4 row-deletion estimate
first passes at block size 660, about `2^192.72` classical or `2^174.90`
quantum work with a `2^136.95`-element sieve list. The displayed Equation (6)
instead gives 661, the current table's 658 does not pass, and the aggressive
historical dimensions-for-free row gives 608 but remains far outside the
campaign boundary. Theorem 3.1 does not apply to the concrete row because
`q=1 mod 8` and its coefficient widths do not meet the theorem's sufficient
conditions; no practical public-key-distribution signing bridge followed.

The KR review used an explicitly conservative analysis completion: retain
`h1`, omit `h2`, bind a canonical ordered complete key with an inferred
348-to-352-bit digest, transmit all three signature coordinates, reject
nonunit `s2`, and resample it during signing. The paper does not fix those
semantics. Exact short nonunit denominators establish a correctness and
specification gap, while an accepted signature under this completion still
reduces either to the full SR relation or to a fixed-target digest second
preimage. The structured completion row `(g0,-f)` remains the principal reopen
item: reopen if exact paper-distribution statistics make it recoverable and a
derived rank-two basis is shown to sign with `s2=0` at `rho=1512`. The paper's
printed `epsilon=2^-38` and GS cap imply `sigma>=35.627134...` and nominal
radius `1535.922...`, inconsistent with Table 2's `rho=1512`; this and the
estimator discrepancies are proof, parameter-record, or conformance limits,
not demonstrated attacks.

The pinned author Python repository at commit
`16388e0064d8272792047b81ea82fce4791788a1` implements the generic full-vector
construction, not either current SR or KR endpoint. The paper also leaves
byte-level hash-to-point, codecs, KR recovery-coordinate and nonunit handling,
digest, parser, and full current-endpoint known-answer vectors unfrozen, so no
implementation-conformance claim is made. A bounded history search through
2026-10-16 located no public practical signing compromise against the exact
profile at moderate-high confidence; that is a dated absence-of-located-public-
attack statement. This campaign result is not a security proof. Reopen for a
full accepted endpoint within `2^45`; a demonstrated completion-row recovery
and signing bridge; authoritative current SR/KR source, vectors, revision, or
erratum exposing a practical route; a practical KR binding bypass; mathematical
sampler leakage yielding a reusable trapdoor; a nonnegligible publicly
detectable weak-key signer class; or material new exact-target prior art.

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

[GLYPH](attacks/glyph/) (ePrint 2017/766, final v3) admits a
public-key-only zero-query fresh-message forgery at its complete recommended
row. The attacker sets `z1=0`, hashes the all-zero verifier floor with the
chosen message to obtain `c`, and selects each strictly bounded `z2`
coefficient from `{0,-(K-1),K-1}` so that `K-floor(z2-t*c)=0`. The primary
implementation accepted 64/64 fresh-key forgeries and rejected 512/512
controls; a fresh-context independent implementation accepted another 64/64
and rejected 256/256 controls. The claim covers the final-v3 numerical
paper/source interface because the target defines no portable external
signature wire format. The report makes no general technique-novelty claim
and distinguishes original GLP12's prior same-message malleability. No prior
public substantive attack against final-v3 GLYPH was located in searches
completed through 2026-10-13.

[TOT](attacks/tot/) (ePrint 2013/771, sole publicly exposed revision) signs a
raw vector $M\in\mathbb F_2^{128}$ and accepts exactly when the public
quadratic map satisfies $P(\sigma)=M$. A zero-query adversary chooses a
nonzero signature vector, computes $M=P(\sigma)$, and outputs the resulting
fresh pair. The message lies in the public map's image and is therefore
honestly signable. Primary and separately written fresh-context
implementations passed at the same-inventors recommended
`q=2,n=128,d=6,t=64` row, with all controls rejecting. The claim excludes
preselected vectors and any separately added document-hashing wrapper. The
signature-first/no-message technique is classical and no novelty is claimed;
no prior public attack specifically against TOT was located in searches
performed through 2026-10-13.

[Full-Distance Syndrome Decoding](attacks/full-distance-syndrome-decoding/)
(ePrint 2023/1956) exposes the 125-coordinate support of its basic signing map:
the corresponding public `Hstar` columns are exactly those lying in
`Col(R)`. Public elimination recovers a map `U` with `Hstar*U=R`. From one
ordinary signature, an attacker transfers the syndrome equation to an unsigned
target and searches a 25-bit affine correction for the required weight 343.
The retained full Level-I attack and eight-target adversarial review passed; a
fresh-context implementation also forged 5/5 wholly fresh keys with one query
per key, taking at most 13.376 seconds per attack and 22,016 KiB peak RSS in
the complete sequential run. No author implementation was located, so the
result is scoped to an independently documented reconstruction of the paper's
mathematical KeyGen/Sign/Verify relation. No previous public attack against
the exact ePrint 2023/1956 scheme was located in searches completed on
2026-10-14; this is a bounded negative result.

[Higher-Bit Approximate-ISIS](attacks/higher-bit-approx-isis/) (ePrint
2022/1144, Construction 1) prescribes a verifier radius whose
`sqrt(n) b^d s` contribution already exceeds the maximum possible target-vector
norm in every Figure 3 column labelled “This work.” The all-zero signature
vector therefore passes for every attacker-chosen fresh message and every
public matrix under any threshold completion obeying Section 6.4. The primary
run covered all three advertised rows, while a separately written
fresh-context implementation accepted 384/384 checks across 192 fresh
messages, both canonical and centered lifts, and three fresh full-size public
matrices with zero signing queries. The claim is limited to Construction 1
under Section 6.4-compliant thresholds because the paper omits concrete
thresholds, serialization, and a public author implementation. The report
credits the generic zero-vector Approximate-ISIS boundary to
Chen--Genise--Mukherjee and claims no technique novelty. No prior public attack
against this exact signature was located in searches completed on 2026-10-14.

[SSD](attacks/ssd/) (ePrint 2022/1698, standard SSD1760 mode) publishes a
242-by-1760 binary verification matrix but accepts any response of weight 473
through 513 satisfying the public syndrome equation. The attacker row-reduces
that matrix, fixes 363 of its 1,518 free coordinates to one, and solves the 242
pivot coordinates for each fresh public message target. In the paper's
random-oracle model, the resulting pivot weight lies in the accepted interval
with exact probability about 0.93037 per distinct message, so the attack is an
efficient existential message-search forgery with zero signing queries. The
primary and hostile adversarial runs passed on full-size fresh keys. A
separately written implementation then forged 5/5 independently generated
full-rank keys using six public hash queries in total, with all honest,
changed-message, mutation, wrong-key, and exact weight-boundary controls
behaving as required. The result does not claim a universal or fixed-message
forgery, LVK coverage, or rank-deficient-key coverage. No previous public
attack against the exact SSD scheme was located in searches completed on
2026-10-14.

[HPPK DS](attacks/hppk-ds/) (ePrint 2023/1768) accepts a complete
all-zero signature for every message and structurally valid public key under
the ordinary Equation (28) verifier. Each complete SHA-256, SHA-384, or
SHA-512 hash is split into four field-sized segments, so the forgery contains
four `(F,H)=(0,0)` pairs. Direct substitution makes every derived `U_ij(H)`
and `V_ij(F)` coefficient zero and reduces each verifier comparison to `0=0`.
The paper-level reproducer covered all three target rows and all fifteen
benchmark rows; fresh-context evidence covered 72/72 complete paper
forgeries and 192/192 pinned-Go attacker checks, with zero signing queries.
The Go source is separate source-specific corroboration and is not an exact
implementation of an advertised row. A September 2026 public-key-only
forgery was found against a materially divergent HPPK-labelled implementation
whose signature supplies `{F,H,U,V}`. That related result does not execute the
paper's `{F,H}`-only verifier, and the bounded no-prior-attack conclusion is
limited to the exact Equation (28) construction.

[Jevil](attacks/jevil/) (ePrint 2026/1103, current fourth revision) exposes
four authenticated field values at each initial zk-WHIR opening. Across
ordinary signatures, 32,768 distinct outer positions determine all four
degree-below-32,768 Reed--Solomon rows and the committed signing state. The
primary run recovered that state from 641 ordinary signatures and produced an
ordinary-verifier-accepted signature on an unqueried message; a separately
written fresh-context implementation repeated the full endpoint on a new key
with 650 signatures and a second untouched-source verifier. Both stay below
the allowed 1,023 queries and do not use the paper's advertised 1,024th-
signature recovery. No prior public practical signing attack against this
exact current profile within the query budget was located through 15 October
2026. The package separately discloses a May 26 pre-publication root-binding
forgery fix and a June 2 public non-power-of-two Merkle-helper finding without
a located signing consequence for this profile; it makes no broad first-attack
claim.

[EagleSignV3](attacks/eaglesignv3/) (ePrint 2024/1234, current second
revision) leaks centered-modulus wrap labels through public `r` at the exact
paper-level Ring-L2 row
`(k,l,n,q,tau,eta,beta,gamma1,gamma2)=(1,1,1024,59393,16,1,16,16384,16384)`.
The labels give sparse threshold inequalities in ternary `D`; solving them
recovers `D` and, when public `T` is a ring unit, the equivalent signing key
`G=T^-1(A+D)` and a fresh-message signature. Unit `T` is publicly testable and
has estimated probability about 98.29% for this row. Both counted one-key
trials succeeded: the primary and prospectively sealed independent runs each
used every one of 40,000 outputs returned by the printed Algorithm 4,
including respectively 1,767 and 1,727 outputs rejected by the ordinary
verifier. The result is paper-level because no exact V3 source, canonical wire
encoding, or known-answer vector was located; the later package replay is
supplemental validation and is not a third trial.

No prior public substantive attack against EagleSignV3 (IACR ePrint
2024/1234) was located in the searches performed as of 15 October 2026.

Pulles and Tibouchi previously broke EagleSign V1 and V2 using response statistics and ideal structure. Those schemes use different response relations, and EagleSign V2 includes an explicit centered-modulus-boundary rejection that is absent from the EagleSignV3 specification studied here. We located no earlier public disclosure applying the centered-modulus-wrap, public-commitment-label route to EagleSignV3. This is a bounded search statement; we make no absolute firstness or attack-technique novelty claim.

See [methodology](METHODOLOGY.md), [attack-history methodology](docs/attack-history-methodology.md), [publication policy](docs/publication-policy.md), [reproducibility](REPRODUCIBILITY.md), and [AI disclosure](AI_DISCLOSURE.md).
