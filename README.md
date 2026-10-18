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
| Schemes identified | 53 |
| Known attacks excluded | 3 |
| Schemes audited | 50 |
| No practical attack found | 33 |
| Verified and independently reproduced practical design attacks | 17 |

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
| [FABS](attacks/fabs/) | 2026/022 current | Pairing-based key-policy attribute-based signature | One-H0-query, zero-signing-query universal fresh-message forgery | Public satisfying witness and Schnorr-style response programming | Figure 1 KP-ABS, 100-attribute all-AND endpoint | 1 `H0` query; 0 signing queries | Verified; independently AI-reproduced |
| [Iceberg](attacks/iceberg/) | 2026/1757 v1 | Nested threshold MuSig2 over replicated secret sharing | Group signing-key recovery with fresh-message BIP340 forgery | Same-message context splitting and a three-response linear solve | `t=2`, `n=4`, `mu=3`, `nu=2`, secp256k1 | 3 signing queries; 0.95 s wall independent replay; 15,360 KiB peak, 1 worker | Verified; independently AI-reproduced |

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
| Lattice SEP | 2024/131 current major revision | Exact `LSEP-2024-131-SOURCE-M10-v1` ordinary source endpoint at commit `e0b750bdff26cc4d3cc9cf49921314bd0fa6c2e7`; fixed 320-byte binary-vector messages and source `B1'` cutoff | No practical signer or forgery; non-injective source tags are outside correct unique-tag operation, and the sampler correction remains a proof limitation without a signing consequence |
| Aerie | 2026/2501 initial/current | Exact `AERIE-F512-V1-PER-RECORD-N32768-v0.2.0` released per-record-salt Falcon-512 aggregate verifier at 32,768 records; Aerie `v0.2.0` and pinned Akita | No practical signer or fresh-record aggregate forgery; the raw-SHAKE chosen-key alias remains type-separated and has no signing bridge |
| Robust ECDSA Threshold Signing at Scale | 2026/2493 v1 | Exact paper profile `ROBUST-ECDSA-2026-2493-SECP256K1-SHA256-N88-T29-PAPER-v1` at `n=88,t=29`; intended agreement and ordered single-use presignatures; author benchmark excluded | No qualifying intended-design signer or forgery; the literal 30-versus-31 release mismatch and same-presignature two-view key recovery are real but nonqualifying under the stated agreement, single-use, and freshness rules |
| Concurrently Secure Compact Blind Signatures from Module-SIS | 2026/1690 v1/current | Exact paper-static profile `MSIS-CBS-2026-1690-N1536-M4608-Q1013921281-GAMMA2.5-PAPER-v1`; full-vector verifier; linked estimator unavailable | No practical signer, fresh-message forgery, or pairwise-distinct one-more forgery; the `B>q` reduction defect and rejected-round valid signatures remain nonqualifying |
| FALCON with message recovery (FALCON-MRM) | 2026/420 paper v1/current | Exact paper-static profile `FALCON-MRM-2026-420-N512-Q12289-L19-G15-MAXREC-M2EMPTY-PAPER-v1`; native Algorithm 4 at `n=512`; no author source or KAT | No practical signer or fresh native-message forgery; signature-first candidates face `q^19`, while hash-first candidates require a full Falcon short preimage |
| smklhs | 2026/1370 initial/current | Base Figure 4 at the claimed BLS12-381 setting, exactly two distinct honest signers, weakly adaptive predeclared queries, and the literal Figure 4 plus Figure 3 verifier; paper-static | No practical signer or accepted false/fresh aggregate; the literal challenge-scaled proof statements generically reject honest nonzero multisigner outputs |
| BRaccoon | 2026/1084 current 2026-09-25 | Current Table-3 `Q_s=2^32` paper-static object, four-move issuance protocol, and literal Figure-5 external-message verifier; parameter-certificate source only | No practical signer, fresh-message forgery, or one-more forgery; floor-rounding proof/certificate mismatch is nonqualifying and full-query H-MLWE regression is outside the practical envelope |

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
completed a bounded audit of the exact 19,616-byte Default row with no
practical signing compromise. The review found inconsistent capacity
definitions, one implying a generic collision boundary near `2^126.798`, and an
underdetermined interpolation step, but neither yielded a secret, reusable
signer, or fresh-message forgery. No authoritative current-row implementation
was available. Reopen if an implementation or revision resolves those gaps, or
if a concrete primitive, interpolation, or composition route reaches the
campaign bound.

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

NIC signature (ePrint 2026/1573 v1) completed a bounded paper-level audit of
the Level-I `(k,n,w)=(210,1050,350)` core with no practical signing compromise.
Two full-parameter XOR-SAT lanes reached their five-minute limits without
finding a witness, and the strongest exact reduction still leaves about
`2^116.951` marginal candidates. The paper supplies neither an implementation
nor a fully specified wrapper or encoding. Reopen if authoritative artifacts
fix those semantics, non-random key structure becomes exploitable, or a
concrete full-row solver enters the `2^45` campaign bound.

SPHINCS-PE (ePrint 2026/1708 v1) completed a bounded paper-level audit of the
standard 128f row with `q_use=2^8` and no practical signing compromise. The
reconstructed verifier binds the prepared certificate and online opening in one
address space. Even after the advertised preparation and signing budgets,
pooled FORS coverage is about `2^-130.70`, leaving a `2^45` digest grind near
`2^-85.70` success. The author repository was unavailable. Reopen if
implementation evidence changes verifier semantics or a concrete bias,
state-use issue, or primitive break supplies a fresh-message route.

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
principal `n=32,h=10,w=4,L=1` endpoint with no practical signing compromise. A
reachable `D_MESG` length extension changed the digest, and all three Tandem-DM
verifiers rejected unchanged signatures; no LM-OTS signing bridge survived the
checksum. Conformance remains limited by the underdefined Tandem-DM byte
dialect and the absence of an independent endpoint vector. Reopen if a
practical LSH or Tandem-DM route gains an LMS signing bridge, a padding or
domain alias appears, or authoritative source evidence changes the endpoint.

SigRPO-LDR (ePrint 2024/1553 current v2) completed a bounded source-backed
audit of the Goldilocks `D=2048,q=85,e=3,m=58` LDR profile with no practical
signing compromise. Its RPO endpoint has efficient chosen-digest quotient-leaf
preimages and multicollisions, but substituted openings still failed the
required DEEP/Horner condition; the defect does not transfer to the separately
reviewed Blake3 endpoint. Reopen if a sub-`2^45` constrained opening or
transcript route supplies that missing condition, or if a material source,
parser, profile, or prior-art change alters the result.

ANSA-IBS (ePrint 2026/2134, current 2026-10-12 revision) completed a bounded
paper-level audit of the ordinary IBS-1 profile with no practical signing
compromise. The closest observation, an approximately `2^50` auxiliary RSIS
diagnostic, follows from two already-valid same-commitment forks but gives no
reverse construction to an accepted transcript. The claimed author artifact was
unavailable and several hash and wire encodings remain unspecified. Reopen if a
concrete RSIS, BMST, annular, weak-challenge, or symmetry route gains a signing
bridge, or authoritative artifacts materially change the profile.

Round-Optimal Pairing-Free Blind Signatures (ePrint 2026/091 v1/current)
completed a bounded audit of the intended Scheme2 relation with no practical
key recovery, equivalent signer, fresh-message forgery, or one-more forgery.
Exact reblinding only simulates concurrent issuance, while the strongest
generic collision, claw, nonce, and proof routes remain at roughly `2^125` work
or more. The repository lacks a canonical outer decoder and full-scheme
known-answer vector. Reopen if a concrete message-map, nonce, group, proof, or
commitment route enters `2^45`, or if authoritative semantics materially
change.

edaBitE Blind Signature (ePrint 2026/2473) completed a bounded paper-level
audit of the base single-issuer ML-DSA-44 profile with no practical signing
compromise. Omitting the paper's unverified eight-bit grinding credit leaves
estimated generic soundness near `2^-120.38`. A stated extraction mismatch is
resolved only by the intended requirement that the 256-bit mask be fixed or
extractably bound before hashing. The advertised artifacts were inaccessible.
Reopen if authoritative source permits post-hash mask correction or omits
required binding, or if a concrete proof-system route reaches the campaign
bound.

ModFalcon (ePrint 2019/1456, current 2024-11-01 revision) completed a bounded
paper-level audit of ModFalcon-2-512 with no practical signing compromise. The
most favorable corrected signature-recovery estimate is about `2^192.72`
classical work, while published table and theorem conditions do not match the
concrete row. The key-recovery profile is underdefined; nonunit denominators
expose a correctness gap but no accepted-signature bridge. The available source
implements only the generic construction. Reopen if authoritative endpoint
semantics or vectors expose a sub-`2^45` completion-row, binding, weak-key, or
sampler-leakage route.

Lattice SEP (ePrint 2024/131) completed a bounded source-backed audit of the
standalone stateful M10 profile with no practical signing compromise. A `2^24`
tag scan found many collisions, and same-tag affine identities held, but every
tested candidate failed the source norms or verifier; exploiting scheduled
reuse would also violate the paper's unique-tag operation. A small successor
sampler-margin discrepancy produced no leakage or signing consequence. Reopen
if a norm-compatible tag, message-map, factor, or sampler route reaches `2^45`,
or if authoritative state, source, or vector semantics change.

Aerie (ePrint 2026/2501) completed a bounded static audit of the released
32,768-record per-record-salt Falcon-512 aggregate verifier with no practical
signing compromise. A raw-SHAKE encoding alias can be found cheaply while
varying an adversarial key, but the verifier keeps key and target types
separate and the observation gives no short witness or fresh honest-row
forgery; fixing the honest key instead restores a generic 512-bit preimage
task. Reopen if that alias gains an honest-row signing bridge, a practical
Akita false-statement route appears, or authoritative source, wire, or profile
semantics materially change.

Robust ECDSA Threshold Signing at Scale (ePrint 2026/2493 v1) completed a
bounded audit of the intended `n=88,t=29` secp256k1 profile with no qualifying
practical attack. Literal Protocol 1 releases shares before its formal `t+2`
authorization boundary, and two demonstrations recovered the key from
conflicting views, but that route violates the construction's stated message
agreement and atomic single-use presignature rules. Reopen if authoritative
semantics make the reproduced execution conforming, or if a concrete route
defeats those rules and yields key recovery or a fresh-message forgery within
`2^45`.

Concurrently Secure Compact Blind Signatures from Module-SIS (ePrint 2026/1690
v1) completed a bounded paper-static audit of the full-vector profile with no
practical signer, fresh-message forgery, or pairwise-distinct one-more forgery.
Setting `y=0` can expose valid signatures from rejected rounds, but all remain
bound to the same message. Literal `MSIS_B` is also trivial because `B>q`, yet
the resulting vector exceeds the verifier bound and gives no signer. Reopen if
pinned implementation semantics expose cross-state transfer or a sub-`2^45`
short preimage for a fresh syndrome.

FALCON with message recovery (ePrint 2026/420) completed a bounded paper-static
audit of the native Falcon-512 maximal-recovery profile with no practical
signing compromise. Signature-first candidates must hit one prescribed value in
`q^19`; hash-first candidates instead require a full random-target Falcon short
preimage. Sleeping-Falcon transfer also lacks the required exact target
repetition under fresh salts. No author source or target-specific known-answer
vector was available. Reopen if a public preimage method, hash relation,
ordinary sampler repetition, or authoritative codec and padding profile
supplies a fresh native-message forgery within `2^45`.

smklhs (ePrint 2026/1370) completed a bounded paper-static audit of the
two-signer base BLS12-381 profile with no practical signing compromise. The
printed outer proof scales honest contributions by a Fiat--Shamir challenge
while its inner verifier uses an all-ones vector, so ordinary nonzero
aggregates generally fail; this is a material correctness and proof gap. A
complete false-zero forgery still requires a target-group discrete logarithm,
estimated near `2^127.43`. Reopen if a practical group relation, proof attack,
hash weakness, or authoritative revision turns the defect into accepted fresh
or false signing.

BRaccoon (ePrint 2026/1084, current 2026-09-25 revision) completed a bounded
paper-static audit of the Table-3 `Q_s=2^32` profile with no practical signing
compromise. Literal floor rounding conflicts with the strict half-width proof
relations, but the relation remains single-valued where defined and the
verifier is not relaxed. The strongest key-recovery bridge needs essentially
`2^32` complete sessions, about `2^48.524` scalar updates, and roughly 3.3 PiB
of transcripts. Reopen if lower-sample regression, a verifier or flooding
bypass, or authoritative rounding, source, or profile changes produce a
sub-`2^45` signing endpoint.

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
revision) leaks centered-modulus wrap labels through public `r` at the
paper-level Ring-L2 row because `q=59393 < 4*gamma2=65536`. The labels yield
sparse ternary constraints that recover `D`; when public `T` is a unit, a
publicly testable condition estimated for 98.29% of keys, they also give the
equivalent key `G=T^-1(A+D)` and fresh signing. Both counted one-key trials
used all 40,000 outputs returned by Algorithm 4, including outputs rejected by
the ordinary verifier, and each produced an accepted fresh-message signature;
the independent pipeline took 296.09 seconds and 221,272 KiB on one worker.
The claim is paper-level because no exact V3 source, canonical codec, or
known-answer vector was located. Earlier EagleSign V1/V2 attacks use different
response relations; no prior public exact-V3 attack was located through 15
October 2026, and no technique-novelty or absolute-priority claim is made.

[DualMS 2.0](attacks/dualms-2/) (ePrint 2026/1941, retained current body)
permits a public-key-only fresh-message forgery because the verifier hint can
absorb its rounded reconstruction: choose `w`, query
`c=Hsig(w,message,aggpk)`, set `z=r=rbar=0`, and choose `h` so verification
reconstructs `w`. The primary and independent implementations accepted
forgeries with zero signing queries at both advertised rounded Table-6 rows.
The independent run needed four `Hsig` queries for `n=32` and one for
`n=1024`, took 28.16 seconds, and used 252,432 KiB on one worker. Exact moduli
come from the paper-linked artifact; no author-wire or source-native
acceptance is claimed. No prior public exact-target attack was located through
16 October 2026; the package credits NGCC CS `sign-07-2` as a different-scheme
hint-absorption analogue and makes no technique-novelty claim.

[FABS](attacks/fabs/) (ePrint 2026/022, current) admits a universal
fresh-message forgery because the literal Figure 1 KP-ABS verifier proves a
relation with public witnesses but does not bind `A`, `B`, and `C` to an
issued credential or the responses to valid policy reconstruction. Setting
`A=B=g1`, `C=g2`, `beta=0`, `k=1`, and every `delta_i=0` yields a nonidentity
transcript with one `H0` query and no key-generation or signing query. The
primary model accepted the full 100-attribute all-AND endpoint, and an
independent Arkworks BN254 implementation accepted both 100-attribute attack
forms in 5/5 fixed setup checks while rejecting eight controls per check; the
run took 3.77 seconds and 31,744 KiB on one worker. The result covers Figure 1
KP-ABS, not SP-ABS or anonymity, and makes no exact author-backend or byte-codec
claim. No prior public exact-target attack was located through 18 October
2026, and no technique novelty is claimed.

[Iceberg](attacks/iceberg/) (ePrint 2026/1757 v1) binds a session identifier
to one message in its security game but leaves the attacker-chosen outer
MuSig2 context unbound across honest members. With one corrupt member, the
attacker queries each of the three honest members once under the same SID and
message while changing only the cosigner nonce. Interpolation yields three
complete group partial signatures whose public full-rank equations recover
both fixed nonce scalars and the group signing key. The recovered key then
produces an ordinary BIP340 signature on a never-queried message with no
honest participation. The exact pinned-source C run and an independently
written secp256k1 reproduction both passed, including rank, parity, raw-share,
and changed-message controls; the independent replay took 0.95 seconds wall and
15,360 KiB on one worker. The result claims no novelty for its known component
techniques, and no prior public report of the complete Iceberg-specific attack
was located through 18 October 2026.

See [methodology](METHODOLOGY.md), [attack-history methodology](docs/attack-history-methodology.md), [publication policy](docs/publication-policy.md), [reproducibility](REPRODUCIBILITY.md), and [AI disclosure](AI_DISCLOSURE.md).
