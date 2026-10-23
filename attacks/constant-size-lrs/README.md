# Constant-Size LRS: adaptive ring-permutation forgery

> **VERIFIED ATTACK.** The paper/profile, fresh-context reproduction,
> adversarial-result, final exact-target history, and independent AI
> publication-package review gates passed with all ten binding qualifications
> preserved.

| Field | Value |
|---|---|
| Scheme | Efficient Constant-Size Linkable Ring Signatures for Ad-Hoc Rings via Pairing-Based Set Membership Arguments |
| Target | [ePrint 2025/1174](https://eprint.iacr.org/2025/1174), revision 2 dated 24 November 2025 |
| Scheme authors | Min Xie, Zhengzhou Tu, Man Ho Au, Junbin Fang, Xuan Wang, and Zoe Lin Jiang |
| Family | Pairing-based scoped linkable ring signature using ccGro16, CPlink, and optimized KZG-backed set membership |
| Competition history | None located; the paper is the ACM CCS 2025 full version |
| Result | Zero-signing-query fresh-message false-membership forgery at the full paper profile |
| Technique | Adapt the ordered ring after the base SMA challenges by orienting 254 honest KGO key pairs, cancelling the sole unavailable SRS coefficient |
| Technique originality | No general technique novelty claimed; the contribution is the concrete application to this scheme's transcript and Equation 15 |
| Affected parameters | Authors' BN254 evaluation: BabyJubJub/MiMC91, `n=m=1024`, ccGro16, CPlink, optimized KZG-backed SMA |
| Signing queries | 0 |
| Measured independent replay | 63.85 s wall, 24,576 KiB peak RSS, one worker, for the deterministic Python paper model only |
| CPU/workers | AMD EPYC Processor under KVM (64 vCPUs available); the run used one Python worker and one thread |
| Design level | Yes; it uses only the revision-2 paper interface and honest KGO public keys |
| Condition | The adversary chooses the final ordering of an ad-hoc ring after the base commitments, as the paper API and security game permit |
| Independent reproduction | PASS for ordinary and `python -O` full-row runs; independently validated evidence |
| Execution boundary | SMA Equation 15 and KZG Equation 17 executed exactly; ccGro16/CPlink composed by honest-witness correctness, not emitted proof objects |
| AI provenance | AI-assisted cryptanalysis, implementation, review coordination, reproduction, and writing; Daybreak Blue at ultra reasoning; separate adversarial review PASS |
| Human verification | Not performed and not required by the project |
| Last attack-history search | 23 October 2026; final exact-target recheck PASS |

## Impact

An attacker generates a valid key that is not in a ring of 1,024 honest KGO
public keys and produces a paper-level signature on a fresh message that the
ordinary three-component verification relation accepts. The attacker uses its
outside secret only for the honest ccGro16 and CPlink relations. The forged
component is the set-membership argument: it asserts that the outside hashed
key belongs to the ring when it does not. No signing-oracle query, ring secret,
setup trapdoor, malformed ring element, or exhaustive search is used.

## Attack at a glance

The optimized SMA base challenges `H_s`, `H_t`, `H_u`, and `H_agg` bind the
message tag and commitments but omit the ordered ring
`Phi=(phi_1,...,phi_n)`. For commitment coefficients `b_i`, expansion of the
paper's Equation 15 at the sole unpublished G1 SRS power `X^(n+1)` gives

```text
E = delta_b   sum_i s_i b_i(b_i-1)
  + delta_o  (sum_i b_i-1)
  + delta_phi(sum_i b_i phi_i-phi_star).
```

Before the challenges, pair 508 honest public-key hashes as `(a_j,c_j)` for
`0 <= j < 254`, put `b_j=2^j/(a_j-c_j)` at one position of each pair, and put
zero at the partner and remaining 516 positions. Swapping pair `j` later
changes the weighted membership term by exactly `-2^j`. After `delta` is
known, the 254-bit expansion of the required BN254 residue selects the pair
orientations and makes `E=0`. The final ring is only a permutation of the
fixed honest-key multiset, while `phi_star` remains absent.

The later KZG challenge does include the final ordered ring. That does not
repair the earlier omission: once the orientation has cancelled the missing
coefficient, the attacker computes the KZG commitments and opening honestly
for that final ring.

## Exact scope

The attack and retained run cover the paper's claimed full evaluation row
`eprint-2025-1174-v2-bn254-babyjubjub-mimc91-n1024-m1024`. Every ring entry is
an exact BabyJubJub/MiMC91 KGO output and all 1,024 hashes are distinct. Exactly
254 nonzero coefficients use uncorrupted entries, and the attacker key is not
in the ring. The exceptional event `delta_phi=0` has probability `1/q`; an
attacker starts a new transcript in that event. Equal hashes within a selected
pair are detectable and require replacing that pair; this is negligible under
the paper's hash assumptions.

The reproducer executes the complete SMA polynomial identity in Equation 15
and the ring-bound KZG quotient identity in Equation 17 at the full row. It
checks that the attacker knows a valid outside secret satisfying the ccGro16
relation and matching openings satisfying CPlink, so the ordinary honest
provers can produce those components by correctness. It does **not** emit
ccGro16 or CPlink group proofs. The authors publish a partial benchmark and
reference implementation, but we located no complete external LRS verifier,
outer 687-byte codec, or known-answer test in the published artifact.
Accordingly, this package makes no
byte-level author-verifier, codec, KAT, or complete author-source execution
claim.

## Reproduction

Python 3 and the standard library are sufficient. From this directory:

```bash
python3 -B reproduce.py --reference
python3 -B reproduce.py
python3 -B reproduce-all-rows.py --reference
./reproducer/reproduce.sh --quick
./reproducer/reproduce.sh --full
```

The quick commands independently validate the retained evidence. A fresh full
run normally takes about one minute and regenerates the byte-identical public
evidence. Use `--raw-output-dir PATH` with either direct full entrypoint to
retain its core and validator logs. Success ends in JSON with
`full_attack_reproduced: true` or `all_rows_pass: true`.

## Evidence and controls

The positive run has zero at the missing `X^(n+1)` coefficient, passes SMA
Equation 15 and KZG Equation 17, and satisfies both honest-witness relations.
Three independently checked controls reject the composite paper relation:

- retaining the pre-challenge pair orientation leaves a nonzero unavailable
  coefficient and fails Equation 15;
- flipping pair zero after the proof is fixed makes the ring-bound KZG check
  fail; and
- changing the message rederives the transcript and fails both SMA checks.

The ordinary and hostile `python -O` reproductions emitted byte-identical
evidence. The full deterministic replay regenerated every KGO output from the
fixed scalar stream. A separate validator checked every BabyJubJub curve
equation, MiMC91 public-key hash, pair coefficient, residue bit, and reported
predicate without importing the attack implementation; that standalone
validator does not derive points from the committed KGO scalars or recompute
the complete transcript. See [`evidence/`](evidence/),
[`reference-output.json`](reference-output.json), and
[`all-rows-reference-output.json`](all-rows-reference-output.json).

## Relationship to known techniques

The complete-statement binding requirement for Fiat--Shamir transforms is
classical, and KZG commitments and missing-power polynomial algebra are
established techniques. Binary expansion of a public field residue is also
elementary. No general method novelty is claimed. The contribution is the
target-specific observation that revision 2 leaves the ordered ring out of
its base SMA challenges, together with the 254-pair construction that turns
that omission into a full-profile false-membership forgery.

## Limitations

- An application that canonically fixes and authenticates ring order before
  the base commitments could block this exact permutation route. Revision 2
  imposes no such lifecycle on its ad-hoc rings.
- The paper calls the BN254 row 128-bit. This package records that as the
  authors' claim and does not endorse it as a current independent estimate.
- The paper samples secrets in the full BN254 scalar field, while the partial
  source circuit decomposes 253 bits. The retained outside secret happens to
  be below `2^253`; no broader source-conformance claim follows.
- No complete author LRS verifier, codec, or KAT was located in the published
  artifact, and the
  public experiment is a paper-level algebraic execution with the precise
  ccGro16/CPlink composition boundary stated above.
- The executed endpoint is one fresh false-membership signature. The
  two-signature scoped-linkability consequence is a direct algebraic extension
  and was not independently executed twice.

## Repair direction

Bind the complete ordered ring statement into every base challenge that is
used to aggregate the SMA relations, before any response or proof component
can depend on those challenges. If applications intend canonical ring order,
specify and authenticate that lifecycle as part of the signed statement. Any
repair requires a new proof and full interoperability testing; this package
does not claim a drop-in patched construction.

## Sources and provenance

- Target paper: [IACR ePrint 2025/1174](https://eprint.iacr.org/2025/1174)
- Venue DOI: [ACM CCS 2025](https://doi.org/10.1145/3719027.3744830)
- Author source: [pinned commit `b312e41`](https://github.com/TuZhengzhou/lrs-v2/tree/b312e41b069857209eb680c156692bb5d2b456b4)
- Attack paper: [PDF](paper/attack.pdf) and [LaTeX source](paper/attack.tex)

OpenAI Codex reconstructed and analyzed the target, prepared the experiment,
coordinated independent AI review and reproduction, and drafted this package.
The sealed fresh-context reproduction and separate adversarial-result review
passed. The final exact-target recheck concluded: “No prior public substantive
attack against ePrint 2025/1174 revision 2 was located in the searches
performed through 2026-10-23.” Independent human verification has not been
performed; it is optional and there is no human-verification requirement.
The independent AI publication-package review returned GO; this package is
classified as `VERIFIED_ATTACK`.
