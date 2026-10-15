# The Jevil Is in the Details: State Recovery and Fresh-Message Forgery Below Jevil's Signature Cliff

> **VERIFIED ATTACK.** The full-parameter primary result, hostile
> adversarial review, fresh-context independent reproduction, final
> exact-target history recheck, and independent Publication Review passed.

## At a glance

| Field | Value |
|---|---|
| Scheme | Jevil: A Catastrophic-Failure-by-Design Signature Scheme |
| Target | IACR ePrint 2026/1103, current fourth revision; exact source-backed `n_star=1023`, Poseidon2 capacity `c=4` profile |
| Target paper | [IACR ePrint 2026/1103](https://eprint.iacr.org/2026/1103) |
| Attack paper | [`paper/attack.pdf`](paper/attack.pdf) |
| Scheme author | Nadim Kobeissi |
| Attack-paper byline | Martin Feussner; Selmer Center, University of Bergen; martin.feussner@uib.no |
| Family | Few-time signature with a polynomial evaluation budget and a zk-WHIR proof layer |
| Result | Equivalent signing-state recovery followed by an accepted fresh-message forgery |
| Primary result | 641 ordinary signatures; 41,024 authenticated openings; 35,203 distinct positions; four rows recovered |
| Independent result | 650 ordinary signatures on a fresh key; 41,600 authenticated openings; 35,603 distinct positions; four rows recovered |
| Signing queries | 641 in the primary result and 650 in the independent result, each below the allowed 1,023; no minimum-query claim |
| Affected profile | Current-revision `n_star=1023`, `c=4`, internal domain size 131,072, four rows of degree below 32,768 |
| Conditions | Repeated ordinary signatures under one public key; public messages, signatures, and public key only; no 1,024th signature, secret seed, original signer cache, malformed input, or weakened verifier |
| Layer | Design |
| Technique | Accumulate authenticated width-four openings, interpolate the four Reed--Solomon rows, reconstruct the committed state, and sign with fresh proof randomness; no technique originality claimed |
| CPU | AMD EPYC Processor |
| Primary resources | Four one-worker collection shards, each at most 203.05 s and 131,060 KiB peak RSS; public recovery 486.90 s and 143,756 KiB peak RSS with one worker |
| Independent resources | Oracle collection 799.13 s and 131,256 KiB; public recovery and forgery 253.12 s and 150,380 KiB; clean verifier 0.93 s and 91,840 KiB; one worker |
| Ordinary-verifier evidence | The unchanged verifier accepted each fresh forgery; changed-message, changed-root, altered-signature, and corrupted-row controls rejected |
| Final history gate | `FINAL_ATTACK_HISTORY_PASS_WITH_MANDATORY_DISCLOSURES`; search cutoff 15 October 2026 |
| AI provenance | This audit used the OpenAI model Daybreak Blue at the ultra reasoning level. OpenAI Codex generated and selected the title and intentionally chose its “Jevil is in the details” wordplay. |
| Reproduction status | Full primary and fresh-context independent AI reproduction passed on two different keys; independent human verification was not performed and is optional provenance |
| Publication status | Verified attack; independent Publication Review passed |

## Impact

Jevil reuses one committed low-degree state across its bounded number of
ordinary signatures. At the affected profile, the initial codeword consists
of four rows, each determined by 32,768 field evaluations. Every ordinary
signature authenticates 64 outer positions, and each width-four leaf supplies
one evaluation from every row. The positions therefore accumulate across
signatures much faster than a scalar accounting suggests.

Once 32,768 distinct outer positions have appeared, standard interpolation
recovers all four rows. The recovered rows reconstruct the committed
`c || r_zk` state. The attacker checks both public bindings by reproducing the
public evaluation `w=f(z)` and the original Merkle root, then invokes the
ordinary signing path with fresh proof randomness for a message absent from
the query set. The ordinary verifier accepts the resulting signature.

The primary attack reached this endpoint from 641 ordinary signatures. A
separately written fresh-context implementation reached it on a new key from
650 ordinary signatures. These are two successful one-key demonstrations, not
an estimate of a minimum query count or a broad success probability.

## Why this is below the advertised cliff

The paper explicitly advertises state recovery from signature 1,024, namely
`n_star+1`. That behavior is outside this audit's query budget and is already
shown by the author example and a public teaching repository.

This attack uses the width of each authenticated leaf. A single opening
reveals four row evaluations at one outer position. The primary and independent
runs reached 35,203 and 35,603 distinct positions with 641 and 650 ordinary
signatures, respectively. Both exceed the 32,768-position interpolation
threshold while remaining below 1,023 queries. Neither run requested or used
signature 1,024 or zero-based query index 1,023.

## Exact scope

The executable target is the current fourth ePrint revision and the official
source at commit
[`905466fbe3be99d90fd41e461e0c68271d09104b`](https://github.com/symbolicsoft/jevil/commit/905466fbe3be99d90fd41e461e0c68271d09104b).
The PDF SHA-256 is
`c0da79bdf8b2d2c9667d6167d6ab008b8eeaf838b463a40eb64f2abe123c01c5`,
and the source tree is
`f4a7366dac1a1f079186d87a2aca79c9918ee79e`.

The affected source-backed profile is:

```text
n_star / advertised cliff     1023 / 1024
initial openings per signature 64
internal domain size           131072
row count                      4
row degree bound               degree < 32768
main RS rate / interleaving    1/4 / 4
Poseidon2 capacity             4
public key / secret key        68 bytes / 32 bytes
signature size                 about 337 KiB
```

The paper claims greater-than-124-bit classical `EUF-CMA-n*` security for at
most 1,023 ordinary signatures and at most `2^128` random-oracle queries. The
attack violates that bounded signing claim at the full source-backed profile.
Capacity `c=6` appears only as an unimplemented discussion and is outside this
result.

## Design-level reasoning

The attack uses only information that ordinary verification must authenticate:

1. Collect ordinary signatures on distinct chosen messages under one public
   key.
2. Recompute the Fiat--Shamir positions and run the ordinary verification
   path before accepting an opening.
3. For each valid initial opening, authenticate its four-symbol leaf against
   the public root and retain the four row evaluations at that outer position.
4. After at least 32,768 distinct positions have accumulated, interpolate each
   degree-below-32,768 row and re-encode it over the full domain.
5. Check every retained opening, reconstruct the committed `c || r_zk` state,
   and require both the public evaluation and public root to match.
6. Use that equivalent signing state with independently generated proof
   randomness to sign a previously unqueried message.
7. Submit the serialized result to the unchanged ordinary verifier and require
   strict mutation controls to reject.

The source lays out `c || r_zk` as contiguous row chunks, whereas the cited
zk-WHIR Definition 3.22 uses a four-row allocation. This difference changes
some partial-leakage accounting, but it does not remove complete recovery:
under either coherent width-four interpretation, each authenticated outer
position supplies one value from each of four rows, and 32,768 distinct
positions determine every row. The executable demonstrations use the pinned
source layout. No separate paper-faithful implementation of the
under-specified literal stripe map was executed.

## Primary full-parameter result

`JEVIL-EXP-001` retained 641 ordinary responses at query indices 0 through
640. All responses passed ordinary verification before extraction. Their
41,024 authenticated openings covered 35,203 distinct outer positions, with
no conflicting values. Public-only recovery reconstructed all four rows, the
public evaluation, and the exact target root, then produced an accepted
signature on a message absent from all queries.

- Fresh message SHA-256:
  `8ce41393d2090c73c23e3f2d108abe774370bd65429fc42a09772dcbe8a038ee`.
- Fresh signature SHA-256:
  `3096cea57f85088a8a6c3eeba412b97a04a70ce940fd95696ff3b9f4b0f3f893`.
- Fresh signature size: 343,532 bytes.
- Public recovery: 486.90 s wall time, 143,756 KiB peak RSS, one worker.
- Collection: four parallel one-worker shards; slowest shard 203.05 s and
  largest per-process peak 131,060 KiB.

The ordinary source files used for signing and verification were unchanged:

```text
src/sign.rs    34a61da541e7239402e2e49fedee76aaa50fc4c328c49cc9a307dca3bac2fb74
src/verify.rs  d84341b99aa3b76413c20118f7fb0a78886754e1d9c7c0f952c7f930037e569b
Cargo.lock     a13a82ddbe35d97e7cd9f0056af036695d0c6bab0202cb9b6bd351ec09b65d77
```

The run rejected a changed message, changed public root, corrupted recovered
row, and altered signature. A hostile reviewer then replayed the complete
sealed public corpus with one worker, reproduced every stable recovery field,
and created a different accepted fresh signature. A checker linked only to a
pristine source extraction accepted the primary forgery and rejected its
message, root, and signature mutations.

## Fresh-context independent reproduction

`JEVIL-EXP-002` was designed and sealed before execution. It used independently
written extraction, interpolation, recovered-state, oracle, and verifier code;
a new key from operating-system randomness; a disjoint message namespace; and
no primary source, transcript, recovered row, key, or generated artifact.

The independent run collected 650 responses at indices 0 through 649. All 650
passed ordinary verification. Its 41,600 authenticated openings covered
35,603 distinct positions. It recovered and re-encoded all four rows, matched
every retained opening, reproduced the exact public root and evaluation, and
signed an unqueried message. Both the attack build and a second untouched
source extraction accepted the forgery.

- Fresh message SHA-256:
  `b51eba4cebdd7a40627bc0e45b285ecedab3d62a3ff40e3be6663d110015c547`.
- Fresh signature SHA-256:
  `7e7b8fa3a213fcbfe6fe26792d5f8233df5268eb54914d217f3dd500e1066ed1`.
- Fresh signature size: 332,140 bytes.
- Oracle collection: 799.13 s, 131,256 KiB peak RSS, one worker.
- Public recovery and forgery: 253.12 s, 150,380 KiB peak RSS, one worker.
- Untouched-source verifier and controls: 0.93 s, 91,840 KiB peak RSS, one
  worker.

Changed-message, changed-root, altered-signature, and corrupted-row controls
all rejected. The fresh message was absent from the query set, the fresh
signature was distinct from every oracle response, and the recovery process
had only the public corpus as input.

## Reproduction interface

The public package must contain both `paper/` and `reproducer/`. The planned
reproducer interface is:

```sh
cd reproducer
./reproduce.sh --smoke
./reproduce.sh --full
```

Smoke mode checks the structural attack invariant and terminates with:

```text
JEVIL STRUCTURE SMOKE: PASS
```

Full mode builds the pinned source, generates a fresh `n_star=1023` key,
collects 650 ordinary signatures, recovers the four rows from public artifacts,
signs a fresh message, invokes a separately built untouched-source verifier,
and runs the registered controls. It terminates with:

```text
JEVIL FULL ATTACK REPRODUCTION: PASS
```

The final package must retain canonical public result files, source pins,
commands, timing and memory records, and SHA-256 manifests. It must not retain
the generated secret seed or raw private signer state.

## Attack history and mandatory disclosures

No prior public practical signing attack against the current fourth-revision
Jevil profile at `n_star=1023`, `c=4`, using at most 1,023 ordinary signing
queries was located in the searches performed through 15 October 2026.

This is a bounded exact-profile statement. It does not claim that Jevil was
previously unattacked or that this is the first attack on anything named
Jevil. Public search cannot exclude private, removed, unpublished, or
unindexed work, and citation indexes can lag.

Two earlier public records require explicit disclosure:

- On 26 May 2026, author commit
  [`3c7968ddacf4bddcbd178b3e7a61625148dabf9c`](https://github.com/symbolicsoft/jevil/commit/3c7968ddacf4bddcbd178b3e7a61625148dabf9c)
  bound WHIR verification to `pk.root` and added
  `forged_root_attack_now_rejected`. The prior development verifier allowed a
  prover-chosen commitment and a root-substitution forgery. The fix predates
  the paper's receipt and is present in the frozen current target. This is a
  public pre-publication development-version forgery, fixed before the current
  target, and is not prior art for the width-four attack.
- On 2 June 2026, the public
  [`jedisct1/security-audits`](https://huggingface.co/datasets/jedisct1/security-audits/commit/cea51fd3cec15036e4d845d0fb6d3f5628709d60)
  Swival trace reported that `verify_multiproof` accepts padded index 13 for an
  artificial 13-leaf tree. Its normalized `src/merkle.rs` matches the current
  file. The affected deployment here uses power-of-two commitment sizes, and
  the ordinary verifier derives positions from the transcript modulo the
  codeword length. The trace gives no located signing-state recovery,
  fresh-message forgery, or width-four recovery for this profile. It remains a
  public current-file helper bounds bug and is disclosed as such.

The paper's advertised 1,024th-signature recovery and the corresponding
public examples are also related history. They are out of this audit's query
budget and do not reproduce the 641- or 650-query result.

## Technique attribution

The package claims no originality for Reed--Solomon interpolation, product
trees, inverse transforms, fast polynomial division, Merkle authentication,
or the general idea of accumulating openings from a reused commitment. The
result is the application of those standard tools to the four values exposed
by every ordinary Jevil initial opening at the current profile, followed by a
demonstrated equivalent-state signing consequence.

## Limitations

- The primary and independent results each use one key. Together they show two
  successful full-parameter attacks on different keys; they do not establish a
  broad empirical success rate.
- The 641- and 650-query counts are observed successful counts, not a claimed
  optimum or minimum.
- Only revision 4 of four public PDF revisions was recovered for bytewise
  inspection.
- The pinned source commit predates the final PDF by about 19 hours 47 minutes,
  and the paper does not name a source commit.
- The executable result uses the source's contiguous row allocation. The
  complete-recovery threshold also follows under the cited four-row layout,
  but no separate paper-faithful implementation of the under-specified literal
  stripe map was executed.
- The primary processes used source and path separation rather than a kernel
  sandbox. The fresh-context reproduction additionally used a scrubbed
  environment and an unreadable private-seed directory, but a mount namespace
  and syscall trace were unavailable under the managed kernel policy.
- The primary seal did not include the exact primary-time release binary. The
  hostile review hashed the extant binary and replayed the sealed inputs; the
  independent reproduction separately retained executed-source and binary
  evidence.
- Runtime and the number of distinct positions depend on the machine and
  random-oracle occupancy. The attack requires at least 32,768 distinct outer
  positions before interpolation.

## AI provenance

This audit used the OpenAI model Daybreak Blue at the ultra reasoning level.
OpenAI Codex performed AI-assisted target analysis, attack-history research,
cryptanalysis, implementation, experimentation, and technical writing.
Separately tasked AI agents performed component review, hostile adversarial
review, fresh-context independent reproduction, and the final exact-target
history recheck.

OpenAI Codex generated and selected the title and intentionally chose
“The Jevil Is in the Details” as scheme-related wordplay on “the devil is in
the details”: the attack depends on accounting for all four field values in
each authenticated Jevil leaf. Independent human verification was not
performed; it is optional provenance and is not a publication requirement.

## Sources

- [Target: IACR ePrint 2026/1103](https://eprint.iacr.org/2026/1103)
- [Pinned source commit](https://github.com/symbolicsoft/jevil/commit/905466fbe3be99d90fd41e461e0c68271d09104b)
- [Pre-publication root-binding fix](https://github.com/symbolicsoft/jevil/commit/3c7968ddacf4bddcbd178b3e7a61625148dabf9c)
- [June 2 public security-audit trace](https://huggingface.co/datasets/jedisct1/security-audits/commit/cea51fd3cec15036e4d845d0fb6d3f5628709d60)
- [Public teaching repository for the advertised cliff](https://github.com/systemslibrarian/crypto-lab-jevil)
- [`paper/attack.tex`](paper/attack.tex)
- [`reproducer/README.md`](reproducer/README.md)
- [`affected-rows.json`](affected-rows.json)
