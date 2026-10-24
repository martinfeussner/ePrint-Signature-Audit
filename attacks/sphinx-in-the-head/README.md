# Sphinx-in-the-Head

> **VERIFIED ATTACK.** A one-signing-query fresh-message non-frameability
> forgery in the complete typed paper model. The result passed primary and
> fresh-context independent reproduction, hostile review, final exact-target
> history review, and independent exact-byte publication review.

| Field | Value |
|---|---|
| Scheme | Sphinx-in-the-Head: Group Signatures from Symmetric Primitives |
| ePrint | [2024/649](https://eprint.iacr.org/2024/649), current official 66-page PDF frozen by SHA-256; revision ordinal unresolved |
| Authors | Liqun Chen, Changyu Dong, Christopher J. P. Newton, Yalan Wang |
| Family | Fully dynamic group signature from symmetric primitives with LowMC/Davies--Meyer hashing |
| Competition history | None applicable |
| Prior public attack history | None located against the exact scheme, version, and profile in the searches performed as of 2026-10-24 |
| Result | One-query adaptive fresh-message forgery and Figure-8 non-frameability violation in the complete typed paper model |
| Technique | Deterministic zero-extension/message-randomizer retargeting through the unframed `H1(msg\|str)` boundary |
| Technique originality | No general novelty claimed; Davies--Meyer, zero-extension, fixed-point, and retargeting ideas are established background |
| Affected parameters | TEST2: `(n,q,h,d,k,NR,NU)=(255,1024,1,16,70,1120,70)`, claimed quantum-128 context, group capacity `2^10`, Appendix-B Algorithm-2 zero padding |
| Queries | 1 honest `GSigHU` query on the empty string; 1 permitted `TraceU` query with `RL_0` |
| Measured independent replay | 0.01501373597420752 s candidate-internal time, 21,504 KiB peak `RUSAGE_SELF`, one worker, one trial |
| Design level | Yes, for the complete typed construction printed in the paper |
| Condition | Appendix E.2's one- and two-block formulas instantiate the two relevant `sid` calls |
| Independent reproduction | PASS; exact clean-room code and evidence retained byte-for-byte and separately validated |
| Execution boundary | Ideal hidden-key proof/credential capabilities and ideal primitive surrogates; no author-byte or real LowMC/M-FORS/MPCitH execution |
| AI provenance | AI-assisted reconstruction, cryptanalysis, implementation coordination, reproduction, review, and writing; Daybreak Blue at ultra reasoning |
| Human verification | Not performed and not required by the project |
| Last attack-history search | 24 October 2026; final exact-target recheck PASS |

## Impact

One honest signature on the empty bit string can be transformed into a
signature on a never-queried 255-bit message. The ordinary typed-paper
verifier accepts the transformed object, and the paper's ordinary tracing and
tracing-verification algorithms attribute it to the honest member. The output
therefore wins the paper's Figure-8 non-frameability game and also meets the
stricter ordinary fresh-message condition.

The result does not recover a member key, an equivalent signing key, a proof
witness, or an authority secret. It is a design-level paper-model result, not
a claim that a released binary or deployed verifier accepts particular bytes.

## Attack at a glance

The paper signs with

```text
sid   = H1(msg || str)
Sigma = (str, stt, com, pi_G).
```

Obtain one honest signature on the empty string:

```text
Sigma_0 = (u, stt, com, pi_G),   |u| = 255.
```

Then output

```text
msg*   = u
Sigma* = (0^255, stt, com, pi_G).
```

Appendix E.2 gives, for the relevant one- and two-block cases,

```text
H1(u)        = low_mc(u, 0^255)
H1(u||0^255) = low_mc(u, 0^255) xor 0^255 = H1(u).
```

The original and transformed pairs therefore induce the same `sid`. The raw
`msg` and `str` are not separately present in the printed public statement
`(gp,rpk,gid,sid,stt,com)` for `pi_G`, so retaining `stt`, `com`, and `pi_G`
leaves that statement unchanged. With `RL_0` empty, ordinary `GVf` accepts.
The permitted `TraceU` query returns the honest identity and `pi_t*`; the final
`TVf` call accepts at `tau=0`.

The sole signing query is on the 0-bit string, while `msg*` is a 255-bit
string. Freshness therefore holds even in the rare edge case `u=0^255`, where
the numeric values are both zero but the typed lengths differ. The independent
run sampled a nonzero `u`; the zero edge is a static consequence, not an
empirically observed event.

## Exact scope

The profile is
`SITH-2024-649-HBGS-TEST2-N255-Q1024-H1-D16-K70-NR1120-NU70-Q128-G2P10-PAPER-ALG2-ZEROPAD`.
It uses the exact tuple `(255,1024,1,16,70,1120,70)`, 16 modeled MPC parties,
and the authors' claimed 128-bit quantum context. Both evaluated M-FORS top
trees start with 70 roots, append 58 `0^255` leaves to capacity 128, and use a
complete height-7 Appendix-B Algorithm-2 tree. The Appendix-E.5 node-lifting
variant is excluded.

The typed model covers ordinary `GSig`, `GVf`, `Trace`, and `TVf`, plus the
complete Figure-8 endpoint: one `AddHU`, one `GSigHU(epsilon)`, one
`TraceU(RL_0,...)`, exact-pair freshness, strict message freshness, ordinary
verification, honest attribution, and `tau=0`.

The official [HBGS repository](https://github.com/UoS-SCCS/HBGS) is pinned at
commit `e13fe83cdc4a636dd8c72a37545090eef99812b7`, tree
`2cb34c40bff268dcdae3a1179ff6168f35fd91a4`. It is a component/test
implementation rather than a complete outer scheme. It defines no full
`Join/GSig/GVf/Trace/Revoke` API, outer codec, revocation loop, arbitrary-
length unary `H1`, SITH KAT, or mapping from its external 64-byte
`message_digest` and 32-byte `nonce` buffers to paper `msg`, `str`, or `sid`.
GitHub archive transport bytes differed between two acquisitions although the
Git commit and tree agreed; no archive-byte identity claim is made.

## Reproduction

Python 3 and its standard library are sufficient. From this directory, quick
mode validates retained evidence without importing or running the attack
model:

```bash
python3 -B reproduce.py --reference
./reproducer/reproduce.sh --quick
make check
```

A fresh user-run after publication requires a new output path:

```bash
./reproducer/reproduce.sh --full fresh-evidence.json
# equivalently:
python3 -B reproduce-all-rows.py --trials 1 --output fresh-evidence.json
python3 -B reproducer/validate_evidence.py --evidence fresh-evidence.json
```

The full command executes the clean-room typed model with fresh operating-
system randomness. It is not run by `make check`, the metadata validator, or
ordinary CI. The output path must not exist; the program writes it with
exclusive-create semantics.

## Evidence and controls

The exact public clean-room program is SHA-256
`3b3b62d9018b28cda7a279fd2145697421f5b132a5d3728d6c99daf2178ee863`.
Its historical header says it was prospectively sealed and not executed; that
header is intentionally retained so the public bytes stay identical to the
reviewed pre-run bytes. Those exact bytes subsequently ran once and emitted
[`evidence/evidence.json`](evidence/evidence.json), SHA-256
`f4b829edf9f822a8f44fbbf94108416a603571e7305d2e5bc1671e484995cfcd`.

The independent result was one success in one trial. A separate validator
passed 166/166 assertions, and a separate hostile result review found no
blocker. The evidence reports ordinary original and transformed acceptance,
the Appendix-E.2 identity, exact retention of `stt`, `com`, and `pi_G`, honest
tracing identity, final `TVf` acceptance, message and exact-pair freshness,
and Figure-8 return one. It contains public fingerprints but no raw member or
authority secret.

All eight controls passed:

- public-only zero-query signature construction rejected;
- public credential synthesis rejected;
- public proof synthesis rejected;
- changed-statement proof reuse rejected;
- signature-field mutation rejected;
- nonzero replacement `str` rejected;
- revocation with the honest tracing key rejected; and
- a separate length-framed, domain-separated `H1` world rejected the
  transformation while accepting its original signature.

The corrected primary typed model independently passed 48/48 checks in one
3.48-second externally timed run with 21,504 KiB peak RSS. Its code is not the
source of this public reproducer.

## Relationship to known techniques

Davies--Meyer feed-forward hashing, fixed-point observations, variable-length
hash framing, and message-randomizer retargeting are established ideas. Here
the decisive equality needs neither a LowMC break nor a fixed-point search:
XOR feed-forward of the all-zero second block is identically zero. Generic
work on Davies--Meyer hashing, randomized hashing, SPHINCS+, FORS, LowMC,
Picnic, or MPC-in-the-Head is related background, not a prior attack against
this exact target. No technique-novelty claim is made.

The closest exact-paper criticism located, DGSP (ePrint 2025/760), concerns
signature size and opening efficiency or scalability rather than a forgery,
key/witness recovery, or non-frameability break. No prior public substantive
attack against the exact scheme, version, and profile was located in the
searches performed as of 2026-10-24. That conclusion is bounded by 403/WAF
blocks, rate limits, paywalls, citation-index disagreement and lag, and
private, deleted, embargoed, or unindexed material.

## Limitations

- The result assumes the Appendix-E.2 one-/two-block formulas govern the two
  relevant `sid` evaluations; it does not invent a general framing rule.
- The proof and credential systems are ideal hidden-key capabilities. The
  model uses an ideal domain-separated LowMC surrogate, ideal M-FORS values,
  and a typed fallback for other `H1` arities.
- No real LowMC, M-FORS, F-SPHINCS+, KKW, Picnic, MPC-in-the-Head,
  Fiat--Shamir/NIZK, serializer, or parser is executed.
- No official-source, author-byte, outer-codec, interoperability, KAT, or
  deployed-verifier acceptance is claimed.
- One trial establishes the deterministic scoped transformation; it is not a
  statistical success-rate estimate.
- The independent runtime is internal through trial completion, excluding
  final serialization and `fsync`; neither recorded runtime is an end-to-end
  scheme cost.
- The retained artifacts are consistent with one invocation, but artifact
  absence is not an operating-system audit of every historical execution.
- No secret or equivalent signing key, proof witness, credential, or authority
  secret is recovered.
- No equivalence between Appendix-B zero padding and Appendix-E.5 lifting is
  claimed.
- The attack-history conclusion is date- and search-bounded.

## Repair direction

Use an injective encoding of `msg` and `str`, for example explicit bit lengths
and domain separation, consistently in `GSig`, `GVf`, `Trace`, and `TVf`.
Specify the complete arbitrary-length `H1` dispatcher and outer codec, and add
known-answer tests covering the empty message and block boundaries. Binding
the raw operands or their unambiguous encoding into the group-proof statement
is another defense-in-depth direction. A revised construction needs a new
proof and interoperability testing; this package does not claim a drop-in
patch.

## Sources and provenance

- Target paper: [IACR ePrint 2024/649](https://eprint.iacr.org/2024/649)
- Venue DOI: [10.1145/3638763](https://doi.org/10.1145/3638763)
- Official component source: [pinned HBGS commit](https://github.com/UoS-SCCS/HBGS/tree/e13fe83cdc4a636dd8c72a37545090eef99812b7)
- Attack paper: [PDF](paper/attack.pdf) and [LaTeX source](paper/attack.tex)
- Public evidence: [`evidence/`](evidence/)
- Reproducer provenance: [`reproducer/PROVENANCE.md`](reproducer/PROVENANCE.md)

OpenAI Codex reconstructed and analyzed the target, coordinated separate
hostile review and fresh-context independent reproduction, and drafted this
package. The audit used the OpenAI model Daybreak Blue at the ultra reasoning
level; OpenAI Codex generated and selected the title and the scheme-specific
“Riddle Me Zero” wordplay. Independent human verification has not been
performed; it is optional and not a publication requirement. The independent
AI exact-byte publication review returned GO, and this release is classified
as `VERIFIED_ATTACK`.
