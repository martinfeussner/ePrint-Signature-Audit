# DualMS 2.0 Takes the Hint: Zero-Signing-Query Forgeries from Hint Slack

> **AI disclosure.** This audit used the OpenAI model Daybreak Blue at the ultra reasoning level.
> OpenAI Codex generated and selected this title and
> deliberately chose “Takes the Hint” as wordplay on the verifier hint
> absorbing its reconstruction. OpenAI Codex assisted with the cryptanalysis,
> implementation, experiments, review coordination, and technical writing. A
> separately tasked AI agent performed hostile adversarial review, and a
> fresh-context AI agent independently reproduced the result from the pinned
> target and pre-attack evidence.
>
> Independent Publication Review returned PASS / NO VETO for the sealed pre-integration candidate (manifest SHA-256 cd8a152ee60fef056df0c6c08f4f612848ee2007998259149037b698315899a0). Independent human verification was not performed and is not required.
>
> **Publication status.** `VERIFIED_ATTACK`.

This publication describes public-key-only fresh-message
forgeries against both rounded DualMS 2.0 rows advertised in Table 6 of Lai,
Chen, Liu, Zhao, Wang, and Wang's
[*DualMS 2.0: Practical Lattice-Based Two-Round Fiat-Shamir Multi-Signature
with Better Efficiency*](https://eprint.iacr.org/2026/1941), IACR ePrint
2026/1941. The attack makes **zero signing-oracle queries**. It does make
ordinary public random-oracle queries to `Hsig`: a practical number for the
32-signer row and one for the 1,024-signer row.

The paper is in [`paper/attack.tex`](paper/attack.tex). The public
standard-library reproducer is documented in
[`reproducer/README.md`](reproducer/README.md).

| Field | Verified result |
|---|---|
| Publication status | `VERIFIED_ATTACK` |
| Scheme | Rounded DualMS 2.0 same-message multisignature |
| Target | IACR ePrint 2026/1941; retained PDF SHA-256 `fdbf743b5108e66efefa686aac92e73f995a2e3e4b94ac27c38c89ead5a26691` |
| Target authors | Qiqi Lai, Chongshen Chen, Feng-Hao Liu, Tianyu Zhao, Qi Wang, Zhedong Wang |
| Outcome | Public-key-only, zero-signing-oracle-query fresh-message forgery against both advertised rounded rows |
| 32-signer work | Per-candidate success at least `0.0300039691`; expected at most `33.329` `Hsig` queries; 99 distinct candidates succeed with probability at least `0.950996` |
| 1,024-signer work | Every canonical hint passes at zero response; one `Hsig` query |
| Primary evidence | Ordinary verifier accepted both exact paper/artifact profiles; 10 `Hsig` queries at `n=32`, one at `n=1024`; zero signing-oracle queries |
| Hostile review | `PASS`; attack survives, with explicit codec, source, and history limitations |
| Independent evidence | Fresh-context clean-room reproduction passed both exact rows; 4 `Hsig` queries at `n=32`, one at `n=1024`; zero signing-oracle queries; all sealed controls behaved as specified |
| Publication Review | `PASS / NO VETO`; review ID `dualms-2-2026-1941-publication-review-v2-20261016T201049Z` |
| Layer | Printed design-level mathematical verifier in the random-oracle model |
| Technique lineage | Related to NGCC CS `sign-07-2` and the general hint-soundness warning in EP4224785A1; no technique novelty claim |
| Author implementation | No successful source-native execution; the Go artifact uses different NTT-friendly moduli |
| Human verification | Not performed; not required |

## The verifier gap

Write `aggpk` for the rounded aggregate public key. For an aggregate signature
`(c,z,r,rbar,h)`, the printed ordinary verifier computes

```text
[b,Bmat] = Hcom(aggpk,message)
u = round_nu_w(A*z - c*2^nu_b*aggpk + r*b + Bmat*rbar)
w_check = u + h  in R_qw^m
```

It then checks

```text
Hsig(w_check,message,aggpk) == c
||(z,2^nu_w*h)||_2 <= B
||r||_2 <= B'_n
||rbar||_2 <= B''_n.
```

The verifier does not separately establish that `h` came from an honest
rounded commitment. For any aggregate public key and attacker-chosen fresh
message, choose `w`, query

```text
c = Hsig(w,message,aggpk),
```

and set

```text
z = 0, r = 0, rbar = 0,
u = round_nu_w(-c*2^nu_b*aggpk),
h = w-u in R_qw^m.
```

The verifier reconstructs exactly `u+h=w`, so its hash equation holds. The
terms derived from `Hcom` are evaluated but multiplied by zero. The two
separate response norms are also zero. Acceptance depends only on whether the
scaled hint fits the joint `z/h` bound.

This works for every public aggregate key. It does not need a signer secret,
malformed key, repeated nonce, parser ambiguity, hash collision, selected
challenge, side channel, or fault.

## Both advertised rounded rows

The paper prints only the bit length of `q`. The exact integer moduli below
come from the paper-linked author Sage profiles and prime-selection routine.

| Row | `(n,N,m,ell,eta,kappa,nu_b,nu_w)` | Exact `q` | `(q_b,q_w)` | Result |
|---|---|---:|---:|---|
| rounded 32 | `(32,256,7,6,1,60,11,26)` | `2113928077` | `(1032191,31)` | Practical probabilistic forgery |
| rounded 1024 | `(1024,256,10,6,1,60,11,28)` | `4160748533` | `(2031615,15)` | Every canonical hint passes |

For the 32-signer row, the paper bound gives

```text
B = 24959699776.3818219481128...
floor((B/2^26)^2) = 138330.
```

The 1,792 centered coefficients of a fresh hint are uniform on
`{-15,...,15}` in the ideal random-oracle experiment. A coefficient square has
mean 80, variance 5104, and centered third absolute moment `15494144/31`.
A Berry--Esseen calculation with constant 0.56 and no continuity correction
gives

```text
Pr[||h||_2^2 <= 138330] >= 0.0300039691166414.
```

The corresponding conservative expected-query upper bound is `33.329`, and
99 distinct candidates succeed with probability at least `0.95099665`. The
prospectively sealed primary run succeeded at candidate 10 with
`||h||_2^2=138286`.

For the 1,024-signer row,

```text
B = 4872415274260.441301417139...
floor((B/2^28)^2) = 329464658.
```

Here `q_w=15`, so each centered hint coefficient has magnitude at most 7.
Across `10*256` coefficients,

```text
max ||h||_2^2 = 10*256*7^2 = 125440 < 329464658.
```

Every canonical hint therefore satisfies the printed joint bound when `z=0`.
The primary run needed one `Hsig` query. Its registration list contained one
honest challenge public key and 1,023 distinct adversarial public keys, which
is permitted by the paper's MS-UF-CMA game.

## Reproduction

The public package requires only Python's standard library. To emit the
canonical single-profile publication fixture byte-for-byte:

```sh
python3 reproduce.py --reference
```

To execute both advertised rows with fresh operating-system entropy:

```sh
python3 reproduce.py
```

The no-argument root wrapper constructs one honest challenge key and the remaining
adversarial registration keys, runs ordinary `KeyAgg`, forges a never-signed
message, submits the result to a complete ordinary verifier, and checks
changed-message, changed-challenge, changed-response, range, and changed-list
controls using a newly sampled 32-byte seed. It hashes a direct injective
length-delimited encoding of the full registration list. The separate stable
all-row helper executes both rows with the committed publication seed when
invoked as `python3 reproduce-all-rows.py`; its `--reference` mode emits the
canonical `all-rows-reference-output.json` fixture byte-for-byte. Successful
execution contains
`DUALMS 2.0 ATTACK REPRODUCTION: PASS`.

This executable is the public reproducer. Its local package self-test is
supplemental validation and is distinct from the sealed
fresh-context independent reproduction described below.

## Independent reproduction

A fresh-context AI agent independently implemented the paper's ring
arithmetic, `Setup`, `KeyGen`, complete-list `KeyAgg`, random-oracle
interfaces, codecs, ordinary verifier, and forger from the pinned target and
pre-attack profile evidence. It did not read the sender intake, primary code,
primary outputs, or primary reports before sealing. The prospectively fixed
command then ran once with one worker and a 4 GiB address-space limit.

| Field | 32 signers | 1,024 signers |
|---|---:|---:|
| Signing-oracle queries | 0 | 0 |
| Attacker `Hsig` queries | 4 | 1 |
| Observed `||h||_2^2` | 137833 | 48944 |
| Allowed `||h||_2^2` | 138330 | 329464658 |
| Ordinary verifier | accept | accept |
| Registration list | 32 distinct honest keys | 1 honest + 1,023 distinct adversarial registrations |

The 1,024-signer run retained an 11,294,048-byte full-list witness and fed its
direct injective framing into every `Hagg` query without a list prehash. The
controls rejected changed messages, challenge mutations, invalid ranges,
uncompensated responses, oversized 32-signer hints, and compensated excessive
`rbar` values at their sealed conditions. The predicted maximum canonical
1,024-signer hint passed the otherwise vacuous hint bound. The complete run
took 28.16 seconds, used 252,432 KiB peak RSS, and made no network request.

The independent verdict is
`PASS_INDEPENDENT_REPRODUCTION_BOTH_ADVERTISED_ROUNDED_ROWS`. Its pre-execution
manifest has SHA-256
`f493f7a434468639b92330878b0896af920e044b474c324da0ed2084072ab7bb`,
its post-run manifest has SHA-256
`a684ab5117043444f2e38ac6b36409010b44041054c325268fd7aaf80c0085cb`,
and its verdict has SHA-256
`f624f7f7c8ad10097db96bece708c2c95c0bd6ccda6eb17acef7d142bf8c5842`.

## Exact scope and limitations

- The retained 39-page PDF matches the current official title, authors,
  abstract, dates, and linked artifact. The official PDF and version-index
  endpoints returned HTTP 403, so this package pins the body by SHA-256 and
  does not claim official byte identity or assign a version ordinal.
- Table 6 gives only `ceil(log2(q))`. The exact integer moduli are pinned by
  the paper-linked author artifact, not by the paper body alone.
- The author Go implementation uses the distinct NTT-friendly moduli
  `2113927681` and `4160727041`. The frozen source-native control stopped
  before compilation because its module cache was unwritable. No author-code
  acceptance claim is made.
- The paper defines its random oracles on bitstrings but gives no normative
  final tuple framing, aggregate-key codec, aggregate-signature codec, or
  known-answer vector. The public reproducer declares a deterministic
  direct length-delimited completion. The attack is independent of that
  completion because the forger and verifier call the same `Hsig` interface
  and no collision or alias is used.
- The `n=32` claim is probabilistic in the ideal random-oracle model. The
  stated probability is a conservative analytical lower bound, not an
  empirical success estimate.
- The `n=1024` all-hint statement applies to canonical elements of the printed
  `R_15^10` hint space at the advertised row.
- The target was approved only 34 days before the final history search and was
  not consistently indexed. The final history result is dated and bounded; it
  cannot exclude private, deleted, unpublished, or unindexed work.

## Related technique and history

We located no previous public attack against DualMS 2.0, including either advertised rounded Table-6 profile (n=32 and n=1024), in searches completed on 16 October 2026. The closest earlier public analogue we located is NGCC CS finding sign-07-2, where a differently structured verifier permits a hint to absorb reconstruction terms; our result targets DualMS 2.0's printed verifier and parameter bounds and does not rely on CS's challenge-sign blindness or support grind. We make no claim that the general hint-absorption technique is novel.

The sealed final-history recheck returned
`PASS / NO_PRIOR_PUBLIC_EXACT_TARGET_ATTACK_LOCATED /
MANDATORY_RELATED_TECHNIQUE_ATTRIBUTION_RETAINED`. Its report, verdict,
source-query ledger, and manifest SHA-256 values are respectively
`484f630020e4b9812891c99e026e0a6cb78e974888cad9c28367f8761b4b82b9`,
`4f99ca5db817198efb730ae1589834a91f7083620706c2ff8eea0fb236e1cb7a`,
`1e46b6a308cc9fbc294626aa42b418789ba977f20e5e23d55a39183cffd739c3`,
and `2ec10a0339178163b80a5016d76b8612348a11a2bf9220af0e3a2af27d64144e`.
The detached manifest-record SHA-256 is
`b2bc49d218e87cc65de9d520c864da8ac619e0c9af6a5e49553a8921818e1fbf`.

The closest earlier public analogue located is
[NGCC CS finding `sign-07-2`](https://ngcc.dev/reports/sign-07.html#sign-07-2-verifier-challenge-sign-blindness-enables-universal-forgery).
It also uses a signer-controlled hint to absorb verifier reconstruction terms,
but it attacks a different construction through challenge-sign blindness and
a support grind. Its reported full-size attacks remain infeasible. The
present DualMS 2.0 attack does not use those mechanisms.

[EP4224785A1](https://patents.google.com/patent/EP4224785A1/en), with priority
3 February 2022 and publication 9 August 2023, gives an earlier general
warning that a reconstruction hint can break soundness if it is not
independently constrained. It neither analyzes DualMS 2.0 nor establishes
that DualMS 2.0's particular joint bound is loose.

This report claims no novelty for hint absorption, hint-soundness analysis, or
the general attack technique. Its contribution is the exact application to
both advertised rounded DualMS 2.0 rows.

## Repair direction

A repair must stop an attacker-chosen hint from absorbing an arbitrary
verifier reconstruction while remaining inside the acceptance region. This
could require a separately sound hint bound or a redesign that proves the
hint is consistent with an honestly generated commitment. The complete
correctness and security analysis, both concrete rows, and the final codec
would then need to be updated together. This package does not validate a
drop-in repair.

## Acknowledgements

The computations were performed on the Norwegian Research and Education Cloud (NREC), using resources provided by the University of Bergen and the University of Oslo.

## Files

- [`metadata.json`](metadata.json): machine-readable publication record;
- [`affected-rows.json`](affected-rows.json): exact affected-profile summary;
- [`paper/attack.tex`](paper/attack.tex): self-contained paper;
- [`reproducer/dualms2_reference.py`](reproducer/dualms2_reference.py): general
  ordinary verifier, direct-list `KeyAgg`, and public forger;
- [`reproducer/runner.py`](reproducer/runner.py): command-line runner;
- [`reproduce.py`](reproduce.py): fresh-entropy wrapper;
- [`reproduce-all-rows.py`](reproduce-all-rows.py): stable two-row wrapper;
- [`reference-output.json`](reference-output.json): canonical stable package
  replay summary, distinct from the independent-reproduction evidence;
- [`all-rows-reference-output.json`](all-rows-reference-output.json):
  canonical two-row replay record;
- [`validate-package.py`](validate-package.py): standard-library package validator;
- [`SHA256SUMS`](SHA256SUMS): package file seal.
