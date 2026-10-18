# DSS-MS Unmasked: Public Cross-Join Sanitizer-Key Recovery and Fresh-Message Forgery

> **AI disclosure.** This audit used the OpenAI model Daybreak Blue at the ultra
> reasoning level. OpenAI Codex generated and selected this title and
> deliberately chose “Unmasked” as wordplay on DSS-MS's public sanitizer-key
> mask revealing the sanitizer key. OpenAI Codex assisted with paper and source
> reconstruction, cryptanalysis, implementation, experimentation, review
> coordination, and technical writing. A separately tasked AI reviewer checked
> the sealed primary evidence for internal consistency and returned `PASS`.
> A fresh-context AI agent independently reconstructed the target, executed
> eight prospectively sealed full-profile trials, and returned
> `PASS_INDEPENDENT_REPRODUCTION`. Separate final falsification and exact-target
> history reviews returned `PASS`. An independent AI Publication Reviewer
> reviewed the corrected package and returned `PASS_PUBLICATION_REVIEW`.
> Independent human verification was not performed; it is
> optional and is not a publication requirement.

## At a glance

| Field | Value |
|---|---|
| Scheme | Dynamic Sanitizable Signature with Multiple Sanitizers (DSS-MS) |
| Target | [IACR ePrint 2026/041](https://eprint.iacr.org/2026/041), current landing-visible body |
| Target authors | Mingwei Zeng, Qingyang Zhang, Jie Cui, Hong Zhong, and Fengqun Wang |
| Family | Schnorr-style sanitizable signature with a public CRT sanitizer-key mask |
| Layer | Design-level mathematical construction |
| Result | Recovery of the global sanitizer scalar, followed by a fresh-message forgery |
| Technique | Integer GCD across the public masks immediately before and after `Join` |
| Technique provenance | Established PA-CRT-lineage repeated-common-factor integer GCD; no technique novelty claimed |
| Affected profile | BLS12-381/SHA-256, 3,000 initial sanitizers, one ordinary `Join(+20)` |
| Conditions | Unit CRT-coefficient residual after one Join, or further retained ordinary public epochs until the cumulative residual is one |
| Attack inputs | Two public `S_x` epochs, public keys, and one valid signature |
| Signing queries | One valid signature; zero sanitizing queries |
| Primary evidence | PASS on one precommitted exact instance; 34.807209 s, 20,480 KiB peak RSS, one worker |
| Independent evidence | PASS; 7/8 exact recoveries after one Join; retained trial 6 recovered after two further public Join epochs |
| Verifier boundary | Source-equivalent reconstructed ordinary verifier; no compiled-author-binary claim |
| Independent cost | Eight-trial run: 372.77 s wall, 27,136 KiB peak RSS, one worker; one-Join trials 41.115--42.548 s |
| Attack history | Final exact-target recheck passed; no prior public DSS-MS attack located through 18 October 2026 |
| Status | Verified; independently AI-reproduced |

## Impact

DSS-MS places an unreduced integer `S_x` in the public parameters so an
authorized sanitizer can reduce it modulo its individual secret. A normal
`Join` republishes that value after extending the sanitizer set but retains the
same global scalar and public key. A passive observer who keeps both public
epochs can therefore recover the global sanitizer scalar when the two CRT
coefficients are coprime. The scalar grants the scheme's sanitization signing
power: starting from one valid signature, the observer can change the
sanitizable component and make the source-equivalent ordinary verifier accept
the resulting fresh full message.

The attack does not recover the original signer's Schnorr scalar. Its
signing consequence is still direct: an observer with no sanitizer secret
obtains the global capability intended to authorize changes to signed content.
The demonstrated message changes from `(m0,m)` to distinct `(m0,m')`; only the
sanitizable component changes, as required by the attack's scope.

## Public cross-Join key recovery

For pairwise-coprime sanitizer secrets `sk_i`, DSS-MS defines, over the
ordinary integers,

```text
N   = product_i sk_i
N_i = N / sk_i
y_i*N_i = 1 (mod sk_i)
A   = sum_i y_i*N_i
S_x = A*sk_s
PK_s = sk_s*P.
```

Neither the paper nor the pinned source reduces `A` or `S_x`. After adding
sanitizers, `Join` recomputes the CRT coefficient using the enlarged set and
publishes

```text
S'_x = A'*sk_s
```

under the unchanged `PK_s`. Hence

```text
gcd(S_x,S'_x) = sk_s*gcd(A,A').
```

The first and only precommitted full-profile primary instance had
`gcd(A,A')=1`. Its public GCD was exactly the 251-bit `sk_s`, confirmed without
ground truth by checking `gcd(S_x,S'_x)*P=PK_s`. This is one fixed-instance
primary result, not a measured all-key success probability. In the sealed
independent run, seven of eight fixed full-profile seeds had unit residual
after one Join. The retained eighth seed had residual 2 after the first Join
and again at 3,040 sanitizers; the cumulative GCD became exact at 3,060 after a
second additional `Join(+20)`, where the fresh-message forgery and controls
passed. Thus one-Join recovery is practical but not guaranteed, and additional
public epochs removed the one observed residual without reclassifying that
seed as a one-Join success.

## Fresh-message forgery

For a valid signature `(R,z,s,T)` on `M=(m0,m)`, the verifier reconstructs

```text
e  = H0(m,T)
CH = T + s*P + e*PK_s
c  = H1(m0,R,CH)
```

and checks `z*P = R + c*PK`. After recovering `sk_s`, select a distinct
sanitizable component `m'` and a scalar `k`, then set

```text
T' = CH - k*P
e' = H0(m',T')
s' = k - e'*sk_s (mod q).
```

The verifier reconstructs the same `CH`, so it derives the original challenge
and accepts `(R,z,s',T')` on fresh full message `(m0,m')`. The primary run also
showed that changing `m` without retargeting rejects, retargeting with
`sk_s+1` rejects, and checking the valid forgery under a different `PK_s`
rejects.

## Evidence and scope

The controlling PDF has SHA-256
`d35dcd98dc2442b6e263ef58276086832287a3f9d2f9e0131e4b0ad6c7324a20`.
The paper-linked source is pinned at paper-time commit
`b994a3f46cbe5501f47f53aa2e6942cff714b53a`, tree
`5d1b072040170d6df8bca709403d1e01d609536e`; the relevant core file remained
byte-identical at retrieved head
`b48e6359a0c3dce11cc6bf8445577770418d6d27`.

The primary standard-library reconstruction uses actual affine BLS12-381 G1
arithmetic and the source's SHA-256-to-scalar transcript conversion. It is
source-equivalent at the audited equations, but it is not the compiled author
binary and does not claim a normative wire-format known-answer match. The
author package supplies no fixed portable test vector.

The primary one-Join claim is limited to passive retention of two public `S_x`
epochs around one ordinary `Join(+20)`, plus one valid signature. The
independent cumulative variant retained further ordinary public epochs only
after recording its one-Join failure. Revoke is excluded
because the paper and source differ on its behavior. The omitted condition
`sk_s < min(sk_i)`, which causes some honest sanitizers to recover the wrong
literal residue, is a separate correctness defect and is neither an input to
nor part of this attack.

## Fresh-context independent reproduction

An independently written standard-library implementation was sealed before
eight full-profile seeds were executed. Seven trials recovered and publicly
validated the exact scalar after one `Join(+20)`, then produced accepted fresh
full-message forgeries. The eighth retained a residual cofactor of 2 after the
first Join and at 3,040 sanitizers; its cumulative public-mask GCD became exact
at 3,060 sanitizers, after which the same forgery and controls passed. It
remains classified as a one-Join failure and a separately reported
multi-epoch success.

All eight trials passed honest signature and sanitization checks, full-message
freshness checks, message-mutation and wrong-key controls, and curve/subgroup
validation. The one-worker eight-trial run took 6 minutes 12.77 seconds and
27,136 KiB peak RSS. Its sealed manifest has SHA-256
`e94ba0b60d291b6ce3136e995f1459dc3fb28147de33908f63cb1c61cb4235e2`;
the independent source, results, report, and verdict hashes are recorded in
`metadata.json`.

## Reproduce

The target source is pinned at the
[paper-time author commit](https://github.com/rookie-papers/DSS-MS/tree/b994a3f46cbe5501f47f53aa2e6942cff714b53a).
The public package contains the [primary reproducer](reproduce.py),
[independent eight-row reproducer](reproduce-all-rows.py),
[primary reference output](reference-output.json),
[all-rows reference output](all-rows-reference-output.json),
[metadata](metadata.json), [package checksums](SHA256SUMS), and the attack
paper as [LaTeX source](paper/attack.tex) and [PDF](paper/attack.pdf).

Python 3.9 or later and the standard library are sufficient. The fast
regression uses 96 initial sanitizers but executes the complete key-recovery,
forgery, ordinary-verifier, subgroup, and negative-control path:

```sh
make quick
```

Run the exact 3,000-sanitizer, `Join(+20)` profile with:

```sh
make exact
```

The exact mode is deterministic and takes roughly 35 seconds on the audit
host. It reproduces the sealed primary instance and byte-compares it with
`reference-output.json`. Run all eight independently implemented,
prospectively sealed rows and compare them with
`all-rows-reference-output.json` using:

```sh
make all-rows
```

That run takes about six minutes on the audit host. `make reproduce` runs both
exact public reproducers, and `make check` also compiles the scripts and checks
the canonical JSON contracts. Successful documented entry points finish with
`PASS_QUICK_REPRODUCTION`, `PASS_EXACT_REPRODUCTION`, or
`PASS_ALL_ROWS_REPRODUCTION`; any mismatch exits nonzero. The all-rows JSON
also preserves seven `PASS_ONE_JOIN` rows and the retained trial-6
`PASS_MULTI_EPOCH` row. Build the paper with `make paper`.

## Prior work and history

Repeated-common-factor recovery by an integer GCD is established prior art.
DSS-MS directly cites PA-CRT, and public PA-CRT-lineage cryptanalysis discusses
the same method on public products that reuse a hidden factor. In particular,
Tao et al.'s B-DSPA work and Kabil, Aslan, and Azer's 2024 cryptanalysis record
that lineage and its lifecycle assumptions. They do not analyze DSS-MS,
`S_x=A*sk_s`, or the DSS-MS verifier. This report claims no novelty for the
GCD technique.

A bounded exact-target search through 18 October 2026 located no earlier
public attack against DSS-MS. That search result is dated and cannot exclude
private, removed, or unindexed work. The charter-required final history
recheck passed on 18 October 2026. It confirmed the unchanged official landing
and attack-relevant source and located no exact-target disclosure. The result
remains a bounded search finding rather than proof of absolute priority.

## Repair direction

Avoid publishing multiple integer values with the same secret scalar as a
common factor. A redesign can give each epoch an independently sampled
sanitizer scalar and matching public key, bind the epoch and public key into
signatures, and version verification so old signatures remain unambiguous.
Alternatively, distribute sanitizer capabilities with a conventional
recipient-specific key-establishment mechanism instead of a public CRT
common-factor mask. Any repair must also specify the scalar/modulus range
condition, reconcile `Join` and `Revoke`, and receive new correctness and
security analysis. This is design guidance, not a validated patch.

## Verification status

The sealed primary experiment, consistency review, fresh-context independent
reproduction, final falsification review, final exact-target history recheck,
and independent Publication Review all passed.

## Acknowledgements

The computations were performed on the Norwegian Research and Education Cloud (NREC), using resources provided by the University of Bergen and the University of Oslo.
