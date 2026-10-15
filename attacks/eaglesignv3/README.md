# The Eagle Has Wrapped: Practical Public-r Key Recovery against EagleSignV3

> **VERIFIED ATTACK.** The full-parameter primary result, hostile adversarial
> review, prospectively sealed fresh-context independent reproduction, final
> exact-target history review, supplemental public-package replay, and
> independent Publication Review passed. The Publication Reviewer returned
> `PASS / NO VETO`.

## At a glance

| Field | Value |
|---|---|
| Scheme | EagleSignV3 |
| Target | IACR ePrint 2024/1234, current 6 August 2024 revision |
| Target paper | [IACR ePrint 2024/1234](https://eprint.iacr.org/2024/1234) |
| Attack paper | [`paper/attack.pdf`](paper/attack.pdf) ([TeX source](paper/attack.tex)) |
| Scheme authors | Abiodoun Clement Hounkpevi, Sidoine Djimnaibeye, Michel Seck, Djiby Sow |
| Attack-paper byline | Martin Feussner; Selmer Center, University of Bergen; martin.feussner@uib.no |
| Family | Fiat--Shamir-with-aborts lattice signature over a negacyclic ring or module |
| Result | Secret `D` and equivalent signing key `G` recovery followed by an accepted fresh-message forgery |
| Exact target | Paper-level Ring-L2: `(k,l,n,q,tau,eta,beta,gamma1,gamma2)=(1,1,1024,59393,16,1,16,16384,16384)` |
| Trigger | `q=59393 < 4*gamma2=65536`, so centered reduction can wrap without the intended high-bits stability |
| Primary outputs | 40,000 values returned by the printed signer; no minimum-count claim |
| Primary constraints | 21,933 exact sparse inequalities, including 1,811 wraps |
| Primary endpoint | Public relation passed; fresh-message signature accepted; changed-message and altered-signature controls rejected |
| Primary solver resources | One SciPy/HiGHS worker; 68.08 s command wall time; 213,404 KiB peak RSS |
| Primary completion | Appendix A.4's 32-byte `r` |
| Independent outputs | 40,000 values returned by the printed signer; no minimum-count claim |
| Independent constraints | 21,982 exact sparse inequalities, including 1,767 wraps |
| Independent endpoint | Exact `D` and `G`; public relation passed; accepted fresh-message forgery; both negative controls rejected |
| Independent resources | 296.09 s complete public pipeline; one worker; 221,272 KiB peak RSS |
| Independent completion | Section 3.3 main text's 64-byte `r`; Appendix A.4's 48-byte `lambda` |
| Conditions | Public `T` is a ring unit; use every output returned by the printed Algorithm 4 |
| Layer | Design, under an explicit paper-level completion |
| Technique | Public wrap-label decoding and ternary integer feasibility; no technique originality claimed |
| AI provenance | This audit used the OpenAI model Daybreak Blue at the ultra reasoning level. OpenAI Codex generated and selected the title and deliberately chose “The Eagle Has Wrapped” as wordplay on “The Eagle Has Landed” and the modulus-wrap attack. |
| Independent reproduction | `PASS / PRACTICAL FULL-PARAMETER ONE-KEY KEY RECOVERY AND FRESH FORGERY` |
| Counted trials | 2: primary plus prospectively sealed independent reproduction |
| Counted successes | 2 |
| Final history review | `PASS / NO_PRIOR_PUBLIC_SUBSTANTIVE_EXACT_V3_ATTACK_LOCATED / NO_HISTORY_VETO` |
| Adversarial review | `PASS_WITH_LIMITATIONS / NO_VETO_TO_INDEPENDENT_REPRODUCTION` |
| Supplemental package replay | `PASS / PUBLIC PACKAGE FULL REPLAY`; release-readiness validation outside the two counted trials |
| Publication Review | `PASS / NO VETO` |
| Publication status | `VERIFIED_ATTACK` |

## Impact

For a returned signature `(r,z)`, anyone can recompute the challenge `c` and
the verifier value

```text
v = T*z - A*c = p + D*c mod q.
```

The signer computed `r` from the high bits of `p` before adding `D*c`. At the
Ring-L2 row, coefficients of `v` within 15 units of either centered modulus
boundary can correspond to two possible high bits of `p`. There are few such
coordinates in any output. Enumerating their possible flips and hashing each
candidate against public `r` identifies the correct pattern.

For a lower-edge coordinate `v_j=-29696+a`, a flip says
`(D*c)_j > a`; no flip says `(D*c)_j <= a`. At the upper edge
`v_j=29696-a`, a flip says `(D*c)_j < -a`; no flip says
`(D*c)_j >= -a`. Each challenge has weight 16, so every statement is one exact
16-term integer inequality in the 1,024 ternary coefficients of `D`.

The primary run accumulated 21,933 such inequalities from 40,000 printed
signer outputs. A ternary solver recovered `D`. Because that public key's `T`
was a unit, the implementation derived

```text
G = T^-1 * (A + D)
```

and required ternary `G` plus the exact public relation `T*G=A+D` before any
hidden-key comparison. The recovered pair then signed a never-queried message,
and the ordinary paper-level verifier accepted it.

A prospectively sealed fresh-key implementation independently repeated the
endpoint from 40,000 returned outputs. It obtained 21,982 inequalities,
recovered exact `D` and `G`, and passed the same public relation, freshness,
ordinary-verifier, changed-message, and altered-signature gates before a
post-hoc ground-truth comparison.

## Exact scope

The target is the current 35-page ePrint PDF, SHA-256
`9b346bf2234299eadc72460a47c20dd71e6131fa19b3d21abdaaea01a8f061a2`.
No exact public V3 source or known-answer vector was located. The EagleSignV2
repository is predecessor material and is not an implementation-conformance
oracle for V3. The result therefore concerns a documented mathematical
completion of the printed Ring-L2 equations. The primary execution followed
Appendix A.4's 256-bit hash output and therefore used a 32-byte `r`. The
independent execution followed Section 3.3's 512-bit definition and therefore
used a 64-byte `r`. It also used Appendix A.4's 48-byte `lambda`. Success under
both `r` lengths shows that the wrap attack does not depend on resolving that
paper conflict in one particular way; neither execution establishes a
canonical wire format.

The direct `G` derivation requires public `T` to be a unit. Under the
paper-level Ring-L2 distribution, the estimated probability is
`(1-1/q)^n`, about 98.29%. This property is publicly testable. The package does
not claim a route for the remaining nonunit keys.

## Printed signer outputs

The experiment keeps every output returned after Algorithm 4's stated `z` and
low-bits rejection tests. Of the 40,000 primary outputs, 1,767 (4.4175%) fail
the ordinary verifier because the violated modulus condition breaks the
paper's intended high-bits invariant. They still contain public `(r,z)` and
produce valid wrap labels for recovery.

An implementation that adds a final self-verification-and-resampling loop has
different output semantics and is outside this claim. The package does not
assert that the same 40,000-output recovery works unchanged after that added
filter.

## Primary result

The controlled paper-level replay reported:

- 598.77 seconds to produce 40,000 returned outputs;
- 21,933 inequalities and 1,811 wrap labels;
- 69,252 public high-bit candidates tested in total;
- a `21,933 x 1,024` ternary model with 350,928 nonzeros;
- one SciPy/HiGHS branch-and-bound node, 65.67 solver seconds, 68.08 command wall
  seconds, and 213,404 KiB peak RSS with one worker;
- exact satisfaction of all constraints and the public key relation;
- acceptance of a signature on
  `eaglesignv3-highs-continuation-fresh-message-never-queried`;
- rejection after changing the message; and
- rejection after flipping one bit of `r` while retaining `z`.

The constraint dataset SHA-256 is
`a15776674731b97cca2c469ab4d43512c966d6d4636e5e59344ffd8d38ffb97c`.
The fresh forgery and recovered key have SHA-256 values
`1e90009b4eb0d9e9cb0103c6015ee7b3a76bb47a6a4334b0ac703fa79eeb5822`
and
`e0e0fa88ff3bef951687344d17731018495cb958bf68e50d65f7cff3d0bf4eb1`.

This is one fixed-key result. Forty thousand is a demonstrated working count,
not an estimate of the minimum, and one key does not establish an all-key
success probability.

## Fresh-context independent reproduction

The independent implementation and execution were prospectively sealed before
a fresh kernel-CSPRNG seed was generated. The seal covered the hypothesis,
completion profile, commands, C++20 source, SciPy/HiGHS wrapper, and six
executables. Key attempt zero had unit public `T` and was the only generated
key.

The oracle retained all 40,000 values returned after Algorithm 4's two printed
rejection tests: 38,273 passed and 1,727 failed the ordinary verifier. No
verifier filter was applied. Public recovery extracted 21,982 inequalities
and 1,767 wrap labels after testing 69,301 high-bit candidates. SciPy 1.18.1
`optimize.milp` with HiGHS 1.12.0 solved the 1,024-variable,
351,712-nonzero model in 141.57 solver seconds at one node with zero checked
row violation.

Before ground-truth access, the run checked ternary `D`, ternary unit `G`, all
inequalities, and `T*G=A+D`, then produced an accepted signature on
`EagleSignV3 independent fresh forgery 2026-10-15 / ESV3-IR-001`. The
unchanged verifier rejected a changed message and an altered signature.
Post-hoc comparison then confirmed exact `D` and `G`.

The complete public pipeline took 296.09 seconds with one worker and
221,272 KiB peak RSS. Principal sealed evidence:

- terminal handoff:
  `bf51fc87cc1c7f2060c1e30caea121d4f57183e2496424a3646f00672e0473b0`;
- prospective seal:
  `2e8144384c31f59a3dd4d2d196f2d51da885c8bd8fde25e0d7713440e2b67934`;
- run artifact manifest:
  `19da75184dde5c2697d8f796bdd3e33a0b09c7700318151ff4c0a9e42613de8a`;
- solver report:
  `4e66d7a7c57bdc073088e5c63320c31fb00b0b4b448a5b2514dc639ac89dedc9`;
- recovered key:
  `4dc18591edf542ccd5ea1f5ef13cb01f00973694b9a1e62510bac4a193acc737`;
- fresh forgery:
  `aad6f1610b96b5d5b5d10e961d334b1a240fc7f7d4e5066ae7a42fc7316345c5`.

This second one-key result does not measure an all-key success rate. Together,
the two successful runs cover two keys and two disclosed `r`-length
completions.

## Hostile adversarial review

A separately tasked reviewer worked with an explicit disproof objective and
returned `PASS_WITH_LIMITATIONS / NO_VETO`. It checked the exact Ring-L2
arithmetic, wrap labels and strict inequalities, public candidate gate,
negacyclic convolution rows, ternary bounds, public `G` derivation, freshness,
ordinary verification, and both primary controls. It found no secret-key input
or hidden ground-truth label in public candidate selection.

The review retained every material scope qualification in this package. It
also records that the separately invoked verifier shares the audited public
model code. The review authorizes the sealed independent reproduction; it does
not count or publish the attack.

Evidence hashes:

- adversarial handoff:
  `e8c51f43aff9c1a57bd44a619bb718715ee2d340c9e29c01b46228a524f881cb`;
- complete review:
  `af6fec885f924f5df83e202fec9b05106c897fe53d5edb7a7a1f1e2218e218dc`;
- machine-readable verdict:
  `e08c94ef6da1dcbc3a66f46cd231054a345b056ab30b524e6f09fa36638bb420`;
- review artifact manifest:
  `4e1bcf3d6607514189b4b1362805e8b361c5433cc774b54af405547d049daad7`.

## Reproducer

The [`reproducer/`](reproducer/) directory contains a self-contained C++20
paper-level implementation. It uses
separate processes for key generation, oracle output, public recovery,
ordinary verification, and post-hoc ground-truth comparison.

Run only the arithmetic and decomposition smoke checks:

```sh
cd reproducer
./reproduce.sh --smoke
```

Run the complete 40,000-output attack on one fresh unit-`T` key:

```sh
cd reproducer
./reproduce.sh --full
```

Full mode needs a C++20 compiler, OpenSSL 3 development files, Python 3 with
NumPy 2.5.3 and SciPy 1.18.1/HiGHS 1.12.0, `taskset`, GNU `time`, and
`sha256sum`. The sealed solver path uses integral bounds `[-1,1]`, one thread,
one-CPU affinity, a 4 GiB virtual-memory ceiling, and a 21,600-second limit.
The raw public transcript and secret material remain temporary; final reports
and resource records are retained below `output/full/`.

The public code follows the independently reproduced 64-byte-`r` completion
and sealed SciPy/HiGHS method. Its full fresh-key path passed the supplemental
public-package replay and independent Publication Review.

## Attack history and attribution

The final post-reproduction history review returned
`PASS / NO_PRIOR_PUBLIC_SUBSTANTIVE_EXACT_V3_ATTACK_LOCATED /
NO_HISTORY_VETO`, with moderate confidence. Its approved bounded statement is:

> No prior public substantive attack against EagleSignV3 (IACR ePrint 2024/1234) was located in the searches performed as of 15 October 2026.

This statement cannot exclude private, removed, unpublished, or unindexed
work, and search and citation indexes can lag.

The direct-lineage V1/V2 cryptanalysis is documented in
[IACR ePrint 2024/1137](https://eprint.iacr.org/2024/1137).

Pulles and Tibouchi previously broke EagleSign V1 and V2 using response statistics and ideal structure. Those schemes use different response relations, and EagleSign V2 includes an explicit centered-modulus-boundary rejection that is absent from the EagleSignV3 specification studied here. We located no earlier public disclosure applying the centered-modulus-wrap, public-commitment-label route to EagleSignV3. This is a bounded search statement; we make no absolute firstness or attack-technique novelty claim.

Prabowo and Tan's [Concrete Analysis of Schnorr-type Signatures with Aborts](https://eprint.iacr.org/2024/1256)
gives generic with-aborts analysis and a statistical attack on the original
EagleSign. It provides response-statistics context but does not attack exact
V3 or analyze this centered-wrap public-`r` route.

Pellet-Mary and Seck's [On the Properties of HighBits and LowBits Functions and their Applications](https://eprint.iacr.org/2026/895)
provides generic HighBits/LowBits technique context. The reviewed public
surfaces disclosed no EagleSign attack, so it is treated as adjacent context
rather than an exact-target attack.

The final-history evidence is pinned by SHA-256:

- canonical handoff:
  `2a1cbf638453500b5749cbc040ece0d03abb453e0bb95f7ccd7f4d4f2df82faa`;
- review handoff:
  `53b5c8f3ca4726764b9e0db6df5f6c458f25d988b693968044245a01bfe31d62`;
- machine-readable verdict:
  `b28391fda40777c64919a61035a33f8135eccb60a2f635cc7e78d793e2093236`;
- query ledger:
  `43b6eb77e399f8119fc88b162db57ff80d2d8dbf4a5ab127bfcfe4af700256c2`;
- source ledger:
  `f71cd94c1e1e6a9a3af690e39c63074e61aaf98aea7e1bd16705951b5c2f2f48`;
- review artifact manifest:
  `d50ad9e9bebf5a1855c89f960592e131f19fce2b87d8bb5e4514f567d217454d`.

## Publication Review and supplemental package replay

Independent Publication Review returned `PASS / NO VETO`. The complete public
reproducer was also replayed on a new fresh unit-`T` key as supplemental
release-readiness validation. It retained every one of 40,000 printed signer
outputs: 38,219 passed ordinary verification and 1,781 failed it, with no
verifier filtering. It extracted 22,083 inequalities including 1,821 wraps,
recovered exact `D` and `G`, checked `T*G=A+D`, and produced an accepted
fresh-message forgery. The unchanged verifier rejected both the changed
message and altered signature. The one-worker solve took exactly
83.31292366300477 solver-wrapper seconds and 84.10 command-wall seconds, with
243,116 KiB peak RSS.

This replay validates the complete release path. It does not replace the
prospectively sealed independent reproduction or enlarge the primary plus
independent two-key scope. The reported trial count remains two, with two
successes. Supplemental evidence is pinned by SHA-256:

- replay review:
  `ee6fefb703b8be1c50f5d2804c57f5a62bc1f7f377f1bf8ca0f7aef3769b7761`;
- machine-readable replay report:
  `b1549fd2456b8f68d8393ddca1cf23e1ecd2cb43fc12cddb4337832796583e9a`;
- retained output manifest:
  `b969b537a02e87439a2d07d25a44592e23fb5a187526bbcec9ff6ba8f4427fad`;
- replay artifact manifest:
  `8437db885f97a5021353cff69bef8b1cf7604ddbc200feb458196938da369837`.

The replay input was the pre-finalization source candidate, pinned by root
manifest
`9c8fecf3ba1ea16df8ebd60c52d117a014b0939ac1bb9c85a9fea511a25c93d5`
and nested reproducer manifest
`d5b48642fe37e2a043af4b6e9a79219452e9a73d4583c31d4c8a297579e249ac`.
These are old source-candidate pins, not hashes of this final package.

## Limitations

- Paper-level exact Ring-L2 only; no source or wire-format conformance claim.
- Conflicting hash, seed, and packing details required disclosed completion
  choices.
- Direct fresh signing is conditional on public unit `T`, estimated at about
  98.29% of keys.
- The evidence consists of one fixed-key primary execution and one sealed
  fresh-key independent execution; it is not a many-key study.
- The 40,000-output count is sufficient in both runs and is not minimal.
- Every printed signer output is used, including about 4.4% that ordinary
  verification rejects.
- A signer with an added self-verification loop is outside the current claim.
- The final-history PASS has moderate confidence and is a dated bounded search
  result; it cannot establish absolute priority.
- The later public-package replay is supplemental release validation and is
  not counted as a third research trial.

## AI provenance

This audit used the OpenAI model Daybreak Blue at the ultra reasoning level.
OpenAI Codex performed AI-assisted attack-history research, paper review,
cryptanalysis, implementation, experimentation, and technical writing. OpenAI
Codex generated and selected the title and deliberately chose “The Eagle Has
Wrapped” as wordplay on “The Eagle Has Landed” and the centered-modulus wrap
attack. No independent human verification was performed; it is optional for
this audit. Independent AI Publication Review returned `PASS / NO VETO`.

## Acknowledgements

The computations were performed on the Norwegian Research and Education Cloud (NREC), using resources provided by the University of Bergen and the University of Oslo.

