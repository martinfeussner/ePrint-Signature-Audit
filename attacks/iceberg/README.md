# Calving Iceberg: A Same-Message Context-Splitting Group-Key Recovery Attack

> **VERIFIED ATTACK.** The pinned-source C execution and an independently
> written standard-library Python reproduction both recovered the Iceberg
> group key and produced an ordinary BIP340 signature on a fresh message.

> **AI disclosure.** This audit used the OpenAI model Daybreak Blue at the ultra reasoning level.
> OpenAI Codex generated and selected this title and deliberately chose
> “Calving Iceberg” as scheme-related wordplay: iceberg calving splits one ice
> mass, while the attack splits one Iceberg session across several outer
> contexts. OpenAI Codex assisted with target reconstruction, cryptanalysis,
> implementation, experiments, review coordination, and technical writing.
> Independent human verification was not performed; it is optional and is not
> a publication requirement.

## At a glance

| Field | Value |
|---|---|
| Scheme | Iceberg nested threshold multisignature |
| Target | [IACR ePrint 2026/1757](https://eprint.iacr.org/2026/1757), initial/current v1 |
| Target authors | Paul Gerhart, Nadav Kohen, Jesse Posner, and Matias Furszyfer |
| Family | Nested threshold MuSig2 over replicated secret sharing |
| Result | Group signing-key recovery followed by an ordinary fresh-message BIP340 forgery |
| Technique | Split one SID and message across three attacker-chosen outer MuSig2 nonce contexts, interpolate a complete group response from each honest member, and solve the resulting three equations |
| Affected profile | `t=2`, `n=4`, `mu=3`, `nu=2`, secp256k1, BIP327/BIP340, 32-byte SID |
| Corruptions | One member |
| Signing queries | Three: one to each honest member, all on the same message and SID |
| Forged-message participation | Zero honest members |
| Primary source-backed run | 0.01 seconds, 2,560 KiB peak RSS, one worker |
| Independent reproduction | PASS; 0.92 seconds, 15,360 KiB peak RSS, one worker |
| Layer | Design-level formal-game weakness, exercised through the pinned author artifact |
| Conditions | The paper's Figure 3 game, where a SID is bound to one message but the complete outer context is not bound across honest members |
| Attack history | No previous public report of the complete Iceberg-specific attack was located in searches through 18 October 2026 |

## Impact

With one corrupt member, the adversary asks each of the three honest members
to answer once under one session identifier and one message. Each answer sees
a different attacker-controlled outer cosigner nonce. The game permits this
schedule because it consumes state per member and compares only the message
across members. Combining every honest response with the corrupt member's
response gives three complete group partial signatures. They reveal the two
fixed group nonce scalars and the group signing scalar through a full-rank
three-by-three linear system.

The recovered group key is reusable. Together with the adversary's outer
cosigner key, it produces a standard 64-byte BIP340 signature on a message
that was never submitted to an honest member. The ordinary verifier accepts
that signature, so the result meets the project's secret-key-recovery and
fresh-signing criterion.

## Attack outline

For outer context `j`, interpolation gives the group partial scalar

```text
S_j = eps_j*r1 + eps_j*b1*b0_j*r2 + e_j*a*gamma*x  (mod q).
```

Here `r1` and `r2` are Iceberg's two deterministic group nonce scalars for the
SID, `x` is the group secret, `b1` is Iceberg's inner nonce coefficient,
`b0_j` and `e_j` are the outer MuSig2 nonce coefficient and BIP340 challenge,
`a` is the BIP327 group-key coefficient, and `eps_j` and `gamma` are the
public nonce and key parity signs. Every coefficient is public.

The adversary corrupts member 1 and obtains one response from each honest
member `2`, `3`, and `4`. At threshold two, it combines its own response with
the selected honest response using the ordinary interpolation weights. Three
distinct outer nonce contexts produce three independent rows for the common
unknown vector `(r1,r2,x)`. Solving recovers `x`, which regenerates the public
group key before it is used for the fresh BIP340 signature.

## Why the queries are legal in the stated game

Figure 3 stores `SID[i][sid]` separately for each member and a global
`M[sid]`. The signing oracle checks that the selected member is ready and
that `M[sid]` is unset or equals the supplied message. It then passes the
adversary-supplied outer context to `SignRound` and marks only that member
done. It does not record or compare the outer key list, aggregate nonce,
group position, or complete second-round context across members.

The retained schedule keeps the SID, message, key list, group position,
attacker cosigner key, and tweak state fixed. Only the attacker cosigner's
nonce changes. Each honest member receives one pre-round query and one signing
query. For the forged message, the set of honest responders is empty, which
satisfies the game's win inequality `0 < t - |C| = 1`.

The proof later relies on the stronger statement that the same SID cannot be
queried with two different second-round inputs. That property is absent from
the game. Binding only the message therefore does not justify the proof's
single-underlying-call simulation.

## Reproduce

The public reproduction uses Python 3's standard library only:

```sh
python3 -B reproduce.py > /tmp/iceberg-result.json
cmp /tmp/iceberg-result.json reference-output.json

python3 -B reproduce-all-rows.py > /tmp/iceberg-all-rows.json
cmp /tmp/iceberg-all-rows.json all-rows-reference-output.json
```

Or run both comparisons with:

```sh
make reproduce
```

The Python implementation includes secp256k1 group arithmetic, BIP327 key
aggregation, BIP340 signing and verification, the Iceberg transcript tags and
replicated sharing, the extraction, and negative controls. The attacker path
receives only public transcript values, the corrupt member's shares, the
three oracle responses, and the attacker cosigner's secrets. Fixture-wide
secrets are used only for post-recovery assertions.

The package also retains the exact C diagnostic that calls the pinned
artifact's native Iceberg, MuSig2, and BIP340 paths. To use an existing local
checkout:

```sh
ICEBERG_SOURCE_DIR=/path/to/benchmark-iceberg make source-exact
```

Without `ICEBERG_SOURCE_DIR`, that target clones the official artifact. It
checks out commit `b2f87cb047467dd78852bc32722a5228a7167f5e`, verifies the
two construction-source hashes, compiles in a temporary directory, and
requires the reported attack and controls to pass. See
[`reproducer/source-exact/README.md`](reproducer/source-exact/README.md).

## Controls

The reproductions verify all three queried-message outer signatures before
testing the forgery. Two equations have rank two, repeating one context leaves
rank two, omitting nonce parity makes the true solution fail, and treating a
raw honest response as a complete group response does not recover the group
key. A changed-message check rejects the fresh signature.

## Scope, prior work, and repair direction

The executed endpoint is the paper's concrete `t=2,n=4` secp256k1 profile at
the pinned artifact commit. This is a construction-level result in the
paper's formal game. It does not depend on malformed encodings, weak keys,
hash collisions, parser behavior, rollback, faults, or a source-only defect.
The artifact is a benchmark prototype with a trusted dealer; no claim is made
about deployment availability, privacy, DKG integration, or Lightning state
management beyond the stated signing interface.

The three-response MuSig2 linear solve, same-message deterministic-nonce
context manipulation, and replicated-sharing quorum-split ideas are prior
public knowledge. The report claims only their concrete application to
Iceberg's game. No prior public report of this complete Iceberg-specific
schedule, group-key recovery, and fresh forgery was located in the bounded
search through 18 October 2026; no absolute priority or technique-novelty
claim is made.

A repair needs group-wide agreement on the complete second-round context,
including the aggregate nonce, key list, group position, message, and tweak
state, before any member returns a share. Storing only the message is
insufficient. This audit has not validated a drop-in repair or a revised
proof.

Paper: [`paper/attack.tex`](paper/attack.tex) and
[`paper/attack.pdf`](paper/attack.pdf).
