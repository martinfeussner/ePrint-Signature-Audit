# BLS You: A Zero-Query Rogue-Key Forgery Against the 2P-AISO-AS Chosen-Key Interface

> **VERIFIED ATTACK.** The primary full-parameter source-backed execution and
> a separately written fresh-context reproduction establish a zero-query
> fresh-message forgery against the direct-addition BLS instantiation of the
> chosen-key `DS2` interface in Definition 33. The claim is limited to that
> interface and excludes Theorem 1, Figure 6, central honest `KeyGen`, proper
> DKG, the artifact's normal lifecycle, and deployments.

> **AI disclosure.** This audit used the OpenAI model Daybreak Blue at the ultra reasoning level.
> OpenAI Codex generated and selected this title and deliberately chose “BLS
> You” as BLS/“bless you” wordplay tied to the scheme name. OpenAI Codex
> assisted with target reconstruction, cryptanalysis, implementation,
> experiments, review coordination, and technical writing. A separately
> tasked AI adversarial reviewer attempted to disprove the result and returned
> `PASS_NARROW_SCOPE`, requiring the exact Definition 33 boundary used here.
> Independent human verification was not performed; it is optional and is not
> a publication requirement.

## At a glance

| Field | Value |
|---|---|
| Scheme | Direct-addition BLS instantiation of the Definition 33 chosen-key `DS2` interface |
| Target | [IACR ePrint 2026/1394](https://eprint.iacr.org/2026/1394), retained initial/current 83-page preprint |
| Target authors | Javier Gomez-Martinez, Erkan Tairi, Pedro Moreno-Sanchez, and Clara Schneidewind |
| Family | BLS-based two-party signature with direct public-key aggregation |
| Exact target | The chosen-key `DS2` experiment in Definition 33 |
| Result | Public-key-only, zero-signing-query fresh-message forgery |
| Technique | Standard BLS rogue-public-key cancellation; no technique novelty claimed |
| Affected profile | Paper-linked BLS12-381 G1-public-key/G2-signature artifact using SHA-256 XMD |
| Primary source-backed run | PASS; 0.03 seconds, 3,072 KiB peak RSS, one worker |
| Independent reproduction | Sealed PASS, 32/32 fresh honest keys; 1.16381577 seconds of cryptographic checks; 102.98 seconds clean compile-and-run; 400,048 KiB peak RSS; one worker |
| Adversarial review | `PASS_NARROW_SCOPE`; qualifying target is the direct-addition BLS instantiation of Definition 33 only |
| Layer | Design-level break of the explicit Definition 33 interface, exercised through the unchanged ordinary artifact verifier |
| Excluded | Theorem 1, Figure 6, central honest `KeyGen`, proper DKG, normal artifact lifecycle, and every deployment |
| Attack history | `PASS_FINAL_HISTORY`; no earlier public report applying the attack to the exact Definition 33 interface located through 18 October 2026 |

## Impact

Definition 33 reveals one honest BLS public key and then accepts an arbitrary
second public key chosen by the adversary. It does not require a proof of
possession or proof of secret-key knowledge. The adversary can therefore make
the aggregate public key equal a point with a known discrete logarithm and
sign any fresh message under that aggregate key. No honest signing response is
needed.

This directly violates the existential-unforgeability requirement stated for
the Definition 33 `DS2` interface. It does not refute the conditional
Theorem 1 or establish an attack on the separate Figure 6 lifecycle or the
artifact programs, where both participant keys are generated honestly before
aggregation.

## Attack

Let `P` generate the BLS public-key group, let `H(m)` be the hash-to-signature-
group function, and let the honest public key be `X_A=x_A*P`. The artifact
aggregates two keys by addition and accepts a signature `S` under key `X` when

```text
e(P,S) = e(X,H(m)).
```

After Definition 33 reveals `X_A`, the corrupt participant selects a known
nonzero scalar `beta`, checks that `beta*P != X_A`, and registers

```text
X_E = beta*P - X_A.
```

Both inputs are subgroup points, so `X_E` is in the subgroup; the explicit
inequality makes it nonidentity. The aggregate is

```text
X_A + X_E = beta*P,
```

which is nonidentity because `beta` is nonzero. For a never-queried message
`m*`, output

```text
S* = beta*H(m*).
```

Then `e(P,S*)=e(beta*P,H(m*))`, so the ordinary verifier accepts. The forger
knows `beta` and never needs the discrete logarithm `beta-x_A` of the rogue
key. The attack costs constant group work and makes zero signing queries.

## Scope boundary

The result is limited to the explicit Definition 33 chosen-key experiment.
That experiment gives the honest key to the adversary before accepting the
adversarial key and imposes no key-knowledge condition.

Theorem 1 is conditional on the stated security of its underlying primitives;
showing that this concrete direct-addition BLS instantiation fails the
Definition 33 assumption does not refute that conditional theorem. The
paper's Figure 6 instead obtains both participant keypairs from central
honest `KeyGen`; footnote 7 describes DKG as a possible realization. The
artifact's normal programs likewise call `BLSKeyPair::new()` independently
for both parties. Those lifecycles do not expose Definition 33's chosen-key
registration step and are expressly excluded. No claim is made about a proper
DKG, any deployed protocol, Chia, Ethereum, Sui, ZetaChain, or any other
system.

## Source-backed evidence

The paper-linked Anonymous GitHub ZIP is pinned by SHA-256:

```text
f1e70afef59a55e3a852d1a9debfefb7f9250f90679a65faa46ecdf0c0a7b441
```

The mirror discloses no Git repository, commit, or tree, so none is claimed.
The source-exact script verifies the ZIP plus hashes for the BLS implementation,
hash-to-curve code, workspace manifest, crate manifest, and both artifact test
programs before compiling the harness.

The primary harness imports the unchanged `bls-aiso-as` crate. It obtains
`X_A` from `BLSKeyPair::new`, uses the direct G1 addition appearing in the
artifact programs, calls the artifact's SHA-256 XMD `hash_to_g2`, and sends
the forged G2 point to the public `bls::verify`. It calls no signing method.
The ordinary verifier accepted. A sequential repeat had byte-identical output.

Controls rejected a changed message, changed signature, and substituted
honest key. The attack keys were nonidentity and torsion-free, and malformed
G1 and G2 encodings were rejected at the concrete checked decoder boundary.

## Reproduce

The deterministic quick check needs Python 3.9 or later and only the standard
library:

```sh
make reproduce
```

It executes a prime-order bilinear-group reference model and compares the
canonical result with `reference-output.json`. It demonstrates the cancellation,
freshness accounting, verifier equation, and negative controls. It does not
stand in for BLS12-381 hash-to-curve or serialization.

The source-exact run needs Bash, `curl`, `unzip`, `sha256sum`, and Rust/Cargo
1.85 or later:

```sh
make source-exact
```

To reuse a local byte-identical official ZIP and cached Cargo crates:

```sh
BLS_AISO_AS_ARTIFACT_ZIP=/path/to/author-artifact.zip \
  CARGO_NET_OFFLINE=true make source-exact
```

See [`reproducer/source-exact/README.md`](reproducer/source-exact/README.md)
for the exact source pins and lifecycle limitation.

Paper: [`paper/attack.tex`](paper/attack.tex) and
[`paper/attack.pdf`](paper/attack.pdf).

## Prior work and attack history

Rogue-key cancellation for BLS aggregation is established prior art. Boneh,
Gentry, Lynn, and Shacham (2003) discuss the chosen-public-key problem;
Bellare and Neven (2006) address multisignatures in the plain public-key
model; Boneh, Drijvers, and Neven (2018) give the same cancellation equation;
and CFRG BLS guidance describes distinct-message, augmentation,
proof-of-possession, validation, and coefficient-based defenses.

Against the Definition 33 chosen-key `DS2` interface of ePrint 2026/1394, we
apply the standard BLS rogue-public-key cancellation attack and obtain a
zero-query fresh-message forgery at full BLS12-381 parameters. We located no
earlier public report applying this attack to that exact interface in searches
completed through 18 October 2026. The attack technique is prior art; no
technique novelty is claimed. The search statement is dated and bounded; it
does not exclude private, deleted, embargoed, or unindexed work.

## Repair directions

Subgroup and nonidentity checks alone do not help because the rogue key already
passes them. Standard directions include verified proof of possession or
secret-key knowledge, public-key-augmented messages, list-bound key-dependent
coefficients, or authenticated honest generation/DKG. Each changes the
paper's interface or equations and needs a new compatibility and security
analysis. This audit has not validated a repair.

## Review evidence

The source-backed reproduction, independent reproduction, post-evidence
adversarial review, and final history delta all passed before classification.

The sealed independent-reproduction evidence is anchored by
`REVIEW_ARTIFACTS.sha256` SHA-256
`b9c45ff8afea908c2732690215ad80f5acb0e67b4c49567cb304c449ff798a8c`
and state handoff SHA-256
`b089529d0146daeb37bd50f370411c311012283a25d1ca090aaaf128eb67d22e`.
The sealed post-evidence adversarial review returned `PASS_NARROW_SCOPE`; its
manifest SHA-256 is
`f4558bb0b73c6e0a6ae7c1b8b400ebdc2f3cabde0ec71f93cbc7c01ba54eb065`
and its handoff SHA-256 is
`b7218c2be45c0683a1243a639e7be3d510db30018efa230ccaefb6d226b6a2db`.
The final history recheck returned `PASS_FINAL_HISTORY`; its manifest SHA-256
is `796daa3485222c38b14b3e6c6b2e6c7a4514df09efb60c8bbb31b67ada0e25f3`,
its 74-source manifest SHA-256 is
`a12410ab6c67aee1d3a2fbd9caf2acc2667007ccfaa4d1512f23ebfd061f9e95`,
and its handoff SHA-256 is
`847ad6ca5617a2491728e178b957cdc2a096cf6beb9ba0a9c6c7919f072481e3`.

The computations were performed on the Norwegian Research and Education Cloud (NREC), using resources provided by the University of Bergen and the University of Oslo.
