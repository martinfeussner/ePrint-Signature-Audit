# CUBE Collapses to a Point: A Zero-Query Identity-Proof Forgery Against CUBE

> **VERIFIED ATTACK.** Primary and fresh-context independent implementations
> reproduce a zero-signing-query fresh-message forgery against CUBE's ordinary
> proof verifier at full BN254 parameters. The candidate also passes read-only
> calls at the author-listed Sepolia addresses. Those deployed checks are
> historical simulations; no transaction was sent, and no source-to-runtime
> bytecode match is claimed.

> **AI disclosure.** This audit used the OpenAI model Daybreak Blue at the ultra reasoning level.
> OpenAI Codex generated and selected this title and deliberately chose “CUBE
> Collapses to a Point” as wordplay connecting the scheme name to the proof's
> collapse to the group identity point. OpenAI Codex assisted with target
> reconstruction, cryptanalysis, implementation, experiments, review
> coordination, and technical writing. A separately tasked hostile AI reviewer
> and a fresh-context AI reproducer both returned `PASS`. Independent human
> verification was not performed; it is optional and is not a publication
> requirement.

## At a glance

| Field | Value |
|---|---|
| Scheme | CUBE: Partially Blind BBS Signatures for Unlinkable Decentralized Identity |
| Target | [IACR ePrint 2026/920](https://eprint.iacr.org/2026/920), initial/current preprint |
| Target author | Guohao Lai |
| Family | Partially blind BBS credential with a Fiat--Shamir proof and on-chain SBT minting |
| Result | Zero-query fresh-message Sys-EUF-CMA forgery |
| Technique | Set all three proof points to the group identity and all three responses to zero |
| Affected profile | Full BN254 five-word source profile and paper-complete address/nullifier profile |
| Primary reproduction | PASS; actual BN254 pairings; 0.03 seconds, 2,048 KiB peak RSS, one worker |
| Independent reproduction | PASS; fresh-context offline rebuild; 0.03 seconds, 2,048 KiB peak RSS, one worker |
| Deployed evidence | 11/11 read-only checks passed at the author-listed Sepolia verifier and issuer addresses |
| Layer | Design-level failure of the paper's ordinary verification equations |
| Attack history | No prior public CUBE attack located through 18 October 2026; generic BBS nonidentity validation is prior art |

## Impact

CUBE's system unforgeability game accepts an adversary when `Verify` accepts a
proof for an explicit attribute vector outside the set authorized through its
signing oracle. The candidate here makes no signing query, chooses a fresh
attribute vector, and is accepted by the ordinary verification equations. It
therefore reaches the paper's Sys-EUF-CMA endpoint as well as this audit's
fresh-message-forgery criterion.

The result does not depend on a weak key, malformed encoding, parser behavior,
hash collision, source-only omission, or a special parameter choice. Adding
the paper's address and nullifier terms does not change it. The application
must still satisfy its public nullifier-state prerequisite; that prerequisite
does not authenticate the credential proof.

## Attack

For public commitment `C_J`, public key `X`, generator `G_2`, challenge `c`,
and hidden-message base `H_gamma`, Section 4.5.5 accepts when

```text
e(A_bar, X) = e(B_bar, G_2)
U + c*B_bar = s*C_J + t*A_bar + u_gamma*H_gamma.
```

Neither the paper predicate nor the pinned verifier rejects identity-valued
proof points. Choose

```text
A_bar = B_bar = U = identity
s = t = u_gamma = 0.
```

Both pairing inputs then produce the target-group identity, and both sides of
the linear equation are the source-group identity. The result is independent
of `c`, `C_J`, `X`, `H_gamma`, the message vector, and the application context.
The forger can therefore select any explicit unauthorized attribute vector and
submit the same constant proof without obtaining a credential or signing
response.

The actual-BN254 reproductions include honest accepting proofs. They also
reject single changes to `A_bar`, `B_bar`, `U`, and `s`, and reject an honest
proof after one message changes. The candidate continues to accept after the
message vector or context changes. These controls exercise both verifier
equations and distinguish the result from an always-accepting harness.

## Source and deployed evidence

The author repository is pinned at commit
`2af179dc02692c188c51125a3a6d98cf8f67faef`, tree
`24e8f8377199792af57b5d65204e25df9ad44e3e`. Its `BBSVerifier.sol` implements
the two equations above, while `BBSMath.sol` represents the BN254 identity as
`(0,0)` and supplies it to the ordinary precompile path.

The canonical deployed replay made twelve read-only JSON-RPC requests using
only `eth_chainId`, `eth_getCode`, `eth_getTransactionByHash`, and `eth_call`.
At the author-listed verifier address, two distinct all-zero proofs returned
true and mutations returned false. At the block immediately before an
author-listed successful mint transaction, the issuer call also completed
when only the nine proof words were changed to zero. A `U` mutation reverted,
and the zero proof reverted one block earlier before the required public
nullifier state existed.

This establishes behavior at the author-listed addresses. Historical
`eth_call` is a simulation: no forged mint transaction was broadcast, no
private key was used, and the audit did not independently rebuild and match
the deployed runtime bytecode to the pinned source.

## Reproduce

The deterministic quick check requires Python 3.9 or later and only the
standard library:

```sh
make reproduce
```

It runs a prime-order pairing-group coordinate model for the five-word source
profile and the paper-complete seven-word profile. It checks the attack,
honest proofs, changed inputs, and the four mutations. This model is a fast
algebraic replay; it does not replace the curve implementation.

The full reproducer uses actual Arkworks BN254 groups and pairings plus
Keccak-256. With Rust dependencies already present in the Cargo cache, run:

```sh
make actual-bn254
```

The build is locked, offline, and limited to one Cargo job. See
[`reproducer/actual-bn254/README.md`](reproducer/actual-bn254/README.md) for
the precise boundary. Paper: [`paper/attack.tex`](paper/attack.tex) and
[`paper/attack.pdf`](paper/attack.pdf).

## Prior work and history

Generic BBS specifications published before CUBE already require proof points
to be valid nonidentity group elements. The algebraic role of the identity and
the corresponding validation rule are therefore prior art. This report claims
no novelty for the technique or validation principle.

No prior public attack against the exact CUBE construction was located in the
searches completed through 18 October 2026. The same CUBE work also appears in
the 2026 IEEE Conference on Computer Science and Blockchain under DOI
`10.1109/CCSB71176.2026.11716519`; that is a publication instance of the
target, not cryptanalysis. The history claim is dated and bounded and does not
exclude private, deleted, embargoed, or unindexed work.

## Repair direction

Reject the group identity for every proof point before challenge derivation
and verification, following established BBS validation practice. The verifier
should apply the same checks at every API and contract boundary and retain
subgroup and canonical-encoding checks. This is a repair direction rather than
a validated patched protocol; compatibility and security should be reviewed
after a concrete patch exists.

## Review evidence

The primary actual-BN254 reproduction, canonical read-only deployed replay,
hostile adversarial review, distinct fresh-context reproduction, and final
exact-target history recheck all passed before classification. The independent
reproduction rebuilt the frozen package offline and reproduced every required
field. Its result SHA-256 is
`e4d142dc85a9a05ec80bc28b6b47e93f438e99577ac25930084f1e71051cfe7e`,
and the final history report SHA-256 is
`1ba8f4a4f3f8dfc4b3e98b90eb50cd8c43e78b9e31ec9464a754f5fd8ce53a74`.

The computations were performed on the Norwegian Research and Education Cloud (NREC), using resources provided by the University of Bergen and the University of Oslo.
