# A Split-Second Forgery: A Zero-Query Attack on Random-Split St-Gen

> **AI disclosure and review status.** OpenAI Codex generated and selected this
> title and intentionally chose “A Split-Second Forgery” as wordplay on the
> scheme’s random splitting and the millisecond attack. OpenAI Codex performed
> the scheme reconstruction, proof development, implementation, experiments,
> and technical writing, with specialist AI agents used for primary,
> independent, history, scope, adversarial, and publication review. The
> primary reproduction, independent reproduction, exact-history,
> intended-scope, amended adversarial, and independent publication-review
> gates all passed. The result is classified as `VERIFIED_ATTACK`. No
> independent human verification was performed or required.

This report records a public-key-only, zero-query existential forgery against
the literal raw-message interface in Algorithms 5 and 6 of Danilo Gligoroski
and Simona Samardjiska’s *A Digital Signature Scheme Based on Random Split of
St-Gen Codes*, IACR ePrint 2016/391.

The paper asks the signer to sign a raw tuple
$z=(z_1,z_2)$ in $(\mathbb F_2^n)^2$. Its verifier receives this same tuple and
$\sigma$ and computes

$$
e_i'=\sigma G_{i,\mathrm{pub}}+z_i.
$$

The verifier accepts when every block pair of $(e_1',e_2')$ belongs to the
public `ValidErrorSplits` relation. A zero-query attacker therefore chooses any
$\sigma$, chooses public blockwise-valid vectors $e_1,e_2$, and defines

$$
z_i=\sigma G_{i,\mathrm{pub}}+e_i.
$$

Over $\mathbb F_2$, the verifier recovers

$$
e_i'=\sigma G_{i,\mathrm{pub}}+
     \sigma G_{i,\mathrm{pub}}+e_i=e_i
$$

and accepts. The forged object is a fresh attacker-chosen raw $z$ tuple. The
attacker uses no secret value and makes no signing query.

The complete report is in [`paper/attack.pdf`](paper/attack.pdf).

| Field | Result |
|---|---|
| Status | `VERIFIED_ATTACK`; all required publication gates complete |
| Scheme | Random-split St-Gen signature |
| Target | IACR ePrint 2016/391, exact pinned PDF |
| Target PDF SHA-256 | `b2bdf97bcef5dfec9928749d0d3fad0a97956494fc81989c52cd4472dec5755e` |
| Target text SHA-256 | `69fafe4ab6f7bb2fad7dfd6687f66dd19c5d86e738163ac5bdf75cb7fbd06d6f` |
| Signed object | Literal raw $z=(z_1,z_2)$ tuple in Algorithms 5–6 |
| Attack | Public verification-first existential forgery |
| Signing queries | 0 |
| Secret inputs | 0 |
| Printed rows | PS1 $(n,k,\ell,s)=(2142,465,3,2)$; PS2 $(2244,508,4,2)$ |
| Primary full run | 3.21 s, including two complete key generations and controls |
| Maximum primary attack-only time | 1.867 ms |
| Primary peak memory | 20,992 KiB |
| Independent sealed run | Both rows pass; each stage at most 0.66 s |
| Independent peak memory | 20,480 KiB |
| Layer | Paper design, intended raw-vector Algorithms 5–6 interface |

## Exact target and scope

The target is the content-hash-pinned ePrint PDF identified above. The
reconstruction and package are derived from that exact public target and the
sealed primary and independent evidence.

Algorithm 5 calls $z$ the value “to be signed.” Algorithm 6 takes $(z,\sigma)$
and the public matrices, recovers the error vectors, and applies only the
public block-membership test. The paper does not specify a document-to-$z$
encoding, a preimage-resistant hash-to-$z$ transform, or a byte-level message
format.

That omission was checked against both sides of the scheme’s lineage. The
unsplit predecessor,
[*McEliece in the world of Escher*](https://eprint.iacr.org/2014/360),
explicitly says that it decodes `Syndrome = Hash(Doc)` and contrasts this with
the CFS counter loop `Hash(Doc, Counter)`. The predecessor therefore shows how
the authors state document hashing when they intend it, but it does not make
that transform a mandatory unstated component of the later target.

The decisive target-specific evidence is Samy Saad Samy Shehata’s 2017 NTNU
master’s thesis,
[*Post Quantum Cryptography with random split of St-Gen codes*](https://hdl.handle.net/11250/2450584).
The thesis was supervised by target coauthor Danilo Gligoroski and says that it
implements the random-split encryption and signature schemes using the exact
concrete parameter sets published for them. Its Algorithms 19 and 20 call the values
$z_1,\ldots,z_s$ the messages, pass those raw binary vectors directly to
signing and verification, and compute the same
$e_i=\sigma G_{i,\mathrm{pub}}+z_i$ relation. The accompanying C interface
accepts the raw vector as a byte array, and the experimental correctness
criterion is signing a binary vector and successfully verifying its signature.
No document-to-$z$ transform is inserted at this boundary.

The independent scope arbitration therefore classifies the raw binary-vector
interface as the intended mathematical signature construction. An external
hash wrapper is not imported from the predecessor as a mandatory hidden step.
Every attack claim remains confined to this raw $z$ interface. This package
makes no claim about:

- arbitrary documents;
- an unspecified external document-to-$z$ hash wrapper;
- finding a preimage of a chosen $z$ under such a wrapper;
- the predecessor construction in ePrint 2014/360; or
- any software implementation of the scheme.

## Why the attack works

For either printed row, Algorithm 3 makes `ValidErrorSplits` public. The
reproducers derive that relation from its universal-permutation definition:

- PS1, with $\ell=3$, has 24 valid split pairs;
- PS2, with $\ell=4$, has 40 valid split pairs.

The attacker fills every $\ell$-bit block of $(e_1,e_2)$ with one of those
public pairs. It may set $\sigma=0$, in which case $z_i=e_i$ and the attack is
independent of the public matrices. It may instead choose a nonzero $\sigma$
and compute both public matrix products. The nonzero variant confirms the
complete advertised verification path.

The verifier’s cancellation is exact, so the success probability is one for
every public key and every chosen $\sigma$. The experiments test full
parameter handling and the public/private boundary; they do not estimate a
probabilistic success rate.

## Classical technique and attack history

Choosing a candidate signature first and using a public verification equation
to obtain some matching message is a classical route to existential forgery.
The standard hierarchy calls producing at least one new accepted
message/signature pair an existential forgery; see Menezes, van Oorschot, and
Vanstone, *Handbook of Applied Cryptography*, §11.2.4, and the formal
chosen-message security treatment of Goldwasser, Micali, and Rivest.

This report makes no novelty claim for verification-first existential forgery,
linear cancellation, or the general attack technique. Its contribution is the
concrete application to the intended raw-$z$ verifier printed in ePrint
2016/391.

No prior public attack against the random-split St-Gen signature scheme was
located in the searches performed as of **2026-10-09**. This is a dated search
result, not an absolute priority claim. Moody and Perlner’s earlier practical
cryptanalysis applies to the unsplit predecessor and must be credited, but it
does not attack the later random-split public matrices and
`ValidErrorSplits` verifier or disclose this verification-first construction.

## Primary reproduction

Run from this directory:

```bash
python3 reproduce.py
```

The deterministic standard-library implementation:

1. constructs the Equation (1) staircase generator at both printed rows;
2. samples the first split matrix and derives the second from $G_2=G+G_1$;
3. applies an invertible scrambler, one shared outer block permutation, and
   independent inner permutations;
4. derives all valid split pairs by exhaustive Algorithm 3 enumeration;
5. produces zero- and fixed-nonzero-$\sigma$ forgeries using public inputs;
6. passes each forgery to the ordinary Algorithm 6 verifier; and
7. checks one-invalid-block and strict representation controls.

The fixed seeds make the package output byte-for-byte reproducible. They are
not an attack assumption. The forger receives the public matrices, public
valid-split relation, and printed dimensions; it receives no private object.

The sealed primary audit accepted all four row/variant combinations and
checked 2,550 positive blocks. All four invalid-block controls and all sixteen
format controls rejected. The attack-only times were:

| Row | Variant | Blocks | Valid splits | Attack-only | Verification | Result |
|---|---|---:|---:|---:|---:|---|
| PS1 | $\sigma=0$ | 714 | 24 | 1.867 ms | 0.420 ms | accept |
| PS1 | fixed nonzero $\sigma$ | 714 | 24 | 0.469 ms | 0.504 ms | accept |
| PS2 | $\sigma=0$ | 561 | 40 | 0.423 ms | 0.460 ms | accept |
| PS2 | fixed nonzero $\sigma$ | 561 | 40 | 0.501 ms | 0.523 ms | accept |

The stable expected output is [`reference-output.json`](reference-output.json).

## Independent reproduction

Run the separately structured deterministic implementation with:

```bash
python3 reproduce-all-rows.py
```

This implementation uses a dense full-rank scrambler, separately written
matrix and permutation routines, independently derives Algorithm 3, generates
both complete public-key rows, and repeats the zero- and nonzero-$\sigma$
attacks. It also rejects changed-signature, invalid-block, and format controls.
Its expected output is
[`all-rows-reference-output.json`](all-rows-reference-output.json).

The retained sealed independent experiment was stronger than the deterministic
packaging run in one respect: it generated OS-random keys and ran key
generation, the public-only attacker, and verification as separate processes.
Private key material was never persisted, and the attacker process had no
signing-oracle interface. Both rows and both variants passed. That sealed run’s
manifest SHA-256 is
`c0e2c712fccb11803285f2f0bf03c16cee226b7b15f91d0eaab9ece71fae064d`.

## Negative controls

The primary and independent implementations each force one recovered block to
the pair $(0,0)$. Algorithm 3 excludes this pair at both rows, and the ordinary
verifier rejects. The independent implementation also keeps $z$ fixed, flips
one signature bit selected by an exhaustive search, and confirms rejection.
Malformed vector widths, values outside the declared spaces, and wrong message
arity reject before the algebraic test.

These controls distinguish the claimed identity from an always-accepting
verifier or a representation bug.

## Separate correctness observation

The primary reconstruction also exhibits a signer/verifier correctness gap
that is not needed for the forgery. Algorithm 5’s stated decoder contract
ensures an aggregate error in $E_\ell$, while Algorithm 6 requires every split
tuple to satisfy the stronger universal-permutation `ValidErrorSplits`
predicate. Two distinct local unit vectors can have a weight-two sum in
$E_\ell$, yet independent permutations can align them and produce zero, which
is outside $E_\ell$. The full-row control meets the stated aggregate decoder
condition and is rejected by Algorithm 6.

This observation is kept separate from the zero-query attack, which directly
constructs accepting transcripts.

## Implication and repair direction

The verifier relation is publicly solvable when the attacker may choose the
raw $z$ tuple: choose the checked error first and solve the linear equation for
$z$. Preventing the single choice $\sigma=0$ would not repair the design,
because the same construction works for every nonzero $\sigma$.

A repair must define the signed message domain and prevent the adversary from
solving backward from an arbitrary signature to an accepted signed value. An
explicit, analyzed preimage-resistant encoding from external messages into
$z$ could block this particular construction, but it would be a new transform
that is absent from the target and would require its own correctness and
security proof. A redesigned signature relation should bind the accepted
object to the signing key under a standard unforgeability argument.

## Verification and publication status

This package passed:

- the primary full-row reproduction;
- the separate fresh-context reproduction;
- the exact target-history gate;
- independent intended-message-space arbitration; and
- the amended adversarial technical and scope review; and
- independent publication/package review.

The publication reconciliation classifies this result as `VERIFIED_ATTACK`.
Independent human verification is optional under the project policy and was
not performed.

## Acknowledgements

The computations were performed on the Norwegian Research and Education Cloud (NREC), using resources provided by the University of Bergen and the University of Oslo.

## References

- Danilo Gligoroski and Simona Samardjiska, “A Digital Signature Scheme Based
  on Random Split of St-Gen Codes,” IACR ePrint 2016/391.
- Danilo Gligoroski, Simona Samardjiska, Håkon Jacobsen, and Sergey Bezzateev,
  “McEliece in the world of Escher,” IACR ePrint 2014/360.
- Samy Saad Samy Shehata, *Post Quantum Cryptography with random split of
  St-Gen codes*, NTNU master’s thesis, June 2017, supervised by Danilo
  Gligoroski, handle:11250/2450584.
- Dustin Moody and Ray Perlner, “Vulnerabilities of ‘McEliece in the World of
  Escher’,” *Post-Quantum Cryptography 2016*, 104–117,
  doi:10.1007/978-3-319-29360-8_8.
- Shafi Goldwasser, Silvio Micali, and Ronald L. Rivest, “A Digital Signature
  Scheme Secure Against Adaptive Chosen-Message Attacks,” *SIAM Journal on
  Computing* 17(2), 281–308, 1988, doi:10.1137/0217017.
- Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone, *Handbook of
  Applied Cryptography*, Chapter 11, CRC Press, 1996.
