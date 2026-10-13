# TOT-ally Forged: A Zero-Query Raw-Vector Forgery against TOT

> **AI disclosure and review status.** This audit used the OpenAI model
> Daybreak Blue at the ultra reasoning level. OpenAI Codex generated and
> selected this title and intentionally chose “TOT-ally Forged” as wordplay
> on the scheme name TOT. OpenAI Codex performed the source review, scheme
> reconstruction, cryptanalysis, implementation, experiments, and technical
> writing, with separate specialist AI agents for adversarial review, exact
> target history, independent reproduction, and publication review. All
> required campaign gates passed. No independent human verification was
> performed or required.

This report records a public-key-only, zero-query existential forgery against
the literal raw-vector signature interface in Wuqiang Shen and Shaohua Tang's
*TOT, a Fast Multivariate Public Key Cryptosystem with Basic Secure Trapdoor*,
IACR ePrint 2013/771.

TOT's verifier accepts a raw message vector $M\in\mathbb F_2^{128}$ and a
signature vector $\sigma\in\mathbb F_2^{128}$ exactly when

$$
P(\sigma)=M,
$$

where the complete quadratic map $P$ is the public key. A zero-query attacker
therefore chooses any nonzero $\sigma$, evaluates the public key, sets
$M=P(\sigma)$, and outputs $(M,\sigma)$. The ordinary verifier accepts by
construction. Because the attacker made no signing query, $M$ is fresh; and
because $M$ lies in the image of $P$, it is an honestly signable raw vector.

The complete report is in [`paper/attack.pdf`](paper/attack.pdf).

| Field | Result |
|---|---|
| Status | `VERIFIED_ATTACK`; all required publication gates complete |
| Scheme | TOT signature construction |
| Target | IACR ePrint 2013/771, single 2013-11-25 revision |
| Authors | Wuqiang Shen and Shaohua Tang |
| Target PDF SHA-256 | `8ee1200e43b60123cf02f0261bee8e381b1229fde8c7722df086d95e6b7784bc` |
| Target text SHA-256 | `4e95403d8f73be474ae0d57ac730370649d4271b2c9dc5b84bd9bb75b4bb794b` |
| Signed object | Literal raw vector $M\in\mathbb F_2^{128}$ |
| Attack | Choose nonzero $\sigma$, set $M=P(\sigma)$ |
| Signing queries | 0 |
| Secret inputs | 0 |
| Full parameter row | $q=2$, $n=128$, $d=6$, $t=64$ |
| Claimed security | More than $2^{90}$ operations |
| Primary full run | 7.93 s, 19,456 KiB peak RSS, one worker |
| Primary attack step | 5.360155 ms including public-key parsing |
| Independent reproduction | 6.798 s, 20,480 KiB peak RSS, one worker |
| Layer | Paper/patent design, literal raw-vector interface |

## Exact target and scope

The target is the content-hash-pinned ePrint object identified above. The
paper gives the signature family $q=2$, $n=128$, $d\geq6$, $t\geq64$ and
claims more than $2^{90}$ attack cost. The same inventors' signature patent
fixes the exact boundary row $q=2,n=128,d=6,t=64$ and repeats the $2^{90}$
claim. The reproductions use that complete row.

Section 3.3 of the paper calls $M=(y'_1,\ldots,y'_n)$ the message to be signed,
passes that vector directly to the trapdoor inversion, and defines validity by
the equality $P(\sigma)=M$. The same-inventors patent stores and transmits the
raw message/signature pair and compares public evaluation with the stored
message. Neither source specifies a document hash, salt, byte encoding,
domain separator, preimage check, or external document-to-vector transform.

The claim is confined to that literal raw-vector message space. It does not
claim a forgery for an independently prescribed document or a preimage attack
against a separately added document-hashing wrapper.

No author implementation or normative byte-level public-key, message, or
signature format was located. The reproducers' encodings transport the exact
finite-field vectors and complete quadratic map between isolated processes;
they are not presented as an upstream wire format.

## Why the attack works

For any public key and any chosen $\sigma$, public evaluation returns one
well-defined vector $P(\sigma)$. Defining the message to be that vector makes
the verifier equation true identically. This needs one public-map evaluation,
no secret, and no oracle query.

The attack is existential rather than selective: it produces a fresh message
instead of targeting a message fixed in advance. That is the standard
existential-forgery goal. The output is not an unsignable edge case. Its
witness $\sigma$ proves that $M$ is in the image of the trapdoor map, so the
honest signing relation has at least one valid signature for it.

## Technique and attack history

Choosing a candidate signature first and evaluating a public verification map
to obtain its matching message is a classical signature-first, key-only
existential forgery, also called a no-message attack. The report cites the
Goldwasser--Micali--Rivest security framework and the *Handbook of Applied
Cryptography* attack-goal hierarchy. It makes no novelty claim for that
general technique.

No prior public attack specifically against Shen and Tang's TOT (IACR ePrint
2013/771, sole publicly exposed revision dated 25 November 2013) was located
in searches performed through **13 October 2026**. The search covered the
exact title, ePrint identifier, authors, scheme and patent names, citations,
repositories, and attack-related terms. This is a bounded, dated result rather
than an absolute priority claim.

## Primary reproduction

Run from this directory:

```bash
python3 reproduce.py
```

The standard-library implementation:

1. constructs $\mathbb F_{2^{128}}$ and the exact $d=6,t=64$ central map;
2. samples six distinct roots and two invertible affine maps;
3. interpolates all 8,385 public coefficient blocks, for the advertised
   1,073,280-bit payload;
4. checks affine inverses, Frobenius normalization, the signing equation, and
   515 public-versus-secret evaluations;
5. gives a separate attacker process only the public key and an empty signing
   transcript;
6. creates the zero-query pair by evaluating $P(\sigma)$; and
7. passes it to the ordinary verifier and four strict controls.

The retained unselected full-row run accepted the forgery and rejected the
changed-message, changed-signature, swapped-field, and mutated-public-key
controls. It took 7.93 seconds and 19,456 KiB peak RSS with one worker. No
root, affine map, inverse, seed, target preimage, or honest signature was
serialized to the attacker.

## Independent reproduction

Run the separately written implementation with:

```bash
python3 reproduce-all-rows.py
```

A fresh-context AI agent derived this implementation from the public
specification without reading or reusing the primary code or results. It
generates a separate exact-row key, exposes only the public quadratic map to
its forger, makes zero signing queries, invokes its ordinary verifier, and
checks focused negative controls. Its sole sealed run accepted the forgery and
rejected all four controls. It took 6.798212471 seconds in total, used 20,480
KiB peak RSS, and used one worker. The public-only attack and ordinary
verification stages each completed in 0.09 seconds.

Both top-level commands create their ephemeral artifacts in a temporary
directory and print normalized JSON. The checked-in expected outputs are
[`reference-output.json`](reference-output.json) and
[`all-rows-reference-output.json`](all-rows-reference-output.json).

## Negative controls

The primary verifier rejects:

- the same signature with one message bit changed;
- the same message with one signature bit changed;
- the two vector fields swapped; and
- the same pair under a public key whose constant term is changed.

The independent implementation supplies separately written controls. These
tests distinguish the claimed equation from an always-accepting verifier,
field-order confusion, and accidental fixture agreement.

## Limitations and repair direction

The result is a raw-vector existential forgery. It does not recover the
secret key, sign an independently prescribed vector, or invert an external
document hash. None of those stronger outcomes is needed for the claimed
break.

An explicit preimage-resistant transform from external documents into the raw
vector space would block this direct backward construction by requiring a
document preimage for $P(\sigma)$. Such a transform is absent from TOT and
would define a modified signature scheme requiring its own correctness and
security analysis.

## Sources

- [TOT, ePrint 2013/771](https://eprint.iacr.org/2013/771)
- [Same-inventors US patent 9,948,463](https://patents.google.com/patent/US9948463B2/en)
- [Handbook of Applied Cryptography](https://cacr.uwaterloo.ca/hac/)

## Verification and publication status

The result passed source/API reconstruction, full-parameter primary
reproduction, hostile adversarial review, fresh-context independent
reproduction, final exact-target attack-history review, and independent
publication review. It is classified as `VERIFIED_ATTACK`. The paper and this
page disclose the AI-assisted work and the absence of independent human
verification.
