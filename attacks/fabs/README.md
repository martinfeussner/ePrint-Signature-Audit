# FABS-olutely Forged: A One-H0-Query, Zero-Signing-Query Universal Forgery Against FABS

> **VERIFIED ATTACK.** The primary paper-level reproduction, hostile adversarial
> review, fresh-context actual-pairing independent reproduction, final
> attack-history review and post-reproduction delta, and independent
> Publication Review all passed.

## At a glance

| Field | Value |
|---|---|
| Scheme | FABS: Fast Attribute-Based Signatures, Figure 1 KP-ABS |
| Target | [IACR ePrint 2026/022](https://eprint.iacr.org/2026/022), official record revised 18 January 2026 |
| Target authors | Liqun Chen, Long Meng, Yalan Wang, Nada El Kassem, Christopher JP Newton, Yangguang Tian, Jodie Knapp, Constantin Catalin Dragan, Daniel Gardham, and Mark Manulis |
| Construction family | Pairing-based key-policy attribute-based signature with a Schnorr-style proof of a policy-satisfying signing witness |
| Result | Universal fresh-message forgery accepted by the literal Figure 1 KP-ABS verifier |
| Technique | Construct a Fiat–Shamir proof for entirely public witnesses; no technique novelty claimed |
| Affected profile | Every legal public attribute set accepted by Figure 1 Verify; the retained full-size endpoint is the paper's evaluated 100-distinct-attribute set satisfying a legal 100-input all-AND MSP |
| Key-generation queries | 0 |
| Signing queries | 0 |
| Forgery work | One `H0` query and constant public group work for the minimal nonidentity form; the mathematical adversary needs no pairing or `H1` query |
| Layer | Design |
| Conditions | Literal Figure 1 verifier and ordinary typed group elements; no malformed input, weak key, collision, preimage, parser failure, or exceptional setup |
| Primary paper-model record | 0.11 seconds, 18,432 KiB peak RSS, one worker; 12/12 attack cases accepted and 8/8 negative controls rejected |
| Independent reproduction | **PASS, 5/5 fixed setup controls**: fresh-context Arkworks BN254 run with actual pairing operations at fixed nonzero setup exponents 1, 2, 3, 5, and 7; honest 1/3/100 controls accepted, both 100-attribute attack forms accepted, and eight controls rejected in every run |
| Independent resources | AMD EPYC Processor on a KVM x86_64 host; 3.77 seconds wall, 3.72 seconds user, 0.04 seconds system, 31,744 KiB peak RSS, one program thread, one Cargo build job |
| Human verification | Not performed; optional provenance and not a publication requirement |
| Attack history | No prior public attack against FABS was located in the searches performed as of 18 October 2026; the sealed post-reproduction delta completed at 04:02:59 UTC and returned clear |
| AI provenance | This audit used the OpenAI model Daybreak Blue at the ultra reasoning level. OpenAI Codex generated and selected the title and deliberately chose “FABS-olutely Forged” as wordplay on the FABS scheme name. |

## Impact

The adversary chooses any fresh message and any legal public attribute set,
makes no key-generation or signing query, and outputs a signature that the
ordinary Figure 1 verifier accepts. The attack therefore violates the paper's
adaptive EUF-CMA claim directly. It does not recover the master secret because
none is needed: it provides universal fresh-message signing capability from
public information alone.

The attack applies to the paper's KP-ABS construction. This package makes no
attack claim about the separate SP-ABS construction.

## Attack at a glance

For a signature

```text
(A, B, C, c, s_alpha, s_k, {s_i})
```

the literal verifier computes

```text
Y = e(A,g2) / e(B,C)
Z = X^s_alpha * Y^c
W = g1^s_k * product_i H1(attribute_i)^s_i * B^c
c_check = H0(A,B,C,Y,Z,W,message)
```

and accepts when `c_check = c`.

The minimal nonidentity forgery is the following numbered algorithm.

1. Receive the public key, a legal public attribute set, and choose a fresh
   message.
2. Choose a public nonzero scalar `rho` and set `A=B=g1`, `C=g2`, `Y=1_GT`,
   `Z=1_GT`, and `W=g1^rho`.
3. Make the sole challenge-oracle query
   `c=H0(A,B,C,Y,Z,W,message)`.
4. Return `s_alpha=0`, `s_k=rho-c`, and one zero scalar `s_i` for each public
   attribute, together with `A`, `B`, `C`, and `c`.

In formula form, it sets

```text
A = g1, B = g1, C = g2,
c = H0(g1,g1,g2,1_GT,1_GT,g1^rho,message),
s_alpha = 0, s_k = rho-c, s_i = 0 for every attribute.
```

Verification obtains `Y=1_GT`, `Z=1_GT`, and
`W=g1^(rho-c)g1^c=g1^rho`, exactly reproducing the tuple queried to `H0`.
All three transmitted group elements are nonidentity. The construction is a
valid proof for the public witnesses `beta=0`, `k=1`, and every `delta_i=0` in
the proof statement printed by the paper. No circular hash fixed point occurs:
the whole prechallenge tuple is fixed before the one `H0` query.

An all-identity form is even simpler. A strengthened form keeps
`A=B=g1,C=g2`, chooses `s_alpha=1` and nonzero public scalar attribute
responses, and makes `A`, `B`, `C`, `Z=X`, and `W` nonidentity. Thus checking only transmitted
identities, or only zero responses, does not repair the verifier.

## Why the security proof does not cover the transcript

The printed proof of knowledge establishes only

```text
Y = X^beta
B = g1^k * product_i H1(attribute_i)^delta_i.
```

It does not prove that `A`, `B`, and `C` came from an issued credential, that
the attributes satisfy the credential policy, or that
`beta=k*t` and `delta_i=gamma_i*k` for the same signing values.

Theorem 3 later assumes the honest structure that the verifier never checks.
Its forking step extracts `k*t` and `k`, divides to obtain `t`, computes a
`1/t` power, and finally uses an inverse containing `delta_id*k*t`. For the
nonidentity public witness, `k*t=0` and `k=1`, hence `t=0`; those inversions are
undefined even though Figure 1 accepts. The all-identity form also prevents
the stated division because its extracted `k` is zero.

## Scope and parameter boundary

The retained target is a 29-page full-version paper with SHA-256
`0660d99b322467489a85f9a7f239c145b00b5a024958e474cee295361364e8a8`.
The IACR Asia and Zenodo copies are byte-identical. The canonical IACR PDF
endpoint was inaccessible during the audit, so canonical byte identity is not
claimed. The official metadata records receipt on 6 January 2026 and revision
on 18 January 2026.

The paper names the BN254 curve but does not state a numeric bit-security
claim. The public model pins the common scalar order
`0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
The algebra works in every prime-order Type-III pairing group. Because the
paper's exact Charm/PBC backend and byte codec remain unresolved, this is an
explicit common BN254 instantiation and a construction-level result, not an
exact author-backend or byte-conformance claim.

The 100-attribute all-AND instance is a legal full evaluated workload from the
paper's performance section. It is neither a security level nor the only
affected attribute set. The zero-signing-query construction works for every
legal public attribute set because the minimal attribute responses are all
zero. A policy belongs to a signing key in the EUF-CMA game; it is not supplied
as an input to Figure 1 Verify and is not forged by this attack.

## Relationship to known techniques and prior work

The attack is an elementary application of a standard proof-system rule: a
Fiat–Shamir transcript only proves the relation encoded by its verification
equations. Here those equations admit public witnesses and omit credential
origin and policy consistency. We make no claim that Schnorr public-witness
transcripts, identity validation, or this general reasoning technique is new.

The original Schnorr identification/signature work and Fiat–Shamir transform
are cited in the accompanying paper. RFC 8235 and RFC 9591 are generic
examples of specifications that discuss
identity-element validation. They do not analyze FABS, and identity-only
validation does not stop the nonidentity form above. Earlier published attacks
on the Guo–Zeng and Maji–Prabhakaran–Rosulek ABS families concern different
constructions and do not disclose this FABS transcript.

No prior public attack against FABS was located in the searches performed as
of 18 October 2026. The comprehensive review was followed by a sealed
post-reproduction delta through 04:02:59 UTC; it found no new exact-target
attack and no evidence that the earlier review missed one. This is a bounded
statement about the searched public record, not an absolute priority claim.
It does not claim novelty for the technique or assert a categorical first.

## Reproduce

Python 3.9 or later is sufficient; there are no third-party dependencies.

```sh
python3 -B reproduce.py --reference
python3 -B reproduce-all-rows.py --reference
```

The first command replays the complete 100-attribute endpoint. The second
checks the all-identity, minimal nonidentity, and strengthened nonidentity
presentations. Both run honest controls, four fresh-message forgeries, and
eight negative controls through one general verifier. Their canonical outputs
are `reference-output.json` and `all-rows-reference-output.json`.

The model also checks 0-, 1-, and 3-attribute forms. The 0-attribute form is
an algebraic edge check, not the qualifying endpoint; the legal
100-distinct-attribute set satisfying the 100-input all-AND MSP is the retained
full-scale endpoint.

The model represents a cyclic-group element by its exponent solely to execute
group equalities. The attack code does not read those exponents as discrete
logarithms.

The `reproducer/actual-bn254/` directory also includes the exact independent
Rust source, `Cargo.toml`, `Cargo.lock`, and declared encoding specification.
That clean-room implementation
uses Arkworks BN254 G1, G2, GT, and `Bn254::pairing` operations. It reproduced
the attack for five fixed nonzero setup values. These are deterministic setup
controls, not random-key statistical trials. In each run, honest 1-, 3-, and
100-attribute signatures accepted; an equivalent minimal form with
`s_alpha=1`, `Z=X`, and zero adversarial `H1` queries accepted; the
strengthened form with nonidentity `A`, `B`, `C`, `Z`, and `W` and all 100
scalar attribute responses nonzero accepted; and all eight single-change controls
rejected. The forger made zero key-generation and signing queries. The sealed
run took 3.77 seconds wall and 31,744 KiB peak RSS on one program thread.
The Rust harness deliberately computed `Y` using actual pairings to test the
cancellation. The mathematical adversary can instead use the known target-
group identity and need not execute a pairing.

If the pinned crates are already present in the local Cargo cache, the actual
pairing source can be replayed without network access:

```sh
make actual-bn254
```

This command places Cargo build products under `/tmp`; cached crate archives,
the release binary and build tree, raw logs, and private sealed evidence are
not part of this public-package candidate.

Paper: [`paper/attack.tex`](paper/attack.tex) and [`paper/attack.pdf`](paper/attack.pdf).

## Repair direction

Rejecting identity values in `A`, `B`, and `C` is insufficient because the
minimal nonidentity forgery uses generators in all three positions. Rejecting
the derived value `Y=1` would change the stated construction and would also
require the honest signer to exclude zero choices that Figure 1 currently
samples from the full scalar field.

A repair needs a redesigned statement that binds `A`, `B`, and `C` to a
credential issued under the master key, binds the attribute responses to the
same MSP reconstruction coefficients and signing values, and excludes the
public zero-witness branch in a proved way. Any revised statement, sampling
rule, and serialization need a new correctness and unforgeability analysis.
This audit has not validated a drop-in repair.

## Limitations

- The public Python model is a typed mathematical verifier, not an exact
  author-source, Charm/PBC, or byte-codec execution.
- The author repository is pinned at commit
  `aed8ba37b86e7fce1cb797de9ab53a38e0214d68`, but it has no dependency lock,
  fixed known-answer vector, or normative transcript encoding.
- Static review found that the author signer omits general MSP reconstruction
  coefficients, so it cannot serve as an arbitrary-MSP Figure 1 conformance
  oracle. The attack does not rely on that source defect.
- The independent actual-pairing result is an explicit common BN254
  instantiation; it makes no Charm/PBC, author byte-codec, or author-source
  conformance claim.
- This result concerns KP-ABS unforgeability. It does not evaluate SP-ABS or
  either construction's anonymity.

## Sources and provenance

- Target paper: [IACR ePrint 2026/022](https://eprint.iacr.org/2026/022)
- Official venue record: [USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/chen-liqun)
- Pinned author source: [commit `aed8ba37`](https://github.com/Anonymous-Mystery/FABS/commit/aed8ba37b86e7fce1cb797de9ab53a38e0214d68)

OpenAI Codex reconstructed the scheme, derived and implemented the attack,
coordinated the experiment, and drafted the documentation. A separately tasked
AI agent completed hostile adversarial review. A fresh-context AI agent
independently reconstructed the verifier with actual Arkworks BN254 pairing
operations and returned PASS in five of five fixed setup checks. Independent
Publication Review returned PASS. Independent human verification has not been
performed and is optional.

