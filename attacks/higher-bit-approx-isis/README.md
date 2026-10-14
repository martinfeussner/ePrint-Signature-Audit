# A Bit Too Approximate: A Universal Zero-Vector Forgery against Higher-Bit Approximate-ISIS

> **Status: `VERIFIED_ATTACK`.** Primary reproduction, hostile adversarial
> review, fresh-context independent reproduction, the final exact-target
> attack-history recheck, and the independent Publication Reviewer gate
> passed. All required publication gates passed.
>
> **AI disclosure.** This audit used the OpenAI model Daybreak Blue at the
> ultra reasoning level. OpenAI Codex generated and selected this title and
> intentionally chose “A Bit Too Approximate” as wordplay on the scheme name
> Higher-Bit Approximate-ISIS and on the verifier radius becoming too
> permissive. OpenAI Codex assisted with the cryptanalysis, implementation,
> experiments, review coordination, and technical writing. A separately
> tasked AI agent performed hostile adversarial review, and a fresh-context AI
> agent independently reproduced the result. No independent human
> verification was performed or required.

This report records a zero-signing-query fresh-message forgery against
Construction 1 of Le Dévéhat, Shizuya, and Hasegawa's
[*On the Higher-bit Version of Approximate Inhomogeneous Short Integer
Solution Problem*](https://eprint.iacr.org/2022/1144), IACR ePrint 2022/1144.
The claim applies to every Figure 3 column labelled “This work” under every
choice of `alpha` and `beta` that obeys the threshold prescription in Section
6.4.

The paper is at [`paper/attack.pdf`](paper/attack.pdf), and the public
reproducer is documented in [`reproducer/README.md`](reproducer/README.md).

| Field | Result |
|---|---|
| Publication status | `VERIFIED_ATTACK`; all required publication gates passed |
| Scheme | Higher-Bit Approximate-ISIS hash-and-sign signature, Construction 1 |
| Target | IACR ePrint 2022/1144; pinned PDF SHA-256 `cbbbb33cacef911548d52de7990eff74479dbb2e4ab9467974770107458cabeb` |
| Target authors | Anaëlle Le Dévéhat, Hiroki Shizuya, Shingo Hasegawa |
| Construction family | Lattice hash-and-sign with higher-bit approximate trapdoors |
| Attack result | Public-key-only, zero-query universal fresh-message forgery under the Section 6.4 threshold prescription |
| Technique | Submit the all-zero signature; Section 6.4's required error radius already covers every vector in `Z_q^n` |
| Technique provenance | The generic zero-vector Approx-ISIS boundary is due to Chen–Genise–Mukherjee (ASIACRYPT 2019); no technique novelty claim |
| Affected parameters | All three Figure 3 “This work” rows: claimed AISIS costs 75.0, 155.4, and 153.9 bits |
| Signing queries | 0 |
| Primary evidence | 3/3 rows, 2 fresh messages/row, both lifts, all 12 target checks accepted; 3.63 s wall, 62,800 KiB peak RSS |
| Independent evidence | 3/3 rows, 64 fresh messages/row, both lifts, 384/384 target checks accepted; 11.40 s wall, 61,072 KiB peak RSS |
| Recorded environment | AMD EPYC Processor; one worker |
| Layer | Design-level ordinary verification relation |
| Source status | Authors' proof-of-concept is cited as private communication; independent paper-level verifier reconstruction |
| Human verification | Not performed; not required by the audit charter |
| Attack-history status | No prior public attack against the exact scheme was located in the searches performed as of 2026-10-14; bounded moderate-high confidence |

## Impact

Construction 1 accepts a signature `x` when

```text
||x|| <= beta
||b^d A x - H(message)|| <= alpha.
```

Section 6.4 states that the bounds `||x|| <= s` and
`||e|| <= b^l sigma + sqrt(n)b^d s` must be respected when setting `beta` and
`alpha`. Therefore every compliant completion has

```text
beta >= s
alpha >= sqrt(n)b^d s.
```

At `x=0`, the first norm is zero and the residual is `-H(message)`, independent
of `A`. Every canonical representative in `Z_q^n` has norm at most
`sqrt(n)(q-1)`, while the centered maximum is smaller. The paper defines
`k=ceil(log_b(q))`, hence `q<=b^k`. For the three affected rows,
`b^d s/(b^k-1)` is respectively `45.4069`, `67.6229`, and `3.8959`.
Consequently, even the conservative Section 6.4 radius covers the complete
target space. The same public zero vector verifies on every message and every
public key.

## Reproduction

Run the quick path on fresh full-dimension public matrices and eight fresh
messages per row:

```sh
./reproducer/reproduce.sh --quick
```

Run the complete 64-message public path:

```sh
./reproducer/reproduce.sh --full
```

Both modes test all three rows, both canonical and centered lifts, the ordinary
verification inequalities, and precommitted in-domain diagnostics. They use
one worker and zero signing queries. Successful output contains
`"banner": "ATTACK REPRODUCTION: PASS"` and exits with status zero.
Deterministic committed fixtures are in [`reference-output.json`](reference-output.json)
and [`all-rows-reference-output.json`](all-rows-reference-output.json).

## Exact scope and missing specification

The quantified claim is limited to Construction 1 under every `alpha,beta`
completion that follows Section 6.4. The paper does not give concrete row-wise
values for `alpha`, `beta`, or `sigma`; it prints `tau`, the Gaussian width of
`R`, instead. It does not fix threshold rounding, a residue lift, the
hash-to-vector mapping, byte order, public-key or signature serialization, or
the source of the cited private proof-of-concept. The table also does not
provide a complete Ring mapping.

For those reasons, this package does not claim a replay against author code,
an exact wire profile, or honest signing. The executable instantiates
`q=b^k`, both natural lifts, an explicit SHAKE256 random oracle, and fresh
uniform full-size matrices. The positive result is independent of these
choices because the proof holds for every matrix and every target vector.

Figure 3 contains additional inconsistencies that matter for interpretation:

- its third “This work” row reports `||y||=50533.7` and `s=3989.3`, although
  Section 6.4 states `||x||<=s`;
- the printed `||e||` values are much smaller than the Section 6.4 worst-case
  bound and are not labelled `alpha`; and
- Figure 2's matrix public-key size formula does not reproduce Figure 3's
  kilobyte values without an unstated structured representation.

These issues prevent an exact implementation-profile claim. They do not
change the universal `x=0` result for threshold choices that obey the paper's
explicit Section 6.4 instruction.

## Prior technique and attack-history status

Chen, Genise, and Mukherjee introduced Approx-ISIS and explicitly identified
the generic zero-vector boundary in *Approximate Trapdoors for Lattices and
Smaller Hash-and-Sign Signatures*, ASIACRYPT 2019. This audit claims no novelty
for that technique. Its contribution is the concrete application to the
higher-bit construction's published threshold prescription and all advertised
rows.

No prior public attack against the Higher-Bit Approximate-ISIS hash-and-sign
signature of ePrint 2022/1144 was located in the searches performed as of
2026-10-14. This is a dated, bounded result rather than an absolute priority
claim. The final-history handoff has SHA-256
`daadbc0743cb5ff1c76d2b1cd842261157e3dd438f06bc35579ee1529431c81b`;
its sealed evidence manifest has SHA-256
`9702681ceaaeb90882e0d04c9058f4558fe3f0a5412be2211bd3ede6212d4657`.

## Files

- [`metadata.json`](metadata.json): machine-readable attack record;
- [`affected-rows.json`](affected-rows.json): Figure 3 row transcription;
- [`paper/attack.tex`](paper/attack.tex) and
  [`paper/attack.pdf`](paper/attack.pdf): self-contained report;
- [`reproducer/hbaisis_reference.py`](reproducer/hbaisis_reference.py):
  ordinary verifier and experiment core;
- [`reproduce.py`](reproduce.py): fresh eight-message wrapper;
- [`reproduce-all-rows.py`](reproduce-all-rows.py): fresh 64-message wrapper;
- [`SHA256SUMS`](SHA256SUMS): package seal.

