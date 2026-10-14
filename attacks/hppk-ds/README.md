# HPPK with Nothing: A Universal All-Zero Forgery against HPPK DS

> **VERIFIED_ATTACK.** Primary reproduction, hostile adversarial
> review, fresh-context independent reproduction, final exact-target history
> review, and independent Publication Review passed.

## At a glance

| Field | Value |
|---|---|
| Scheme | Homomorphic Polynomial Public Key Cryptography for Quantum-secure Digital Signature (HPPK DS) |
| Target | IACR ePrint 2023/1768, current ePrint body matching arXiv v2 |
| Paper | [`paper/attack.pdf`](paper/attack.pdf) |
| Authors | Randy Kuang, Maria Perepechaenko, Mahmoud Sayed, Dafu Lou |
| Family | Multivariate/polynomial signature over hidden rings with Barrett-transformed verification |
| Result | Universal all-zero fresh-message forgery at the paper level |
| Forgery | Four `(F,H)=(0,0)` pairs, one for each complete-hash segment |
| Signing queries | 0 |
| Affected rows | All 3 target Table 1 rows and all 15 benchmark Table 2 rows |
| Conditions | Ordinary published verifier equations, a structurally valid public key, and four independently verified field-sized hash segments; no malformed key, parser failure, signing oracle, or external condition |
| Layer | Design |
| Technique | Direct zero substitution into the published verifier equations; no technique novelty claimed |
| CPU model | AMD EPYC Processor |
| AI provenance | This audit used the OpenAI model Daybreak Blue at the ultra reasoning level. OpenAI Codex generated and selected the title and intentionally chose its HPPK/“happy” wordplay. |
| Primary pinned-Go evidence | 45/45 accepted messages across 15 fresh keys and 5 source-specific profiles |
| Primary resource record | 19.20 CPU seconds, 230,900 KiB peak RSS for the complete registered workflow; one worker |
| Independent paper evidence | 18/18 rows, 72/72 complete four-pair forgeries, 288/288 segments, and 1,440 coefficient pairs |
| Independent pinned-Go evidence | 192/192 attacker checks accepted across 12 fresh keys, 48 fresh messages, and 6 source-specific profiles; 96/96 honest checks accepted and 288/288 negative controls rejected |
| Independent resource record | 0.34 seconds, 7,680 KiB peak RSS, one worker |
| Final history gate | PASS with independent cross-check; bounded public search cutoff 2026-10-14 14:47:51 UTC |
| Publication status | `VERIFIED_ATTACK`; independently AI-reproduced; Publication Review passed |

## Impact

HPPK DS signs each field-sized segment of a message hash with a pair `(F,H)`.
For every coefficient used by the ordinary verifier, the target paper's
Equation (28) has the form

```text
U_ij(H) = H*p'_ij - s1*floor(H*mu_ij/R) mod p
V_ij(F) = F*q'_ij - s2*floor(F*nu_ij/R) mod p.
```

Setting `F=H=0` makes both coefficients zero exactly. Every subsequent
polynomial sum is therefore zero, so the verifier compares `0=0` for every
message, structurally valid public key, verifier-noise choice, and advertised
parameter row. The attacker needs only the public segment count, makes no
signing query, and uses no secret information.

The advertised SHA-256, SHA-384, and SHA-512 profiles split a complete hash
into four 64-, 96-, or 128-bit field representatives. A complete mathematical
forgery is consequently

```text
[(0,0), (0,0), (0,0), (0,0)].
```

The papers do not specify a canonical byte encoding. This package therefore
claims the mathematical four-pair signature, not a paper-defined wire string.

## Exact scope

The proof covers:

- the 64-, 96-, and 128-bit target rows in Table 1 of ePrint 2023/1768;
- all 15 explicit parameter rows in Table 2 of ePrint 2024/019;
- target Equation (28) and the intended coefficient range in Section 5.3; and
- benchmark Equation (8), including either printed `s1`/`s2` branch at zero.

The target table omits a concrete prime and an explicit `(n, lambda, m)` tuple.
The later benchmark gives exact primes and dimensions. No public or reviewed
row-exact implementation or archived vector was located. The executable
reproducer checks the parameter-independent identity for every transcribed
row. It does not present its deterministic coefficient fixtures as
author-generated keys or a row-exact implementation.

## Claimed security

The original HPPK DS paper sizes its parameter sets from the claimed
`O(S1*S2/p)=O(p^3)` key-recovery cost and reports estimated entropies of 192,
288, and 384 bits in Table 1. Propositions 3--5 separately present generic
forgery searches with claimed cost `O(S1*S2)`. The companion benchmark later
presents an optimized modulus-recovery search with claimed total cost
`O(2^L)`; its Table 2 sets `L=2*|p|_2+16` and labels Levels I, III, and V with
144, 208, and 272 bits. The all-zero forgery bypasses these searches by
directly constructing the fixed four-pair signature, independently of either
claimed entropy column.

## Paper evidence and pinned-Go evidence are separate

The design claim comes from the paper equations. The public
[`xtaci/hppk`](https://github.com/xtaci/hppk) source at commit
`a66c951eef2f231a228e8121a7a6391b991146e1` is separate corroboration:

- its verifier consumes one whole digest rather than four field segments;
- it requires source orders of at least five and uses source-specific hidden
  moduli and Barrett parameters;
- its signature JSON adds `Beta`, `S1Verify`, `S2Verify`, `U`, `V`, and `K`;
  and
- it does not implement any advertised paper or benchmark row exactly.

In the sealed primary experiment, a clean harness used the ordinary exported
`hppk.VerifySignature` endpoint. It created each signature object from public
array lengths and constants, serialized it as JSON, decoded it into a fresh
object, and verified three fresh messages before any control signing call. All
45 forged messages accepted across 15 unique fresh `GenerateKey` outputs and
five source-specific profiles. Attack signing queries were zero. Fifteen later
`Sign` calls were controls only.

All generated keys had the expected public shape and accepted honest
signatures, but `PublicKey.IsValid()` returned false because generated
ring-mapped coefficients can exceed `Prime` while that diagnostic requires
them to be smaller. The ordinary verifier does not call `IsValid`. This source
inconsistency is reported separately and is not the cause of the forgery.

The source declares Go 1.22.5 while the research host provided Go 1.22.2. The
registered module build stopped on that version check; the authorized fallback
copied the byte-identical pinned source to an offline GOPATH, disabled module
and network resolution, and compiled it without source edits. Pre- and
post-build source comparisons were empty.

## Fresh-context independent reproduction

A separately tasked AI agent independently reconstructed the paper relation
and the pinned source test. Its paper harness passed all 3 target rows and all
15 benchmark rows: 72/72 complete fresh-message signatures, 288/288 hash
segments, and 1,440 coefficient pairs. Every complete signature contained
four `(0,0)` pairs, and the attack made zero signing queries.

The separate source run covered custom 64-, 96-, and 128-bit profiles and the
source `DefaultPrime` at orders 5, 8, and 10. Across 12 unique fresh keys and
48 unique fresh messages, the ordinary exported verifier accepted 192/192
attacker checks: all-zero and live-auxiliary serialized objects, each under
both the correct and a wrong public key. The live form kept `F=H=0` while
using nonzero in-range auxiliary fields, legitimate array lengths, and the
source-derived normal positive `K`. Honest direct and serialized checks
accepted 96/96, while six negative-control classes rejected 288/288. The
attacker made zero signing queries and read no secret values. Exact source
inventories matched before and after execution. The source run used one
worker, 0.34 seconds, and 7,680 KiB peak RSS.

The first attempt completed the paper checks, then stopped at compilation
before creating or executing a source binary because of a pointer-slice
bookkeeping type error. A prospectively sealed one-line type correction
enabled the sole source execution; there was no result tuning or retry. The
sealed handoff, manifest, paper result, and source result have SHA-256 hashes
`b541f891c214fb633614e50211252cd4db2268ba0ca346b0bceacf5c3e20a18d`,
`7e46c648643754e2de850e8854d50409275afba856519067a85a5e5a1f70b08f`,
`fca4d1246dcc3f671022b5dd4e9ac471b29268f07e2529636889e244c9327dbe`,
and `1af9a9ec0b3bf46f6faa9c03683547240cc595b9cef17e86e39755fc5e745c9c`,
respectively. The failure/fix addendum and exact source pre/post manifest have
SHA-256 hashes
`25e04eaa40cd786fe9b8a1800029a3cee956169d8288eedb6c591b1068d3f963`
and `a0169dd8e2943e099c55c2795b188554d4ef1010160a33fd0553227f3efdb409`.

## Reproduce the paper-level result

Python 3.10 or newer is sufficient. No third-party package is used, and every
run is sequential with one worker.

```sh
python3 -B reproduce.py
python3 -B reproduce-all-rows.py
```

The quick wrapper checks one complete hash per row: 18 messages and 72 zero
pairs. The full wrapper checks four complete hashes per row: 72 messages and
288 zero pairs. Both cover all 18 rows. Successful JSON ends with the semantic
values:

```json
{
  "all_rows_pass": true,
  "banner": "ATTACK REPRODUCTION: PASS",
  "status": "PASS"
}
```

Stable fixtures can be compared byte for byte:

```sh
python3 -B reproduce.py --reference > /tmp/hppk-ds-quick.json
cmp /tmp/hppk-ds-quick.json reference-output.json
python3 -B reproduce-all-rows.py --reference > /tmp/hppk-ds-full.json
cmp /tmp/hppk-ds-full.json all-rows-reference-output.json
```

The controls require rejection of three- and five-pair objects, `F`-only and
`H`-only nonzero signatures under a live comparison fixture, and the exact
zero object under a test-only per-segment repair. A balanced nonzero fixture
must continue to pass that repair. The balanced fixture is a path control, not
an honest-signature claim.

## Attack history and attribution

In public searches completed through 14 October 2026 at 14:47:51 UTC, we
located no previous report of the four-pair all-zero universal forgery, or of
another practical signing compromise, against the exact Equation (28) HPPK DS
paper construction in ePrint 2023/1768. This is a bounded, dated result. It
cannot exclude nonpublic, deleted, unpublished, or unindexed disclosures, and
search and citation indexes can lag. We make no absolute novelty or priority
claim.

The search did locate a public-key-only forgery reported in September 2026
against a materially divergent HPPK-labelled implementation in
[`sergelen02/HPPK_2` PR #1](https://github.com/sergelen02/HPPK_2/pull/1).
The public branch commit
[`782f518...`](https://github.com/sergelen02/HPPK_2/commit/782f51815b011dbd16ac4dd5de48757e0fb69bf4),
titled “test: reproduce public-key-only signature forgery,” makes the report
explicit.
That implementation's attacker-supplied signature has four fields
`{F,H,U,V}`. Its demonstration chooses `F=H=1`, computes `U` and `V` from the
message and public key at `p=65537`, and passes a verifier that separately
checks `U=alpha*H mod p` and `V=beta*F mod p`. The paper target instead has an
`{F,H}` signature: its Equation (28) verifier derives every `U_ij(H)` and
`V_ij(F)` internally and compares two polynomial sides. The September result
is a real prior implementation-specific forgery, but it neither reports the
four-pair all-zero attack nor executes an advertised paper row. The repository
owner is not a target-paper author, and the history review found no target
association. We therefore classify it as related work against a divergent
implementation, not an attack on the exact paper construction.

The target paper's Propositions 3--5 present generic forgery searches with
claimed cost `O(S1*S2)` and do not give a practical advertised-parameter
compromise. Hao
Guo's ePrint 2023/453 gives a practical forgery against predecessor MPPK/DS,
whose public structure and linear verifier differ from HPPK DS. The September
2026 D-HPPK KEM preprint reports a Lattice Reconstitution Attack against the
original unmasked HPPK KEM; it does not analyze the ePrint 2023/1768 signature
verifier, recover a DS signing witness, or demonstrate fresh DS signing. These
items are relevant history, but each falls outside the exact Equation (28)
signature target.

## Repair boundary

For every hash segment, verification should reject the pair `(F,H)=(0,0)`, and
signing should resample if it produces that forbidden pair. This blocks the
exact paper-level forgery described here. It is a narrow mitigation, not a
proof that the remaining construction is secure. A complete revision should
also define component ranges and a canonical encoding. The divergent Go
format separately needs coherent range checks and binding of auxiliary values.

## Limitations

- No public or reviewed row-exact implementation or archived vector was
  located for an advertised paper or benchmark row.
- The target paper does not define a canonical signature encoding.
- Benchmark Algorithms 5 and 6 contain duplicated/missing signing terms, an
  extra coefficient index, and an `s1`/`s2` branch discrepancy; nearby size and
  parameter prose also conflict with Table 2. The claim is anchored to the
  target equations and intended ranges, where zero annihilates either branch.
- The pinned Go evidence is source-specific corroboration and must never be
  reported as execution of an advertised row.
- The final history result is a bounded public-search conclusion with
  moderate-high confidence.

## AI provenance

OpenAI Codex independently reconstructed, derived, and verified the attack and
performed AI-assisted attack-history research, algebra review, implementation,
experimentation, and this technical writing. Separately tasked AI agents
performed algebra/domain review, hostile adversarial review, and fresh-context
independent reproduction, and a final exact-target history recheck; all four
gates passed. OpenAI Codex generated and selected the title and intentionally
chose “HPPK with Nothing” as wordplay: HPPK visually echoes “happy,” while the
forgery consists entirely of zeros. A separately tasked independent AI
Publication Reviewer also passed the complete public candidate. No independent
human verification has been performed; it is optional and is not a publication
requirement.

## Sources

- [Target: IACR ePrint 2023/1768](https://eprint.iacr.org/2023/1768)
- [Benchmark: IACR ePrint 2024/019](https://eprint.iacr.org/2024/019)
- [Pinned public implementation](https://github.com/xtaci/hppk/commit/a66c951eef2f231a228e8121a7a6391b991146e1)
- [Predecessor MPPK/DS cryptanalysis: IACR ePrint 2023/453](https://eprint.iacr.org/2023/453)
- [Divergent implementation forgery: `sergelen02/HPPK_2` PR #1](https://github.com/sergelen02/HPPK_2/pull/1)
- [D-HPPK KEM preprint](https://www.preprints.org/manuscript/202608.1587)
- [`paper/attack.tex`](paper/attack.tex)
- [`affected-rows.json`](affected-rows.json)
