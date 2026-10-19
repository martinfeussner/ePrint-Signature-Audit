# Syndromes Solved Directly: A Zero-Signing-Query Forgery against SSD

> **Publication-review status:** primary reproduction, hostile adversarial
> review, fresh-context independent reproduction, the final exact-target
> attack-history recheck, and independent Publication Reviewer review passed.
> This public package is published in the ePrint Signature Audit repository
> and classified `VERIFIED_ATTACK`.
>
> **AI disclosure.** This audit used the OpenAI model Daybreak Blue at the
> ultra reasoning level. OpenAI Codex generated and selected this title and
> intentionally chose “Syndromes Solved Directly” as wordplay that spells the
> scheme acronym SSD and describes the direct public linear solve used by the
> forgery. OpenAI Codex assisted with cryptanalysis, implementation,
> experiments, adversarial review coordination, and technical writing. A
> fresh-context AI agent independently reproduced the attack on five new
> full-size keys. Independent human verification was not required.

This public report records a public-key-only, zero-signing-query
existential fresh-message forgery against the full standard SSD1760 parameter
set in Abdelhaliem Babiker's [*Digital Signature from Syndrome Decoding
Problem*](https://eprint.iacr.org/2022/1698), IACR ePrint 2022/1698.

The paper is at [`paper/attack.pdf`](paper/attack.pdf). The full-parameter
public implementation is documented in
[`reproducer/README.md`](reproducer/README.md).

| Field | Result |
|---|---|
| Publication status | `VERIFIED_ATTACK`; published with all required technical, history, reproduction, and publication-review gates passed |
| Scheme | Signature from Syndrome Decoding (SSD), standard mode |
| Target | IACR ePrint 2022/1698; pinned 14-page PDF SHA-256 `619903383e40bed6320d1fc0a17c61553073d11545eb12302cafe6a84cfbd80e` |
| Target author | Abdelhaliem Babiker |
| Construction family | Binary syndrome-decoding signature with structured public matrices |
| Attack result | Public-key-only, zero-signing-query existential fresh-message forgery by distinct-message search |
| Technique | Put public `H` in systematic form, fix 363 free ones, and solve the 242 pivots for each public message target |
| Technique provenance | Standard Gaussian elimination and affine completion; no technique novelty claim |
| Affected parameters | Standard SSD1760: `(n,k',d,omega,mu,k)=(1760,242,502,484,11,440)` |
| Ordinary acceptance interval | Inclusive weights `[473,513]` and `H*s=Y*hbar` |
| Ideal-model success | `Pr[110 <= Binomial(242,1/2) <= 150] = 0.9303737782253141` per message |
| Expected queries | 1.0748368273 public message-hash queries; 0 signing queries |
| Primary evidence | Fresh full-size key; honest weight 499 accepted; one-message weight-479 forgery accepted; four controls rejected |
| Adversarial evidence | Fresh full-size key; honest weight 501 accepted; one-message weight-473 forgery accepted; endpoint and wrong-key controls passed |
| Adversarial attack cost | 0.19 CPU seconds from before RREF through accepted candidate; one worker |
| Adversarial complete cost | 1.29 seconds wall, 23,552 KiB peak RSS; includes two keys, honest conformance, attack, and endpoint controls |
| Independent reproduction | 5/5 fresh full-rank keys forged; 6 total central public-hash queries; 0 signing queries |
| Independent attack time | 0.052984--0.053914 seconds per key from before RREF; 0.267922 seconds total |
| Independent complete cost | 14.76 seconds wall, 10.66 seconds user CPU, 0.07 seconds system CPU, 24,576 KiB peak RSS; one worker |
| Layer | Design-level ordinary verification relation |
| Source status | No author implementation located; independent paper-level Python and Magma reconstructions |
| Reproduction status | Primary, hostile adversarial, and fresh-context five-key independent reproduction passed |
| Human verification | Not performed; not required by the audit charter |
| Attack-history status | Final bounded exact-target recheck passed with moderate-high confidence on 2026-10-14; no previous public exact-target attack located |

## Impact

Algorithm 4 accepts a signature `s` when

```text
omega - mu <= weight(s) <= d + mu
H*s = Y*hbar.
```

For SSD1760 this gives the broad central interval `[473,513]`. A valid public
matrix `H` has only 242 rows but 1760 columns. Public row reduction exposes
1518 free coordinates. Fixing 363 of them to one leaves a unique 242-bit pivot
completion for every public target `Y*hbar`.

In the paper's random-oracle model, xor-folding the four 440-bit hash blocks
is surjective, and full-row-rank `Y` maps the result uniformly onto 242 bits.
The pivot assignment is consequently uniform. Its weight lies from 110 to 150
with probability `0.9303737782253141`, at which point the total signature
weight lies in `[473,513]` and the ordinary verifier accepts.

The attacker hashes distinct fresh messages until one public completion has
an accepted weight. It never queries the signing oracle or uses the private
key. Because the attacker searches over messages, the result is existential.
The package does not claim a universal forgery, success for every fixed
preselected message, LVK coverage, or a property of rank-deficient keys.

## Reproduction

Run one fresh full-parameter package reproduction:

```sh
./reproducer/reproduce.sh --quick
```

Run the affected-row wrapper:

```sh
./reproducer/reproduce.sh --all-rows
```

SSD1760 standard mode is the only affected advertised row claimed by the
sealed evidence. Each run builds two fresh structured keys, checks honest
acceptance, performs the public attack, cross-checks RREF completion through
an independent pivot-submatrix inverse, and exercises changed-message,
changed-response, wrong-key, zero-response, and equation-valid endpoint
controls. It uses one worker and emits machine-readable JSON.

Deterministic fixtures are available in
[`reference-output.json`](reference-output.json) and
[`all-rows-reference-output.json`](all-rows-reference-output.json).

The sealed fresh-context reproduction independently generated five valid
full-row-rank SSD1760 keys from operating-system entropy. All five fresh
forgeries passed the unchanged ordinary verifier. Their central public-hash
query counts were `1, 2, 1, 1, 1`, with zero signing queries. Changed-message,
weight-preserving changed-signature, independent wrong-key, and inclusive
endpoint controls passed for every key. The separate public-artifact validator
also passed after reading only retained public keys, messages, and signatures.

## Exact scope

The result applies to standard-mode SSD1760 and valid public keys satisfying
`rank(H)=rank(Y)=242`. Its exact probability statement uses the random-oracle
model specified by the paper. The executable package instantiates the
otherwise unspecified 1760-bit hash with SHAKE256 and explicit message bytes.
A successful SHAKE256 run is supporting evidence; it is not an unconditional
statement about every fixed SHAKE256 message.

The attack is ordinary public linear algebra. It is not generic exponential
low-weight syndrome decoding: the verifier's wide central weight interval
lets a fixed affine representative pass with constant probability.

## Specification issues and timer semantics

The following issues are disclosed but are not used as the cause of the
forgery:

- Gen1 permits `alpha_0=r=15`. At that value its candidate factors through a
  rank-198 matrix and cannot supply the 242 independent rows Gen2 requests.
  The attack is restricted to valid full-rank keys.
- Algorithm 3's printed while-condition uses both `omega-mu` and `d-mu`, while
  its prose discusses the `omega-mu` lower bound. The sealed honest signatures
  have weights 499 and 501 and satisfy both readings.
- The paper specifies only a 1760-bit random oracle. It gives no concrete hash,
  message encoding, signature serialization, or author implementation.
- SSD2744's `k'` is printed as `377` in Table I and `337` in Tables III and VI.
  No SSD2744 claim is made.
- The primary JSON field `seconds_including_rref` is mislabeled. Its
  0.000544-second timer begins after RREF and covers only candidate completion.

The reliable adversarial attack measurement is 0.19 CPU seconds, timed from
immediately before public row reduction through the first accepted ordinary
verification. The 1.29-second wall measurement covers the complete Magma
process, including structured key generation, honest conformance, a second
wrong key, and endpoint controls. These scopes must not be interchanged.

## Attack-history status

The mandatory final exact-target and route-specific recheck through 14 October
2026 located the proposal, resource and bibliographic pages, an ordinary
downstream citation, the distinct 2023/1956 FDSD successor, and unrelated
syndrome-decoding work, but no previous public exact-target key recovery,
equivalent signer or witness recovery, practical forgery, substantive
parameter compromise, or application of this affine-completion mechanism to
SSD. This is a bounded moderate-high-confidence public-search result: it
cannot exclude private, deleted, unpublished, or unindexed work, and it makes
no novelty claim for Gaussian elimination or linear algebra.

## Files

- [`metadata.json`](metadata.json): machine-readable verified-attack record;
- [`affected-rows.json`](affected-rows.json): exact claimed-row scope;
- [`paper/attack.tex`](paper/attack.tex) and
  [`paper/attack.pdf`](paper/attack.pdf): self-contained report;
- [`reproducer/ssd_reference.py`](reproducer/ssd_reference.py): full-parameter
  paper-level implementation and attack;
- [`reproduce.py`](reproduce.py) and
  [`reproduce-all-rows.py`](reproduce-all-rows.py): fresh/reference wrappers;
- [`SHA256SUMS`](SHA256SUMS): package seal.

