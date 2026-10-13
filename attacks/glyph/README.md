# The Writing Was on the Floor: A Zero-Query Fresh-Message Forgery against GLYPH

> **Status: `VERIFIED_ATTACK`.** The full-parameter result passed the technical,
> practical, adversarial-review, independent-reproduction, final-history, and
> Publication Reviewer gates.
>
> **AI disclosure and review status.** This audit used the OpenAI model
> Daybreak Blue at the ultra reasoning level. OpenAI Codex generated and
> selected this title and intentionally chose “The Writing Was on the Floor”
> as wordplay on the scheme name and the verifier's `K`-floor operation.
> OpenAI Codex performed the scheme reconstruction, cryptanalysis,
> implementation, experiments, and technical writing, with separately tasked
> AI agents used for adversarial review and fresh-context independent
> reproduction. These were AI review and AI reproduction, not human
> verification. No independent human verification was performed or required.

This report records a practical public-key-only, zero-signing-query
fresh-message forgery against Arjun Chopra's final-v3 GLYPH signature scheme,
IACR ePrint 2017/766. The attack targets the numerical `(z1,z2,c)` signature
and message/hash interface specified by the paper and author source.

The complete report is at [`paper/attack.pdf`](paper/attack.pdf), and
the self-contained public reproducer is under
[`reproducer/`](reproducer/).

| Field | Result |
|---|---|
| Publication status | `VERIFIED_ATTACK`; all mandatory publication gates passed |
| Scheme | GLYPH |
| Target | IACR ePrint 2017/766, current final object (operational final v3, revised 2018-06-07) |
| Target author | Arjun Chopra |
| Construction family | Ring-LWE/GLP lattice signature with `K`-floor (`Compress2`) signature compression |
| Competition history | No relevant standardization or signature-competition history identified |
| Attack result | Public-key-only, zero-query fresh-message forgery |
| Technique | Strict-interior `K`-floor fixed point: set `z1=0`, derive the challenge from the zero floor, and choose bounded `z2` coefficients that reconstruct that floor |
| Technique provenance | Concrete application of public fixed-point and interval arithmetic; no claim that the general technique is novel |
| Affected parameters | Complete recommended row: `m=2048`, `n=1024`, `q=59393`, `B=16383`, `omega=16` |
| Signing queries | 0 |
| Primary result | 64/64 fresh-key, fresh-message forgeries accepted; 512/512 controls rejected |
| Primary cost | 0.076994 ms median attack core; 1.16 s complete 64-trial driver; 52.5 MiB peak RAM; 1 worker |
| Independent result | 64/64 accepted; 256/256 controls rejected |
| Independent cost | 2.596779495 s experiment body; 3.50 s measured wall time; 5.0 MiB peak RAM; 1 worker |
| Recorded CPU/workers | AMD EPYC Processor; 1 worker for every reported run |
| Layer | Design-level numerical verifier relation; ordinary pinned `glp_verify` |
| Conditions | Numeric paper/source signature fields and specified message hashing; no author-standardized external signature wire format exists |
| Reproduction status | Primary and fresh-context independent full-parameter reproductions passed |
| AI provenance | Daybreak Blue at ultra reasoning; AI cryptanalysis, implementation, review, and independent reproduction |
| Human verification | Not performed; not required for classification or publication |
| Last attack-history search | 2026-10-13 |

## Impact

An attacker can generate a signature accepted by the ordinary final-v3 GLYPH
verifier for a fresh attacker-chosen message using only the public key. The
attacker does not obtain a signature, call the signer, or use secret material.
This defeats the scheme's claimed fresh-message unforgeability at its complete
recommended 128-bit parameter row.

## Attack at a glance

For the recommended row, let

```text
K = B - omega = 16367
L = K - 1     = 16366
D = 2K + 1    = 32735.
```

For an attacker-chosen fresh message `mu`, form the sparse challenge from the
all-zero verifier target and set the first response polynomial to zero:

```text
c  = encode_sparse(SHA256(0^n || mu))
z1 = 0.
```

For each coefficient, compute the public residue
`u = (-t*c) mod q` in `[0,q)` and choose

```text
z2 =  0   when 0 <= u < D,
z2 = -L   when D <= u < q-L,
z2 = +L   when q-L <= u < q.
```

Every chosen coefficient has centered magnitude strictly below `K`. The three
reconstructed intervals are respectively `[0,32734]`, `[16369,26660]`, and
`[0,16365]`, all within `[0,D)`. Every coefficient of
`a*z1 + z2 - t*c` therefore has zero `K`-floor. The verifier hashes the same
zero polynomial used to derive `c`, so its challenge check closes and the
forgery is accepted.

The selector was exhaustively checked over all 59,393 residues. The primary
and independent trials reconstructed 65,536 zero-floor coefficients apiece.

## Exact target and scope

The exact target is the current final object of
[*GLYPH: A New Instantiation of the GLP Digital Signature Scheme*](https://eprint.iacr.org/2017/766),
operationally final v3 and last revised on 7 June 2018:

- target PDF SHA-256:
  `ff0eeaea3a9fcb830197ea954472869a08adbf42e64e727470fa8e0038c6682a`;
- extracted target text SHA-256:
  `8ecd84282a5a752e1c2256597b9a10bdf50bfdb8eb2c572fa34eba27e54c1f2a`;
- [author source](https://github.com/quantumsafelattices/glyph) commit:
  `74b96d691391f687fe8f91e1d5cb3c251762d7cc`;
- source tree:
  `2ae8eec4b23dc57fc816c8935da8c2a59a753196`;
- source archive SHA-256:
  `43c68dfab7e717bf37ba57be9aa2fc49270f8eb42bfa420c85bf473aca12fe60`.

The paper defines a signature as the numerical tuple `(z1,z2,c)`. The pinned
source exposes the same tuple as an in-memory structure and implements the
same bounds, `K`-floor reconstruction, message hashing, sparse encoding, and
challenge comparison. The primary tests pass the forged tuple to the ordinary
unmodified upstream `glp_verify` function.

Neither the paper nor the author source defines a portable external signature
byte format or parser. The evidence and public packages use a documented local
codec only to transport numerical test objects. The claim therefore covers
the intended numerical paper/source interface and its message/hash interface;
it does not claim a vulnerability in an unspecified wrapper or wire protocol.

## Experimental evidence

The sealed primary implementation separates key generation, public-key-only
forging, and ordinary verification into different processes. The forger links
no signing or key-generation code and receives only a public key and message.
Across 64 fresh OS-random keys and attacker-chosen messages:

- all 64 forgeries were accepted;
- all 512 changed-message, changed-length, changed-challenge, changed-floor,
  and out-of-bound controls were rejected;
- all 64 public keys, messages, signatures, and challenges were distinct;
- the median attack core took 76,994 ns;
- the complete driver took 1.16 s wall time and 53,760 KiB peak RSS;
- one worker was used.

A fresh-context AI agent independently rebuilt the attack from the pinned
public paper and source without reading the private lead or primary package.
Its separately written implementation accepted 64/64 fresh-key,
fresh-message forgeries and rejected 256/256 controls. Its experiment body
took 2.596779495 s; GNU `time -v` measured 3.50 s wall time and 5,120 KiB peak
RSS on one worker.

Separately tasked AI reviewers checked the interval proof, strict bounds,
Fiat--Shamir dependency order, ordinary-verifier path, process isolation,
symbol reports, exact target, intended scope, full-row constants, controls,
and retained manifests. Those adversarial reviews passed. This is independent
AI review and reproduction, not human verification.

## Relationship to prior work and attack history

This report does not claim novelty for public fixed-point reasoning, interval
selection, or the general attack technique. Its contribution is the concrete
full-parameter application to final-v3 GLYPH's `K`-floor verifier.

Ducas, Durmus, Lepoint, and Lyubashevsky described a same-message
strong-unforgeability malleability observation for original GLP12 in IACR
ePrint 2013/383. That observation changes an uncompressed low bit of an
existing signature, requires a prior signature on the same message, and
predates GLYPH's `Compress2`/`K`-floor mechanism. It is related context, but it
is not an attack on final-v3 GLYPH and does not provide this zero-query
fresh-message forgery.

We located no previous public substantive attack against final-v3 GLYPH in
the searches performed through **13 October 2026**. This is a dated, bounded
negative search result, not an absolute priority claim.

## Reproduction

The public package provides a self-contained C reproducer at
[`reproducer/reproduce.sh`](reproducer/reproduce.sh). From this attack
directory, run:

```bash
./reproducer/reproduce.sh --quick
```

The quick mode exercises the exact full parameter row with eight fresh trials.
For the complete 64-trial run used by the public reference output, run:

```bash
./reproducer/reproduce.sh --full
```

The reproducer uses one worker, compiles the pinned upstream verifier, checks
all 59,393 selector residues, generates fresh keys and messages, invokes a
public-only forging API, submits every forgery to the ordinary verifier, and
runs eight negative controls per trial. See
[`reproducer/README.md`](reproducer/README.md) for toolchain requirements and
the precise source-isolation boundary.

The canonical quick-mode summary is in
[`reference-output.json`](reference-output.json): it reports 8/8 accepted
forgeries and 64/64 rejected controls. The canonical complete-row summary is
in [`all-rows-reference-output.json`](all-rows-reference-output.json): it
reports 64/64 accepted forgeries and 512/512 rejected controls. Both modes
must report zero signing queries, all 59,393 selector residues passing, and
exit status zero.

## Limitations

- The claim is pinned to final-v3 GLYPH and the exact author source revision
  above. It is not generalized to unnamed descendants or modified variants.
- The claim concerns the numerical `(z1,z2,c)` and message/hash interfaces.
  No author-standardized external signature wire format exists to test.
- The experiments establish a practical fresh-message forgery, not recovery
  of the GLYPH secret key.
- Performance measurements describe the recorded AMD EPYC environment; the
  algebraic success does not depend on those timings.
- No independent human verification was performed. The Charter treats human
  verification as optional provenance rather than a publication gate.

## Repair guidance

No drop-in patch is validated here. Final-v3 GLYPH should not be used as
specified. A replacement must prevent an attacker from choosing a public
verifier target, deriving its challenge, and then realizing that target with
bounded response coefficients. That requires redesigning the compression and
verification relation, followed by a new correctness and unforgeability
analysis and full-parameter testing. Increasing the advertised security
parameters or merely rejecting the all-zero floor has not been shown to fix
the structural fixed-point problem. A revised specification should also
define a canonical external signature encoding if interoperable deployment is
intended.

## Files and provenance

- paper: [`paper/attack.pdf`](paper/attack.pdf);
- paper source: [`paper/attack.tex`](paper/attack.tex);
- reproducer guide: [`reproducer/README.md`](reproducer/README.md);
- reproduction entry point:
  [`reproducer/reproduce.sh`](reproducer/reproduce.sh);
- machine-readable record: [`metadata.json`](metadata.json);
- canonical expected result: [`reference-output.json`](reference-output.json);
- canonical complete-row result:
  [`all-rows-reference-output.json`](all-rows-reference-output.json);
- target paper: [IACR ePrint 2017/766](https://eprint.iacr.org/2017/766);
- pinned author source:
  [`quantumsafelattices/glyph@74b96d6`](https://github.com/quantumsafelattices/glyph/tree/74b96d691391f687fe8f91e1d5cb3c251762d7cc).

The primary reproduction, adversarial AI review, fresh-context independent AI
reproduction, and final post-reproduction history recheck are sealed in the
private audit state. The polished public package omits raw research logs and
private intake material.
