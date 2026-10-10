# On a Roll: A One-Query Universal Forgery against Poulakis--Rolland v2

> **Status: `VERIFIED_ATTACK`.** Two standard-library implementations reproduced
> the full-parameter attack with the ordinary pairing verifier. The second
> implementation generated an independent subgroup generator, secret exponent,
> public key, and signing split.

[Poulakis--Rolland, IACR ePrint 2012/134, revision
`20150430:055329`](https://eprint.iacr.org/2012/134) maps every message to

```text
H(m) = [kappa_m] G_H,
```

where both `kappa_m` and the fixed group generator `G_H` are public. One
ordinary signature on a chosen source message can therefore be transported to
any distinct encodable target message. The attack keeps the response integer
unchanged, changes only the signature point, and needs no secret information.

The complete report is in [`paper/attack.pdf`](paper/attack.pdf).

## Result at a glance

| Field | Result |
|---|---|
| Scheme | Poulakis--Rolland v2 |
| Paper | IACR ePrint 2012/134, revision `20150430:055329` |
| Authors | Dimitrios Poulakis and Robert Rolland |
| Family | Composite-order pairing signature intended to combine factoring and elliptic-curve discrete logarithms |
| Result | One-query fresh-message forgery; the queried scalar response can be reused unchanged |
| Signing queries | 1 ordinary chosen-message query |
| Affected endpoint | Printed example: 1023/1024-bit factors, 2046-bit `n`, 2048-bit field |
| Primary run | 105.35 s wall on replay; 17,408 KiB peak RSS; one worker |
| Independent fresh-key run | 156.74 s internal wall; 17,920 KiB peak RSS; one worker |
| Independent attack time | 2.35 s for the fixed-target same-`s` transport; 4.54 s for the range-sampled form |
| Verification | Honest signature accepted; both forgeries accepted by the ordinary modified Tate-pairing verifier |
| Controls | Changed message, point, point sign, scalar, identity, and order-2 non-subgroup inputs rejected |
| Layer | Design |
| History finding | No exact-target v2 attack located in the searches completed as of 2026-10-09 |

## Attack

Write the public map output as `H(m_i)=[kappa_i]G_H`. Before its only
query, the attacker chooses `m0` with `gcd(kappa_0,n)=1`, asks for
`sigma_0=(s_0,S_0)`, and selects a fresh target `m1`. It computes

```text
mu  = kappa_1 * inverse(kappa_0,n) * g^(h(m1)-h(m0)) mod n
s_1 = s_0
S_1 = [mu] S_0.
```

Negative hash differences use the public inverse of `g modulo n`. For an
honest query, `S_0=[g^ell kappa_0]G_H` and
`s_0+ell = a+h(m0)+n (mod phi(n))`. Hence

```text
S_1 = [g^(ell+h(m1)-h(m0)) kappa_1]G_H,
```

and bilinearity turns the target verification equation into the already-valid
source equation. Reusing `s_0` preserves every scalar range check passed by the
honest signature. The source-message invertibility condition is public and can
be tested before spending the query; a nontrivial gcd would itself factor `n`.

The independent implementation also exercises a second form. It computes
`c=s_0-h(m0)`, `U=[inverse(kappa_0,n)]S_0`, and for a sampled fresh target sets
`s*=c+h(m*)`, `S*=[kappa_*]U`. The public bound
`s* <= n-2^1025` guarantees `s*<phi(n)` when both factors are below `2^1024`.

## Full-parameter reproduction

Both programs use Python's standard library only:

```sh
python3 reproduce.py
python3 reproduce-all-rows.py
# or run both:
./reproducer/reproduce.sh
```

The primary path uses the published factors, `g=2`, and published secret
exponent. The decimal `y(P)` in the paper is off-curve because it contains one
extra digit. Correcting that typo produces an order-`2n` point, and the printed
public point is likewise in the order-`2n` coset. The reproducer doubles both
points to obtain the intended exact-order-`n` public key before signing and
verification.

The independent path generates a new exact-order subgroup generator, secret
exponent, public key, and signing split at the same published endpoint. Its
attack functions receive no factors, `phi(n)`, secret exponent, or signing
randomness. The verifier decodes the affine point, checks `1 <= s < n`, checks
`[n]S=O`, and evaluates the full modified reduced Tate pairing in
`F_(q^2)`.

The paper leaves the concrete hashes, KDF framing, scalar/point encoding, and
identity encoding unspecified. The reproductions use explicit SHAKE256 domain
separation and ordinary compressed affine points. The transport uses only the
public scalar necessarily emitted by the Section 4 algorithm; it does not use
a collision or a favorable hash output.

Canonical results are stored in `reference-output.json` and
`all-rows-reference-output.json`. Timing fields are machine-dependent.

## Scope, prior art, and repair

This report concerns the second revision only. Version 1 had a different key,
signing, and verification system and was already labeled broken on the archived
ePrint record. Its old attack does not transfer to v2; the result here follows
from v2's fresh `(k,ell)` split together with its Section 4 map.

The transport technique is not claimed as new. Section 3.2, pages 38--40 of
Mehdi Tibouchi's 2011 thesis explains that BLS becomes forgeable when a
hash-to-group output has a public discrete logarithm relative to a fixed public
base, including the one-signature scaling attack when that base differs from
the key generator. The result here applies that established warning to the
specific v2 response and pairing equations. No public report of this exact v2
attack was located in the searches performed as of 2026-10-09; this is a dated
search result rather than an absolute priority claim.

The direct repair is to replace the public-scalar map with a standard
hash-to-group construction that does not reveal a usable discrete logarithm
between outputs, then re-prove the redesigned signature scheme. Merely changing
the fixed generator does not work: the one-query transport uses ratios of the
public scalars and never needs the generator's discrete logarithm.

## AI provenance

OpenAI Codex generated and selected the title. It intentionally chose
“On a Roll” as wordplay on Rolland. Target reconstruction, cryptanalysis, implementation, execution,
technical and adversarial review, independent AI reproduction, history
searching, and drafting were AI-assisted. The independent reproduction is an
AI reproduction and is not described as human verification.

## Artifact hashes

- Target v2 PDF: `a8b4eae608a28baf86e585fb19056a43881d3c386eae6f7fb6b2cf1d2d49c65f`
- Archived author-source gzip: `d67435736b459ef85c705dd726763204ac6400b3c3c9058ac2a2b2e25011ae86`
- Primary wrapper: `c9572e38344d01848029ad6c4903e41b1b7d2efb996b91ce37c7f3ae7ac496bb`
- Independent wrapper: `58cdd2f8e61b3c03e3ff0d5955822a884705eb10c8d86a194507da2365bc3aa3`
- Primary core: `9b2c4c22ca98a983d7e7df0797f269c32d5cdd838f0956bbb697dc646d4ac921`
- Independent core: `49bf7d87a5904550f2f0cef911c56fa93827aafb83cb7b5c86206825cb5bcb3a`
- Primary raw replay output: `eabe8dc9ff3d32cfe1bb5211ee133a5ebd1140df2b76164fa10ed24423581ff2`
- Independent raw output: `9d019f15e0335c350507a5078f3fb5cbcbcb754f73f977b5131b3f8a6ec32d08`
- Canonical primary reference output: `8eeb6cdf998db293840e3bdb93f4fdadcebf13500a69ea627a37acb708a3f4aa`
- Canonical independent reference output: `bdb96cca35a1719864d8308bbd044dac177e3febf368793d62f7c75489123246`
- Attack paper PDF: `de6211eddca02c00645cab4ccab9414066938c3f550dfe5e4bc579487309bd7b`
