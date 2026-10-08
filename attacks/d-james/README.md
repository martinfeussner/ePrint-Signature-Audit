# D-James q5/128 equivalent-signing-key recovery

D-James in ePrint 2026/1650 v5 exposes its Dragon signature/hash tensor as
an unknown-basis expansion of a two-dimensional generalized Gabidulin code.
Recovering that code structure, then rank-decoding the public
signature/signature block, yields an equivalent HFE-IP central map. The
equivalent map signs fresh public hash vectors for the advertised q5/128 row.

Status: **`VERIFIED_ATTACK`.** The full-parameter attack passed technical,
adversarial, independent-reproduction, history, and publication review.

| Field | Result |
|---|---|
| Scheme | D-James |
| Paper | ePrint 2026/1650 v5 |
| Authors | Jacques Patarin and Alexandre Roullet |
| Family | Multivariate HFE-minus-IP signature with Dragon bilinear terms |
| Attack | Public-key-only equivalent signing-key recovery with fresh signing |
| Technique | Hidden matrix-Gabidulin recovery followed by rank-metric decoding and projected HFE-IP completion |
| Affected row | q5/128: `(q,n,m,a,n_y,r,D)=(5,94,73,21,111,2,6)` |
| Signing queries | 0 |
| Basis recovery | 97.62 s in an independent clean run |
| Completion and signing | 6:27.45 wall time |
| Peak RAM | 224.28 MB maximum observed recovery memory; 104,960 KiB signer RSS |
| CPU / workers | AMD EPYC Processor under KVM / 1 |
| Layer | Design |
| Conditions | Literal v5 `k<d` algebra and the paper's all-ones public target example |
| Independent reproduction | Clean same-key recovery plus two independently generated fresh keys; 3/3 executed keys succeeded |
| Verification basis | Three successful executions plus passed technical, adversarial, history, and publication reviews |
| Last attack-history search | 2026-10-07 |

## Impact

The attack takes only public quadratic and bilinear coefficients. It recovers
an equivalent central representation, lifts the fixed public right-hand side,
and signs a fresh digest without a signing query or the nominal secret key.
On the sealed q5/128 public key, a nonzero 94-symbol signature satisfies all
73 public equations for a fresh message at salt 0. The same signature fails
for every one of 256 salts on a changed message.

The recovered representation need not equal the original secret key. It has
the capability relevant to signature security: it produces new signatures
accepted by the ordinary public equations.

## Fresh-key reproduction

Two additional full attacks began from independently generated, sanitized
public-key artifacts and regenerated the determinants, resultants, recovered
basis, HFE-IP completion, Dragon maps, and fresh signature. Neither execution
imported the primary key's basis or a recovery checkpoint. Both separate
public verifiers recomputed the message hashes, accepted all 73 fresh-message
equations, and found no accepting salt among 256 changed-message controls.

- Fresh-key A used public input SHA-256
  `68a358ce0c20fbe7788319d379a6038f79421875a6c690837ccb771aef168401`.
  Recovery took 98.329 seconds; completion/signing took 391.33 CPU seconds,
  found salt 0 after 14 root attempts, and rejected all 256 controls.
- Fresh-key B used public input SHA-256
  `96810a4a5548a6a04aa8e176df12b51e137a6588e475293c5a8d68080ea1da47`.
  Its three interpolations took 19.55, 19.56, and 19.65 seconds, its resultant
  stage took 39.37 seconds, and completion/signing took 390.80 CPU seconds
  (6:31.36 wall). It found salt 2 after 63 root attempts and rejected all 256
  controls.

Together with the primary execution, all three tested keys succeeded. This is
a three-key empirical result, not a statistical success-rate estimate. Exact
artifact, transcript, forgery, and verifier hashes are pinned in
`fresh-key-evidence.json`.

## Why the public tensor reveals a Gabidulin parent

Let `K=F_(q^n)` and write the hidden field input as

```text
X = sum_i a_i sigma_i.
```

Every retained output coordinate has a trace representation
`phi_j(Z)=Tr(t_j Z)`. For q5, the Dragon term associated with public hash
coordinate `s` is

```text
Lambda_(0,s) X + Lambda_(1,s) X^q.
```

If `gamma_i` is trace-dual to `sigma_i`, unexpanding the public coefficient
of `a_i y_s` gives

```text
d_(s,j) = sum_i gamma_i c_(s,i,j)
        = t_j Lambda_(0,s) + (t_j Lambda_(1,s))^(q^-1).
```

Thus all 111 public hash slices form an `F_5`-subcode of

```text
G_2(t) = span_K {t, t^(q^-1)} in K^73.
```

This is exactly the kind of hidden matrix-Gabidulin structure attacked by
Vinçotte's work on Miranda. We make no originality claim for that recovery
primitive.

For this D-James row, choose three public output columns and form a public
`111 x 94` pencil

```text
A(u,v) = A_0 + u A_1 + v A_2.
```

At the hidden solution, `A(u,v)` has rank 93. Three maximal minors are
reconstructed by exact interpolation on a 95-by-95 grid over `F_(5^3)`.
The gcd of two resultants has factor degrees 1 and 94. The unique degree-94
factor defines the recovered copy of `K`; the common linear factor in `u`
recovers a full-rank hidden expansion basis. Unexpanding all public slices
then gives `K`-dimension two, and intersecting the parent with its Frobenius
shift recovers `span_K(t)`.

## Completing the equivalent signer

Polarizing each public signature/signature quadratic form gives a trace
adjoint operator. The q5 HFE contribution has linearized support
`{-1,0,1}`. The internal-perturbation contribution has image rank at most
four, so each public operator is a dimension-three Gabidulin word plus a
rank-four error.

The implementation decodes the HFE coefficients with an image-space
annihilator. All 73 residual operators have rank four, and the intersection
of their image spaces is the two-dimensional IP plane. Linear algebra then
recovers compatible IP coefficients and lifts their projected quadratic
terms. Two retained output coordinates recover each of the 111 Dragon
coefficient pairs. Random public evaluations certify that the resulting
central map reconstructs the complete projected public map.

For the paper's all-ones public target, the signer solves

```text
Tr(t_j C) = 1,  1 <= j <= 73,
```

enumerates the 25 IP guesses, roots the resulting degree-six polynomial over
`F_(5^94)`, checks IP consistency, and maps the root back to the 94 public
signature coordinates.

## Reproduction

The checked-in attacker input contains public coefficients, the public target,
and public message-hash vectors only. Deterministic key-generation seed
material and secret-derived validation fixtures are excluded.

From the attack directory, the quick verifier uses only Python's standard
library:

```bash
cd attacks/d-james
python3 reproduce.py
```

It recomputes the pinned SHAKE256 message hashes, evaluates all 4,465 public
signature/signature coefficient vectors and all 111 Dragon slices, checks the
73-symbol target, and tests all changed-message salts. It writes canonical
JSON to `result.json`; the checked reference is `reference-output.json`.

An independently implemented direct evaluator repeats the claimed-row check
without the partial-evaluation routine used by `reproduce.py`:

```bash
python3 reproduce-all-rows.py
```

Full public recovery requires Magma V2.29 or later:

```bash
cd attacks/d-james
./reproduce-full.sh
```

The wrapper exports `work/public-data.m` directly from the sanitized JSON,
interpolates all three public minors over `F_(5^3)`, recomputes both
resultants, writes `work/recovered-basis.m`, completes the equivalent signer,
and runs the dependency-free verifier. It does not load a determinant,
resultant, field, basis, trace-support, key-generation, or secret-derived
checkpoint. After signing, `extract_replay_witness.py` parses the generated
salt and signature, requires exact field equality with the published witness,
and sends that generated replay artifact to the public verifier. Expected
hashes and quick-verifier output are recorded in `metadata.json` and
`reference-output.json`. The checked end-to-end transcript hashes and resource
measurements are recorded in `full-replay-evidence.json`.

The same stages may be run individually from `attacks/d-james`:

```bash
mkdir -p work
python3 export_public_magma.py full-q5-128-public-key.json work/public-data.m
magma -b recover.m
magma -b complete_and_sign.m
python3 extract_replay_witness.py --signer-output work/full-attack-results.txt
python3 reproduce.py --forgery work/replay-forgery.json \
  --output work/public-verification.json
```

## Scope

No conforming v5 implementation is public. The available detailed Python/Rust
implementation predates v5 and uses the earlier zero right-hand side. Its
q5 key distribution agrees with the literal v5 coefficient construction:
the two listed HFE monomials, `k<d` IP terms, two IP forms, Dragon maps
`L_0,L_1`, random input/output masks, and 21-coordinate minus projection.
The experiment replaces only the verifier target with the paper's all-ones
example.

V5 does not specify a hash/XOF, salt domain, extension-field polynomial,
encoding, or root order. The transcript demonstration pins the independent
implementation's SHAKE256 mapping and 256-salt domain. The equivalent-key
recovery itself is independent of those choices and signs arbitrary public
hash vectors. We therefore claim a break of the paper-level algebra and its
q5/128 coefficient distribution, without claiming conformance to an
unavailable v5 byte format.

The demonstrated row uses the literal `k<d` IP range stated by v5's
degree bound. The older author notebook implements `k<=d`; that alternate
branch is outside the executed full-parameter claim. Other D-James rows were
not needed to establish the design break and are not claimed here.

## Prior art and provenance

The project located no previous public attack against exact D-James v5 in its
searches as of 2026-10-07. The claim is deliberately narrow: it concerns the
identification and complete exploitation of D-James's public tensor through
fresh signing. It does not claim that the component recovery methods are new.

- Target: [D-James: Ultra Short Multivariate Signatures](https://eprint.iacr.org/2026/1650)
- Vinçotte: [How to break the Miranda signature scheme over matrix Gabidulin codes](https://arxiv.org/abs/2609.30925)
- Le: [Breaking ACDGV MinRank Gabidulin encryption schemes over matrix codes](https://arxiv.org/abs/2608.03328)
- Metouke et al.: [Subcodes of Lambda-Gabidulin Codes for Compact-Ciphertext Cryptography](https://arxiv.org/abs/2604.18282)
- Reconstruction substrate: [mjosaarinen/xdjames at `4328ab3`](https://github.com/mjosaarinen/xdjames/tree/4328ab366c066554094033297eb1ef3ec8b21c6f)

Discovery, history search, cryptanalysis, implementation, adversarial review,
and reproduction were AI-assisted. The result is classified `VERIFIED_ATTACK`
under the project's recorded review gates.
