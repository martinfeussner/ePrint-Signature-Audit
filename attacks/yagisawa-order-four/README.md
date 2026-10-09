# A Quarter Turn Is All It Takes: A Zero-Query Forgery against Yagisawa’s Quaternion Signature

> **Status: `VERIFIED_ATTACK`.** The full-parameter result passed technical,
> adversarial, independent-reproduction, final-history, and publication-review
> gates.
>
> **AI disclosure and review status.** This page documents this audit’s AI-assisted reconstruction of the attack. OpenAI Codex performed exact-version pinning, attack-history searching, scheme reconstruction, cryptanalysis, proof development, implementation, experiment generation, and technical writing. Specialist AI agents were used for technical, adversarial, reproducibility, and publication review. Independent AI reproduction is identified as AI reproduction and is not described as human verification. OpenAI Codex generated and selected the title and intentionally chose “A Quarter Turn Is All It Takes” as wordplay on the quaternion/order-four mechanism: multiplication by $i$ is a quarter turn, and its four-point power orbit defeats the verifier. No claim of independent human verification is made.

Masahiro Yagisawa’s [*A Digital Signature Using Multivariate Functions on Quaternion Ring*](https://eprint.iacr.org/2010/352), final revision `20100627:124304`, can be forged from its public coefficients without a signing query. For the paper’s claimed $d=2,r=3,m=448$ row, choose

```text
R = i = (0,1,0,0)
E = 2k = (0,0,0,2)
g = 2
T*(X) = F(iX) + (x2^13,0,0,0).
```

The ordinary verifier accepts this fresh-message forgery for every integer challenge $p$.

The complete report is in [`paper/attack.pdf`](paper/attack.pdf).

| Field | Result |
|---|---|
| Scheme | Yagisawa quaternion signature |
| Target | IACR ePrint 2010/352, final revision `20100627:124304` |
| Target PDF SHA-256 | `37ad500d8c0442173422d1976f9185b45302de819825624bdfa862de3ec5f9b9` |
| Claimed row | $q$ odd and larger than 20 bits; $d=2,r=3,m=448,s=13$ |
| Public coefficients | 2,240 |
| Attack | Public-key-only direct fresh-message forgery |
| Signing queries | 0 |
| Verification probability | 1 for every $p$ |
| Primary prime | $q=1{,}048{,}609$ |
| Public forger time | 0.001789767 s |
| Full primary run | 112.834013369 s internally; 1:53.69 wall |
| Peak memory | 19,968 KiB |
| Honest same-message control | 80/80 accepted |
| Fresh-message forgery | 80/80 accepted |
| Exact challenge classes | 4/4 accepted |
| Negative controls | 7/7 rejected |
| Layer | Design |
| Attack-history search date | 2026-10-09 |

## Impact

The attack copies and permutes the 2,240 public field coefficients, changes their signs where required, and adds one field coefficient. It neither recovers nor uses the secret factors $(k_h,A_h)$. It makes no signing query and submits the paper’s ordinary signed object $(T^*,R,E)$ on the fresh attacker-chosen message $E=2k$.

The full-parameter run generated an honest signature on that same message only after the public-only forger had finished. Both the honest signature and forgery passed every one of the four exact challenge classes and all 80 sampled large challenges. This control establishes that $E=2k$ is a working honest message for the reproduced key; the result does not rely on an un-signable target message.

We located no previous public attack against this exact Yagisawa construction in the searches performed as of **2026-10-09**. This is a dated search result, not an absolute priority claim. We make no novelty claim for the general vanishing-polynomial or small-evaluation-set principle. That principle is part of the classical foundation of polynomial identity testing, including work by [Zippel (1979)](https://doi.org/10.1007/3-540-09519-5_73) and [Schwartz (1980)](https://doi.org/10.1145/322217.322225).

## Target verifier

For secret $k_h\in\mathbb F_q$ and $A_h\in\mathbb H_q$, the public polynomial is

\[
F(X)=\sum_{h=1}^{m} k_h\prod_{\ell=0}^{d}
\left(A_h^{r^\ell}X^{r^\ell}\right),
\]

where the noncommutative product is taken in increasing $\ell$. For message $E=(E_0,E_1,E_2,E_3)$, the signer sets

\[
g=E_0+E_1+E_2+E_3
\]

and transmits a homogeneous quaternion-valued polynomial $T$, $R$, and $E$. The verifier first requires

\[
F(R^gE)\ne T(RE),
\]

then samples an integer $p$ and accepts when

\[
F(R^{g+p})=T(R^{p+1}).
\]

For $d=2,r=3$, the coordinate degree is

\[
s=1+3+3^2=13.
\]

Each of the four coordinates has $\binom{16}{3}=560$ homogeneous coefficients, giving 2,240 in total.

For this row, the paper describes 2,240 degree-14 equations in 2,240 secret
variables, estimates about `2^302` Gröbner-basis work against a `2^80` target,
and claims Gröbner-basis and differential resistance. The forgery bypasses
secret recovery, so it neither relies on nor validates those estimates.

## Public coefficient transformation

The Hamilton convention in the paper gives

\[
iX=(-x_1,x_0,-x_3,x_2).
\]

Therefore a public monomial transforms as

\[
x_0^{e_0}x_1^{e_1}x_2^{e_2}x_3^{e_3}
\longmapsto
(-1)^{e_0+e_2}
x_0^{e_1}x_1^{e_0}x_2^{e_3}x_3^{e_2}.
\]

The exponent tuple and coefficient map are

```text
(e0,e1,e2,e3) -> (e1,e0,e3,e2)
coefficient     -> (-1)^(e0+e2) * coefficient mod q.
```

This signed permutation constructs $F(iX)$ from public data. The attacker then adds one modulo $q$ to output coordinate zero at exponent tuple `(0,0,13,0)`, producing $T^*$.

## Why every challenge accepts

Since $q$ is odd,

\[
i^2=-1,\qquad i^4=1,
\]

so $i$ has exact order four. For every integer $p$,

\[
R^{p+1}\in\{1,i,-1,-i\}.
\]

All four points have $x_2=0$, hence the added polynomial $D(X)=(x_2^{13},0,0,0)$ vanishes. With $g=2$,

\[
T^*(R^{p+1})
=F(iR^{p+1})
=F(R^{p+2})
=F(R^{g+p}).
\]

At the preliminary inequality point,

\[
RE=i(2k)=-2j,
\qquad
i(RE)=-2k=R^2E.
\]

The shifted public polynomial therefore gives the same value as $F(R^2E)$, while

\[
D(RE)=((-2)^{13},0,0,0)\ne0.
\]

Thus the preliminary inequality and randomized equality both pass. The argument is exact and does not estimate a success probability.

## Hidden noncommutativity condition

The paper also says that $R$ and $E$ must not commute with any hidden $A_h$. The verifier cannot check this secret-dependent condition, but the primary reproduced key satisfies it exactly.

For a uniformly random quaternion $A$, the centralizers of $i$ and $k$ each contain $q^2$ elements and intersect in the $q$ scalar elements. Since $2k$ has the same centralizer as $k$,

\[
\Pr[A\text{ commutes with }i\text{ or }2k]
=\frac{2}{q^2}-\frac{1}{q^3}.
\]

For $m=448$, the union bound at the primary prime is less than $8.15\times10^{-10}$. The attack therefore applies overwhelmingly under independent uniform sampling, while the reproducer also audits the condition directly.

## Primary reproduction

From this attack directory, run:

```bash
python3 reproduce.py
```

The reproducer uses only Python’s standard library. It:

1. generates and expands a legitimate full-row key;
2. cross-checks public coefficient evaluation against the secret factorization;
3. passes only the public $F$ object to the zero-query forger;
4. checks the signed public monomial permutation;
5. proves coverage through all four residue classes of $p\bmod4$;
6. generates an honest signature on the same $E=2k$ only after forging;
7. evaluates 80 honest and 80 forged sampled challenges; and
8. runs seven negative controls.

The primary coefficient digests are:

| Object | SHA-256 |
|---|---|
| Public $F$ | `913281d14869095eb29d4a33c72e3c265364de7ee27ca4f0478f5fde998da160` |
| Publicly composed $F(iX)$ | `14a8d13f29d285638f3c0d38515354447c6cba8febc47c43d840af0bbed92e98` |
| Honest same-message $T$ | `54bea69be598c4b4dc96ead09b58d3a534585db657407248a86fb25a92bdcd3a` |
| Forged $T^*$ | `656154385287f8445f17f1e184dd5e7d6b0d1eff5475afdcc9b20e6ea7c3234c` |

The seven rejecting controls remove the perturbation, replace it by each of three wrong coordinate monomials, add two monomials visible on the challenge orbit, and reuse the forged object on the changed message $E'=2j$.

## Independent AI reproduction

The independent standard-library implementation uses the different conforming
prime `q=1048583` and separately written quaternion, polynomial, signing,
verification, and forger code. It invokes the forger as an isolated process
whose only input is serialized public `F`; the process has no secret or
signing-oracle interface and records zero queries. Run it with:

```bash
python3 reproduce-all-rows.py
```

The independent forgery and the post-forgery honest signature on the same
`E=2k` each passed all four challenge classes. The omitted perturbation,
orbit-visible perturbation, and changed message `E'=2j` controls all rejected.
The isolated public forger took 4.716746141 seconds, including JSON I/O. The
complete retained run took 60.009294720 seconds internally and 61.05 seconds
externally, with 22,528 KiB peak resident memory and one worker.

| Independent object | SHA-256 |
|---|---|
| Public `F` coefficients | `213ae3663e6cf2599d81c5141382bcc951699b8c6aee41712e10d66ce614441a` |
| Forged `T*` coefficients | `4a1350707a4bc3a043d5ab2d436b6214c826c3004994a06e2da08fab9b9cc633` |
| Honest same-message `T` coefficients | `a00eefe7e020a573c1c11ee6ddaa9660f788b081bdea0f386c4f92c4e2db1d33` |
| Independent source | `4a82384994684fdc25f1240f0990f9aeb78a9826a629783f767fa31673f6580b` |
| Public-only forger source | `d6898781f9bb8a1e1a327978392a834e25e245e363755bdcea9da94d419cef03` |
| Retained 19-entry manifest | `2fb137a850f32d75334a0bcbcc848b1ffd59edf1390c8698cc622b601b917f7c` |

## Secondary $g=1$ correctness defect

Choosing $E=k$ gives $g=1$, and the even simpler forged polynomial

\[
T^*(X)=F(X)+(x_2^{13},0,0,0)
\]

also verifies for every $p$. However, honest signing then produces $T=F$, which the preliminary inequality always rejects. This is a separate correctness defect in the stated message domain. The primary attack uses $E=2k,g=2$ because the reproduced honest signature and forgery both succeed on that same message.

## Limitations

- The measured claim covers the exact final revision and its explicit $d=2,r=3,m=448$ row. The algebra is independent of the secret coefficients, but this report does not claim measured results for other rows.
- The result is a direct forgery, not recovery of the nominal secret key.
- The paper provides no production implementation or complete byte-level wire format. The reproducer implements the published mathematical coefficient interface.
- The secret-key sampling distribution is not fully formalized. The primary instance audits every hidden noncommutativity relation, and the probability calculation covers independent uniform sampling.
- The attack-history statement is limited to the public searches performed through 2026-10-09.

## Repair

Banning order-four $R$ is insufficient. Every quaternion satisfies a quadratic relation over its scalar field, so all powers of any $R$ lie in the at-most-two-dimensional subalgebra $\operatorname{span}_{\mathbb F_q}\{1,R\}$. The verifier therefore samples from a predictable low-dimensional algebraic set even when $R$ has large order.

A repair must replace the verification design:

- do not authenticate an attacker-supplied polynomial through evaluations confined to powers of an attacker-supplied quaternion;
- bind the signed object to the message with a standard, analyzed signature transform and require evidence that it was derived from the signing key;
- if polynomial identity testing remains, sample from a domain outside predictable low-degree varieties and prove a soundness bound for the actual polynomial class; and
- make every message-domain condition publicly checkable and require honest correctness for every admitted message.

The paper’s one preliminary inequality cannot repair the restricted challenge locus.

## Acknowledgements

The computations were performed on the Norwegian Research and Education Cloud (NREC), using resources provided by the University of Bergen and the University of Oslo.
