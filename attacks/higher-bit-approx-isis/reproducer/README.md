# Higher-Bit Approximate-ISIS public reproducer

This standard-library Python reproducer evaluates the ordinary verification
relation of Construction 1 in IACR ePrint 2022/1144 at all three Figure 3
columns labelled “This work.” It tests the length-`m` zero signature on
multiple freshly generated messages under canonical and centered residue
lifts. It uses no signing oracle, secret key, author code, or third-party
package.

Run a quick reproduction with a fresh operating-system seed:

```sh
./reproducer/reproduce.sh --quick
```

Run 64 fresh messages per affected row:

```sh
./reproducer/reproduce.sh --full
```

Both commands generate a fresh full-dimension public matrix for each row. A
successful JSON report begins with fields equivalent to:

```json
{
  "banner": "ATTACK REPRODUCTION: PASS",
  "rows_passed": 3,
  "signing_queries": 0,
  "status": "PASS",
  "workers": 1
}
```

The committed reference outputs are deterministic fixtures. Recreate them
with:

```sh
./reproducer/reproduce.sh --reference-quick > reference-output.json
./reproducer/reproduce.sh --reference-full > all-rows-reference-output.json
```

## What is evaluated

For a public matrix `A`, message `m`, and signature `x`, the paper's ordinary
verifier checks

```text
||x|| <= beta
||b^d A x - H(m)|| <= alpha.
```

Section 6.4 says parameter selection must respect

```text
beta >= s
alpha >= b^l sigma + sqrt(n) b^d s.
```

The executable comparison conservatively drops the nonnegative first term and
uses `alpha_floor = sqrt(n) b^d s`. It uses exact scaled integer squares, so no
floating-point threshold rounding affects the outcome. The experiment sets
`q=b^k`, as required by the paper's Algorithm 2 optimization; the proof itself
needs only `q<=b^k`.

The matrix routine traverses the complete advertised `n x m` matrix through a
general matrix-vector product. The identical zero product is reused across
messages as a deterministic optimization. The random-oracle adapter maps
messages uniformly to `Z_q^n` with domain-separated SHAKE256. This is an
explicit audit adapter, not an author serialization. The theorem is pointwise
for every matrix and every hash vector, so neither adapter choice drives the
positive result.

## Diagnostics

The reproducer also checks that:

- `A*0` and `A*e_0` differ through the general matrix path, where `e_0` is a
  well-formed in-domain signature;
- every generated message and hash vector is distinct;
- message-dependent residual norms vary; and
- a precommitted target vector `(q/2,...,q/2)` in `Z_q^n` is rejected under
  both lifts when Figure 3's printed empirical `||e||` is used solely as a
  diagnostic radius.

That printed `||e||` is not treated as the paper's missing `alpha`. The fixed
diagnostic tests the norm and comparison path without using an invalid
over-`beta` signature or choosing a threshold after observing a sample.

## Claim boundary

The result concerns Construction 1 under every threshold completion that
obeys Section 6.4. The paper does not publish concrete `alpha`, `beta`, or
`sigma` values for the three rows, a residue-lift convention, a hash-to-vector
and byte serialization, or the cited private implementation. It also omits a
complete public Ring instantiation. The reproducer therefore does not claim
an implementation replay or honest signing. Its full matrices are uniform
public surrogates; this is sufficient for the stated attack because `A*0=0`
for every possible public matrix.

Python 3.10 or newer is required. All runs are sequential and use one worker.

