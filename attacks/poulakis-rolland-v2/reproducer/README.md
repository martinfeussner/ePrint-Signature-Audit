# Reproducer internals

`primary.py` is the frozen full-parameter reconstruction using the published
factors, `g`, and secret exponent. It repairs the two point defects in the
printed example by deriving the correct square root at the printed x-coordinate
and doubling the resulting order-`2n` point and its matching public point.

`independent.py` implements the same equations separately. It generates a new
exact-order subgroup generator, secret exponent, public point, and signing
split at the published 2046-bit composite-order endpoint. Its attacker
functions receive no factorization, secret exponent, signing split, or
`phi(n)`.

Both implementations use only the Python 3.12 standard library and instantiate
the paper's abstract hash and KDF interfaces with locally domain-separated
SHAKE256. The attack uses the public map scalar and does not depend on a hash
collision or hash weakness.

Run both paths with:

```sh
./reproducer/reproduce.sh
```

Each full run performs several 2048-bit modified Tate pairing evaluations and
normally takes a few minutes on one CPU.
