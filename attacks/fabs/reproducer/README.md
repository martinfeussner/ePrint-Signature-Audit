# FABS paper-level reproducer

This dependency-free Python package implements the literal typed mathematical
KP-ABS verifier in Figure 1 of IACR ePrint 2026/022. It exercises three
public-witness forgeries, honest 1-, 3-, and 100-attribute all-AND controls,
four fresh messages, and eight negative controls.
The 0-attribute forms are algebraic edge checks only; the legal
100-distinct-attribute set satisfying the 100-input all-AND MSP is the retained
qualifying endpoint.

Run the compact 100-attribute replay:

```sh
./reproduce.sh --reference
```

Run every retained attack presentation:

```sh
./reproduce.sh --full --reference
```

The model represents elements of prime-order cyclic groups by exponents and
implements the bilinear map on those exponents. The attack routines never
inspect a discrete logarithm or a secret. The minimal nonidentity attack uses
only public generators and one public `H0` query. The strengthened variant
also uses public `X` and one `H1` query per attribute.

The pinned modulus is a common explicit BN254 scalar order. This package is a
construction-level mathematical replay. It does not claim exact Charm/PBC
backend, byte-codec, or author-source conformance. The separate clean-room
independent reproduction in `actual-bn254/` uses actual Arkworks BN254 curve
and pairing operations. Its exact source, dependency files, and declared
encoding are included. Its prospectively sealed run passed five of five fixed
setup controls at exponents 1, 2, 3, 5, and 7; these are deterministic checks,
not random-key statistical trials. Each run included honest 1-, 3-, and
100-attribute controls, both required
100-attribute attacks, and eight rejecting negative controls per run. It
took 3.77 seconds wall time and 31,744 KiB peak RSS on one program thread and
one Cargo build job. The source and lock are included; crate archives, build
products, binaries, raw logs, and private evidence are excluded.

