# Full-parameter reproducers

The two standard-library implementations independently construct the complete
`d=2`, `r=3`, `m=448`, `s=13` public polynomial specified in IACR ePrint
2010/352 and run the paper's ordinary two-stage verifier.

From this directory's parent, run:

```sh
python3 -B reproduce.py
python3 -B reproduce-all-rows.py
# or both sequentially
./reproducer/reproduce.sh
```

`reproduce.py` uses `q=1048609`; the independent implementation uses a
different conforming 21-bit prime and separately written polynomial and
quaternion code. Both create all 2,240 public coefficients from legitimate
secret parameters, forge from the public coefficient array alone, confirm an
honest signature on the same target message only after the forger returns,
exercise every challenge class modulo the exact order four of `R=i`, and run
negative controls.

The attack itself is a signed permutation of the public coefficients followed
by one field addition. Most runtime is spent generating a complete legitimate
public key and the honest control; timing values therefore measure
reproduction rather than the cost faced by the attacker.
