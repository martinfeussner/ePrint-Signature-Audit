# Full-Distance Syndrome Decoding one-query forgery reproducer

This standard-library-only reproducer generates a fresh full Level-I key,
obtains one ordinary signature on a non-target message, and places only the
public key and that one signature in a separate attack directory. A separate
process recovers the public transformation, forges a fixed fresh message, and
an ordinary verifier process checks the forgery and controls.

Run:

```bash
./reproduce.sh
```

To retain the public run artifacts:

```bash
./reproduce.sh --output /tmp/fdsd-run
```

The expected final banner begins with `ATTACK REPRODUCTION: PASS` and reports
one ordinary signing query, zero target-message queries, an accepted
fresh-message forgery, and rejected negative controls.

## Boundary

`generate_case.py` creates a fresh 32-byte seed with `os.urandom`, performs
the paper-level Level-I KeyGen and one ordinary Sign operation, and never
writes the seed, secret key, or coordinate labels. Its `public/` output holds
only `Hstar`, `R`, public metadata, and exactly one ordinary signature.

`public_attack.py` has no dependency on the reference KeyGen or Sign code. It
installs a Python audit hook after imports and permits reads only from the
four declared public files. It reads exactly the first JSONL record and
permits only its result-file write. `verify_forgery.py` then invokes the
ordinary reconstructed verification relation and applies changed-message,
unchanged-query, weight-preserving signature-change, and `zeta` controls.

The implementation uses one process at a time, one worker, and Python's
standard library. It targets the complete advertised Level-I row
`(n,k,L,epsilon,theta,d)=(1600,400,125,5,25,343)`.

## Source scope

No author implementation or test vector was located. `fdsd_reference.py` is
the audit's independent mathematical reconstruction of the paper, with the
frozen balanced `tau` partition and SHAKE256/MSB-first adapter documented in
the report. It is not represented as author code.
