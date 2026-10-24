# Retained public evidence

`evidence.json` is the exact 7,526-byte output of the sole sealed independent
v2 run. It is retained unchanged at SHA-256
`f4b829edf9f822a8f44fbbf94108416a603571e7305d2e5bc1671e484995cfcd`.
It contains one trial, one success, one worker, the TEST2 profile, public
fingerprints, the complete transformation and Figure-8 predicates, two
Algorithm-2 tree audits, and eight negative controls. It contains no member or
authority secret, private key, credential, internal filesystem path, or source
code.

The evidence records a candidate-internal interval of
`0.01501373597420752` seconds and a Linux `RUSAGE_SELF` peak of 21,504 KiB.
That interval ends before final JSON serialization and `fsync`; it is not an
external whole-process time or a real-proof-system benchmark. The one observed
`u` was nonzero. Correctness for `u=0^255` follows statically from typed string
length and the unconditioned sampler; that rare edge was not observed.

Use `../reproduce.py --reference` or `../reproducer/reproduce.sh --quick` to
validate these retained bytes without running the attack. The standalone
validator does not import the model.
