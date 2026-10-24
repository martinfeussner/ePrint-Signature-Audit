# Reproducer

This standard-library Python package exposes two deliberately separate paths.

To validate the retained independent evidence without executing the attack:

```bash
./reproducer/reproduce.sh --quick
```

Quick mode parses and hashes the retained JSON, checks the exact TEST2 profile,
the one-query transformation, ordinary `GVf`, `TraceU`/`TVf`, Figure-8
freshness, both Algorithm-2 tree audits, the eight negative controls, and the
clean-room code binding. It does not import or run the model.

To start a fresh user-run after publication, provide a new output path:

```bash
./reproducer/reproduce.sh --full fresh-evidence.json
```

Full mode invokes the exact independently written clean-room program once,
with one trial and one worker, then validates the newly created JSON. It
refuses to overwrite an existing file. Each trial uses one `GSigHU` signing
query on the empty string and one `TraceU` query. The run uses fresh operating-
system randomness, so fingerprints and timestamps will differ from the
retained evidence.

`reproduce-all-rows.py` is byte-for-byte identical to the prospectively sealed
independent-v2 implementation (SHA-256
`3b3b62d9018b28cda7a279fd2145697421f5b132a5d3728d6c99daf2178ee863`).
Its opening comment records its historical pre-execution status; the bytes
were deliberately left unchanged. Those exact bytes were subsequently
executed once under review and produced the retained evidence (SHA-256
`f4b829edf9f822a8f44fbbf94108416a603571e7305d2e5bc1671e484995cfcd`).

The model is source-independent. It uses ideal, hidden-key credential and
proof capabilities and an ideal domain-separated LowMC surrogate. It does not
implement real LowMC, M-FORS, F-SPHINCS+, MPC-in-the-Head, an author codec, or
the official HBGS source. Its runtime is therefore a typed-model measurement,
not an end-to-end scheme cost.
