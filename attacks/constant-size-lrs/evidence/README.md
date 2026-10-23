# Public evidence

- `public-evidence.json` is the deterministic full-row public evidence. It
  contains 1,024 public KGO triples, the 254 public pair coefficients and swap
  bits, the outside public key, missing-coefficient values, and positive and
  negative-control predicates. It does not disclose ring secret keys.
- `independent-full-row-stdout.txt` and `independent-full-row-time.txt` are the
  raw output and GNU time record from the sealed primary independent run.
- `independent-validator-output.txt` records the results of a separately
  written validator for both the ordinary and `python -O` runs. It checks the
  public curve equations, MiMC hashes, pair arithmetic, and predicate records;
  the full replay, rather than this validator alone, regenerates KGO points
  from the fixed scalar stream and recomputes the complete transcript.

The evidence SHA-256 is
`465e1c4273312f9a4937d3d08b12ca9e09e2117aebe1e8e4d5146a33f939e0a4`.
The sealed independent-reproduction manifest has SHA-256
`d4e595f593b0df32bf4cd8d122684be5023ff0795c10b5904ff3fbcadd6db883`.

In the authenticated raw stdout, `ATTACK_RECEIVED_RING_SECRETS=FAIL` and
`SETUP_TRAPDOOR_USED=FAIL` mean those prohibited conditions were false; they
are successful access-boundary checks, not failed attack verdicts.

These files demonstrate exact full-profile SMA Equation 15 and KZG Equation
17 execution. The ccGro16 and CPlink flags certify honest-witness relations;
they are not emitted group proof objects or a byte-level run of a complete
author verifier.
