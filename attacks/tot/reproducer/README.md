# TOT public reproducer

The `primary/` and `independent/` directories contain separately written
standard-library Python implementations of the raw-vector zero-query forgery
at `q=2,n=128,d=6,t=64`.

The primary implementation runs key generation, the attacker, and the
ordinary verifier as separate processes. It serializes only the full public
quadratic map and an empty signing-query transcript. The independent
implementation was derived from the public specification in a fresh context
without reading the primary code or results.

Use the stable wrappers in the parent directory:

```bash
python3 reproduce.py
python3 reproduce-all-rows.py
```

Each wrapper creates a fresh temporary run, verifies all assertions, removes
the ephemeral key and transcript artifacts, and prints normalized JSON. Both
use one worker and require no network access or third-party Python packages.

`UPSTREAM-SOURCES.json` records the target ePrint and same-inventors patent
pins used for reconstruction. The source documents themselves are not
vendored.
