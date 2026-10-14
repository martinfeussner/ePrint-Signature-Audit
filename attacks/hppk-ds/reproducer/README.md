# HPPK DS paper-level all-zero reproducer

This standard-library Python package evaluates the mathematical HPPK DS
verification equations for the three target rows in IACR ePrint 2023/1768 and
the fifteen benchmark rows in IACR ePrint 2024/019.

For each complete SHA-256, SHA-384, or SHA-512 hash, it constructs four
field-sized signature pairs:

```text
[(0,0), (0,0), (0,0), (0,0)].
```

Every coefficient in target Equation (28) becomes zero, so both the target's
noise-aggregated equality and the benchmark's per-column equality compare
zero with zero for all four segments.

Run one complete hash per affected row:

```sh
./reproducer/reproduce.sh --quick
```

Run four complete hashes per affected row:

```sh
./reproducer/reproduce.sh --all-rows
```

Use the committed deterministic fixtures:

```sh
./reproducer/reproduce.sh --reference-quick
./reproducer/reproduce.sh --reference-all-rows
```

Every run checks exactly 18 rows, zero signing queries, the four-pair length,
three target verifier-noise choices, and live nonzero and repair controls. The
full run checks 72 fresh messages and 288 segment pairs.

The target Table 1 does not publish a prime or explicit `(n, lambda, m)` tuple.
Its arithmetic probe uses the corresponding later benchmark prime solely to
execute a parameter-independent identity and labels that choice in its JSON.
No fixture is presented as an author key or row-exact implementation. The
separate pinned Go experiment is deliberately absent from this reproducer
because that source does not implement the advertised rows.

Python 3.10 or newer is required. There are no third-party dependencies, and
execution uses one worker.
