# Pinned-source Iceberg reproduction

This directory contains the exact C diagnostic used for the source-backed
Iceberg execution. It calls the native Iceberg, BIP327 MuSig2, and BIP340
paths from the authors' benchmark artifact and verifies the three observed
outer signatures, recovered key, fresh signature, changed-message control,
and rank-deficient repeated-context control.

The target is the official repository
`https://github.com/furszy/benchmark-iceberg.git` at commit
`b2f87cb047467dd78852bc32722a5228a7167f5e`. The runner checks the following
construction files before compilation:

| File | SHA-256 |
|---|---|
| `sources/secp256k1-kmp/native/secp256k1/src/modules/iceberg/session_impl.h` | `16db2bff7e41f5a9f959cf691125a587ac6fc6062a08b4c7d9d4876f29a13c61` |
| `sources/secp256k1-kmp/native/secp256k1/include/secp256k1_iceberg.h` | `6664edc6a0c1532051a90ca42e669442eb8a73ccf4656cd26d1443476dcbc7f0` |
| `attack.c` | `e9787f333a1cd09411629eae9d1751de5c21e29f5b61e8d13102c708ec624e01` |

To replay using an existing checkout:

```sh
ICEBERG_SOURCE_DIR=/path/to/benchmark-iceberg ./reproduce-source-exact.sh
```

If `ICEBERG_SOURCE_DIR` is unset, the script clones the official repository.
It checks out the pinned commit in a temporary directory and deletes build
products on exit. A C99 compiler, Git, and the usual POSIX command-line tools
are required.

The retained run printed `result=PASS`, took 0.01 seconds, used 2,560 KiB peak
RSS, and used one worker. The C diagnostic is source-faithful corroboration of
the design-level result; it is not needed by the dependency-free Python
reproduction.
