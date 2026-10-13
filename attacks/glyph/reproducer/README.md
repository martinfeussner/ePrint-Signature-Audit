# GLYPH full-parameter zero-query forgery reproducer

This package reproduces a public-key-only, zero-signing-query
fresh-message forgery against the final GLYPH design in IACR ePrint
2017/766.  It uses the complete recommended row
`m=2048, n=1024, q=59393, B=16383, omega=16`.

Run the quick path (eight fresh keys and messages):

```sh
./reproduce.sh --quick
```

Run the full path (64 fresh keys and messages):

```sh
./reproduce.sh --full
```

Both modes use one worker, exhaustively test all 59,393 possible selector
residues, compile the vendored verifier, generate fresh keys and messages
from the operating-system-seeded OpenSSL RNG, forge from public input only,
and submit every tuple to the ordinary upstream `glp_verify`.  Each trial
also requires rejection of eight controls: changed, shortened, and extended
messages; changed challenge sign and position; an in-bound response change
that makes the verifier floor nonzero; and out-of-range `z1` and `z2`.
Successful runs end with an explicit `ATTACK REPRODUCTION: PASS` banner that
reports runtime, peak RAM, environment, and worker count.

## Attack implemented

Let

```text
K = B - omega = 16367
L = K - 1 = 16366
D = 2K + 1 = 32735.
```

For an attacker-chosen message, the forger hashes the canonical all-zero
verifier-floor polynomial followed by the message and applies GLYPH's public
sparse challenge encoder.  It sets `z1=0`.  For each coefficient, let
`u=(-t*c) mod q` in `[0,q)`, and select

```text
z2 =  0   when 0 <= u < D,
z2 = -L   when D <= u < q-L,
z2 = +L   when q-L <= u < q.
```

Every `z2` coefficient is strictly inside the response bound
`abs(z2)<K`, and every reconstructed coefficient lies in `[0,D)`.  The
verifier therefore hashes the same all-zero floor polynomial, reconstructs
the attacker's challenge, and accepts.  No secret or signing query is used.

The independently written attack is isolated in `src/public_forge.c`.  Its
exported API accepts only a public key and message.  The build records its
undefined-symbol table and rejects any reference to key generation, signing,
or verification.  The driver calls the ordinary verifier from the unmodified
vendored `glp.c`; the build records both that call and the linked
`glp_verify` symbol.

## Source and dependency pins

The required upstream GLYPH files are vendored under `vendor/glyph` from:

- repository: <https://github.com/quantumsafelattices/glyph>
- commit: `74b96d691391f687fe8f91e1d5cb3c251762d7cc`
- tree: `2ae8eec4b23dc57fc816c8935da8c2a59a753196`
- license: public-domain dedication in `vendor/glyph/LICENSE`

`UPSTREAM-SOURCES.json` records the target PDF pin, source origin, commit,
tree, license, and every vendored file hash.  `UPSTREAM-SOURCES.sha256` is
checked before every build.  The vendored files are byte-identical to that
commit and are never patched.

The 2018 source calls `AES_ctr128_encrypt`, an OpenSSL 1.x convenience
symbol that OpenSSL 3 no longer exports.  The narrow adapter in `compat/`
restores that wrapper through OpenSSL's retained `CRYPTO_ctr128_encrypt`
primitive.  It changes no GLYPH source or algorithm.

The tested environment is little-endian x86-64 Linux, GCC 13.3.0, GNU Make,
GNU time, binutils, and OpenSSL 3.0.13 with development headers.  The build
uses GNU C11.  `requirements.txt` lists the system dependencies; no Python
package is needed.

## Outputs and secret handling

Each run writes `output/quick/` or `output/full/` with a machine-readable
summary, public-input/output hashes per trial, build and symbol reports,
environment details, GNU time statistics, and a verified checksum manifest.
The legitimate signing key exists only in process memory during setup, is
cleansed immediately after public-key generation, and is never serialized,
hashed into a report, logged, or passed to the forging function.  Retained
trial rows contain only hashes of public keys, messages, and forged
signatures.

The author artifacts do not define a portable external signature wire
format.  This reproducer tests the paper/source numerical `(z1,z2,c)`
interface and the ordinary message/hash interface; it makes no claim about
an unspecified document wrapper.
