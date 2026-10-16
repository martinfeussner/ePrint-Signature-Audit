# DualMS 2.0 paper-level reproducer

This public reproducer implements the rounded verifier in
Section 3.2 of IACR ePrint 2026/1941 and the public hint-slack forger described
in the accompanying paper. It uses only Python's standard library and one
worker.

A separately sealed fresh-context reproduction passed for both advertised
rounded rows. This package's own self-test remains supplemental validation
and is distinct from that independent reproduction.

## Run it

Replay both advertised rounded rows with the stable package seed:

```sh
./reproduce.sh --reference
```

Run with fresh operating-system entropy:

```sh
./reproduce.sh
```

Run one row:

```sh
./reproduce.sh --reference --profile n32
./reproduce.sh --reference --profile n1024
```

No signing oracle is called. The 32-signer row may use multiple `Hsig`
queries; the 1,024-signer row uses one. The default cap is 512 candidates and
can be changed with `--trial-limit`.

## What is exercised

For each row the runner:

1. instantiates the exact paper-plus-author-artifact modulus and Table 6
   dimensions;
2. generates the public matrix and one honest challenge public key;
3. constructs the remaining distinct adversarial registration keys allowed by
   the printed MS-UF-CMA game;
4. hashes a direct injective length-delimited encoding of the complete list and
   runs ordinary `KeyAgg`;
5. chooses a rounded commitment, queries `Hsig`, and builds the zero-response
   hint forgery;
6. submits it to a general verifier that computes all four printed terms and
   all printed bounds; and
7. requires changed-message, changed-challenge, changed-response,
   noncanonical-hint, and changed-registration-list controls to reject. The
   32-signer row also requires an excessive canonical hint to fail its norm
   check.

The JSON report records the seed, query count, norm values, list and aggregate
key digests, signature digest, controls, wall time, peak resident memory, and
worker count. It does not expose the honest secret key.

## Specification completion

The paper gives random-oracle domains over bitstrings but no normative final
tuple encoding, aggregate-key wire codec, aggregate-signature wire codec, or
known-answer vector. This code uses SHAKE256 with explicit domain strings and
64-bit length prefixes. `Hagg` absorbs the full injective list encoding
directly, followed by the signer index and public key. This is a declared
non-normative completion.

The result does not depend on a specific completion. The public forger queries
the same `Hsig(w,message,aggpk)` interface that the verifier evaluates and
copies the returned challenge into the signature. It does not use a collision,
alias, parser discrepancy, or selected hash value.

## Profile boundary

The exact integer moduli are selected by the paper-linked Sage artifact because
Table 6 prints only their bit lengths:

| Profile | `q` | `q_b` | `q_w` |
|---|---:|---:|---:|
| rounded `n=32` | `2113928077` | `1032191` | `31` |
| rounded `n=1024` | `4160748533` | `2031615` | `15` |

The author Go implementation uses different NTT-friendly moduli. This package
does not claim source conformance or byte-exact author compatibility.
