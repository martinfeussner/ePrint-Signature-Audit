# Actual BN254 reproduction

This directory contains the Rust implementation used for the sealed
fresh-context independent reproduction. It executes the CUBE proof equations
with Arkworks BN254 G1, G2, scalar-field, and pairing operations and derives
the transcript challenge with Keccak-256.

| File | SHA-256 |
|---|---|
| `Cargo.toml` | `c1a619de502e24344db86d2bada9d9e4447a7faafafd0770298bc1ef933d7152` |
| `Cargo.lock` | `c7945f51c369a9409f9666af703c5c6574eae2b9cd8240abf79cfedfdba64630` |
| `src/main.rs` | `8e0dc0770d4eb9d447d95facef3ae388bbd77661000d2fa3f77b6940cdc963fe` |
| `reference-output.json` | `e4d142dc85a9a05ec80bc28b6b47e93f438e99577ac25930084f1e71051cfe7e` |
| `source-pins.json` | `9c57e45d9b8766bffef9ed50649ad1194e19e012c3851f5a8bcdeeb5de9520b5` |

With the locked dependencies already available in Cargo's cache, run:

```sh
make reproduce-offline
```

The program checks an honest proof and the all-identity candidate under the
five-word source profile and a seven-word paper-complete profile containing
the address and nullifier terms. It also checks changed messages and context,
four single-component mutations, and an honest changed-message control. The
candidate makes zero signing queries.

The publication-package rebuild completed in 126.35 seconds with 399,752 KiB
peak RSS using one Cargo job. The resulting execution output is byte-identical
to the sealed independent reproduction's normalized result.

The inputs are synthetic valid BN254 parameters. This executable does not
invoke an EVM or claim source-to-runtime bytecode identity. The separately
sealed read-only evidence at the author-listed Sepolia addresses is reported
in the attack paper and metadata with that narrower scope.
