# Actual Arkworks BN254 reproduction

This directory contains the exact Rust source, `Cargo.toml`, and `Cargo.lock`
from the sealed fresh-context independent reproduction. It uses actual
Arkworks BN254 G1, G2, GT, and pairing operations.

The retained source and dependency pins are:

| File | SHA-256 |
|---|---|
| `src/main.rs` | `808eb1aad74c3da427459b175675bfdff4ac1a512a378206df9b86fbdb27ae28` |
| `Cargo.toml` | `07e9c71c53b5d70f5235a4b8d80e515fb95797fd3f1bc98d4120a187439fa4fa` |
| `Cargo.lock` | `0c2a3cbf50b8942a9474501ecc1878448afc80cbe7e65cf8968ac862aa76a3c4` |
| `ENCODING.md` | `bc188aa1d5491a9ba93d22b68f6541a5f500964f6d0a3192e8ac9348e304e55e` |

With the locked dependencies available, run:

```sh
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/tmp/fabs-public-actual-bn254-target \
cargo run --release --locked
```

For a previously populated Cargo cache, add `--offline` and set
`CARGO_NET_OFFLINE=true`. The source asserts one program thread and requires
`CARGO_BUILD_JOBS=1`. `ENCODING.md` specifies the typed, length-prefixed
SHA-256 input to `H0`, canonical compressed Arkworks group encodings, and the
deterministic SHA-256 try-and-increment map used for `H1`.

The sealed run passed five of five fixed setup controls at nonzero exponents
1, 2, 3, 5, and 7. These are deterministic controls, not random-key
statistical trials. Every run accepted honest 1-, 3-,
and 100-attribute controls, the minimal 100-attribute forgery, and the
strengthened 100-attribute forgery; all eight single-change negative controls
rejected. The minimal adversary made one `H0` and zero `H1` queries. The
independent Rust minimal form used `s_alpha=1` and `Z=X`; the separate primary
mathematical package also covers the equivalent `s_alpha=0`, `Z=1` form. The
strengthened adversary made one `H0` and 100 `H1` queries, with nonidentity
`A`, `B`, `C`, `Z`, and `W` and 100 nonzero scalar attribute responses. Both
made zero key-generation and signing queries. The measured Rust harness
computed `Y` with actual pairings to test the cancellation. The mathematical
adversary can use the known target-group identity without computing a pairing.

The sealed measurement was 3.77 seconds wall time and 31,744 KiB peak RSS on
one program thread and one Cargo build job. The sealed evidence remains in the
private audit state; this public subtree intentionally excludes crate
archives, build products, binaries, raw stdout/stderr, machine dumps, and
private logs.

This is an explicit common BN254 instantiation. It does not claim exact
Charm/PBC, author-source, wire-codec, or standardized hash-to-curve
conformance. The attack does not depend on the declared local oracle encoding.

