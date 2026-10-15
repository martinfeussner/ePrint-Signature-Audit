<div align="center">
  <img src="assets/jevil.png" alt="Jevil logo" width="300">
  <br>
  <sub>Logo by Ela Bambust</sub>
</div>

# Jevil

[![CI](https://github.com/symbolicsoft/jevil/actions/workflows/ci.yml/badge.svg)](https://github.com/symbolicsoft/jevil/actions/workflows/ci.yml)

> [!CAUTION]
> ## ⚠️ EXPERIMENTAL — DO NOT USE IN PRODUCTION ⚠️
>
> **This is a research-grade proof-of-concept implementation of a brand-new,
> completely novel cryptographic scheme.** Both the *scheme itself* and this
> *implementation* have received **close to zero peer review**.
>
> - The construction has **not** been vetted by the cryptographic community.
> - The security proofs have **not** been independently verified.
> - The code has **not** been audited.
> - There are almost certainly bugs, side channels, and possibly fundamental
>   design flaws that have not yet been discovered.
> - APIs, wire formats, and parameter choices may change without notice.
>
> Treat this repository as a **research artifact only**. Do not use it to
> protect anything you care about. Do not deploy it. Do not rely on it for
> any security property whatsoever.

Jevil ([paper](https://eprint.iacr.org/2026/1103)) is a post-quantum few-time
signature scheme parameterised by a single signing budget `n*`.

Signatures `1..=n*` are existentially unforgeable; at
the `(n* + 1)`-th signature the secret signing key becomes **publicly
recoverable** by anyone observing the signatures — the cap is enforced not by
counters or hardware, but by the algebraic structure of a single committed
polynomial. `Params::new` accepts only `n_star` values for which `n_star + 1`
is a power of two (the paper's recommended regime), so `n_cliff = n_star + 1`
exactly for every deployment.

| | |
| --- | --- |
| **Public key** | 68 bytes |
| **Secret key** | 32 bytes |
| **Signature** | ~40 KB (n*=1) to ~337 KB (n*=1023) |
| **Classical security** | ≥ 124 bits below the cliff |
| **Quantum security** | ≥ 85 bits at default capacity (highly conservative estimate) |

## When to use Jevil

Jevil is designed for **audit-budgeted credentials** — settings where
over-signing must be *self-exposing* rather than merely policy-forbidden:

- a firmware vendor capping its own release count,
- an operator binding themselves to a per-tenure attestation budget,
- an ephemeral session signer with a per-session cap,
- any audit-budgeted credential whose holder shouldn't be trusted to honour
  the budget unilaterally.

It is **not** a general-purpose signature scheme. For everyday signing use a
stateful or unlimited-use post-quantum scheme such as ML-DSA or Falcon.
Jevil's value is in the cliff.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
jevil = "0.1"
```

The crate is `#![forbid(unsafe_code)]` and exposes a single library target.

## Quick start

```rust
use jevil::{Params, keygen, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Pick a signing budget. n_star = 7 means: up to 7 honest signatures;
// the cliff fires at the 8th. Params::new accepts only n_star values for
// which n_star + 1 is a power of two (1, 3, 7, 15, 31, …).
let params = Params::new(7);

// Generate a fresh key.
let mut rng = ChaCha20Rng::seed_from_u64(0);
let (pk, sk, cache) = keygen(&mut rng, params);

// Sign a message.
let signature = sign(&sk, &pk, &cache, params, b"firmware-image-v1.0.0");

// Anyone holding `pk` can verify.
assert!(verify(&pk, params, b"firmware-image-v1.0.0", &signature).is_ok());
```

Try the bundled examples:

```bash
cargo run --release --example basic    # minimal sign/verify
cargo run --release --example bench    # latencies across n_star
cargo run --release --example cliff -- 3  # public-key recovery demo
```

## Testing

Unit and integration tests cover:

- Field arithmetic correctness (commutativity, distributivity, inverse, NTT).
- Hash domain separation (every tag combination is distinct).
- Position-derivation distinctness, sortedness, and rejection sampling bias.
- Lift / symbolic-α correctness across `(ν, ν', K, R)` sweeps.
- Signature round-trip across `n_star ∈ {1, 3, 7, 15, 31}`.
- Tamper rejection: y-value flip, proof byte flip, wrong root, wrong
  message, wrong `n_star`, non-canonical field element, truncated signature.
- Determinism (same seed → byte-identical pk / signature).
- A pinned known-answer test (KAT) for `n_star = 3`, `seed = 0`,
  `msg = "jevil-kat-fixture"`.
- The **cliff property**: at `n_cliff` signatures, Lagrange interpolation
  recovers `f` byte-for-byte from observed `(x, y)` pairs.

```bash
cargo test                                            # standard
cargo test --release --test slow -- --ignored         # n_star = 127, 1023
KAT_UPDATE=1 cargo test --test kat -- --nocapture     # regenerate fixtures
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
