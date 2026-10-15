//! # Jevil — a stateless few-time signature scheme with a sharp cliff
//!
//! Jevil is a stateless few-time signature scheme parameterised by a single
//! signing budget `n*`. Signatures `1..=n*` are existentially unforgeable; at
//! the `(n* + 1)`-th signature the secret signing key becomes *publicly
//! recoverable* by anyone observing the signatures — the cap is enforced not
//! by counters or hardware, but by the algebraic structure of a single
//! committed polynomial. [`Params::new`] accepts only `n_star` values for
//! which `n_star + 1` is a power of two (the paper's recommended regime), so
//! `n_cliff = n_star + 1` exactly for every deployment.
//!
//! ## When to use Jevil
//!
//! Jevil is designed for **audit-budgeted credentials**:
//!
//! - firmware vendors capping their own release count,
//! - operators binding themselves to a per-tenure attestation budget,
//! - ephemeral session signers with a per-session cap,
//! - any setting where over-signing must be made *self-exposing* rather than
//!   merely policy-forbidden.
//!
//! It is **not** a general-purpose signature scheme — for everyday signing,
//! use a stateful or unlimited-use post-quantum scheme such as ML-DSA or
//! Falcon. Jevil's value is in the cliff.
//!
//! ## Properties
//!
//! - **Stateless signing.** No counter, no per-signature state — the signer
//!   only stores a 32-byte seed.
//! - **Cryptographic budget enforcement.** The cliff at `n_cliff` is intrinsic
//!   to the public-key commitment; no malicious signer can extend it.
//! - **Post-quantum.** All primitives (Poseidon2, SHAKE256, WHIR) are
//!   plausibly post-quantum at 128-bit classical security (≥ 85 bits quantum
//!   at the recommended capacity; raise capacity for 128-bit quantum).
//! - **Compact public keys** (68 B) and **moderate signatures** (~94 KB
//!   at n*=1 up to a few hundred KB across the deployable range).
//!
//! ## Quick start
//!
//! ```no_run
//! use jevil::{keygen, sign, verify, Params};
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! // Budget: at most 7 honest signatures (cliff fires at the 8th).
//! let params = Params::new(7);
//!
//! let mut rng = ChaCha20Rng::seed_from_u64(0);
//! let (pk, sk, cache) = keygen(&mut rng, params);
//!
//! let signature = sign(&sk, &pk, &cache, params, b"firmware-image-v1.0.0");
//! assert!(verify(&pk, params, b"firmware-image-v1.0.0", &signature).is_ok());
//! ```
//!
//! ## Parameter selection
//!
//! Jevil takes a single integer parameter `n_star` (the signing budget).
//! `n_star + 1` must be a power of two — i.e. `n_star ∈ {1, 3, 7, 15, 31, 63,
//! 127, 255, 511, 1023, …}`; [`Params::new`] panics on any other value to
//! prevent accidental deployment into the soft-degradation regime. Within
//! this set the cliff fires precisely at signature `n_star + 1`. See
//! [`Params`] for the full parameter derivation.
//!
//! Reference sizes at the recommended `K = 16` positions-per-signature,
//! measured post-size-optimisation on Apple-Silicon-class hardware:
//!
//! | `n_star` | `M`      | `T`      | KeyGen | Sign   | Verify | Sig     |
//! |---------:|---------:|---------:|-------:|-------:|-------:|--------:|
//! |    127   | 2¹¹      | 2²⁷      | 0.4 s  | 0.22 s | 0.10 s | 333 KB  |
//! |   1023   | 2¹⁴      | 2³⁰      | 3.1 s  | 1.3 s  | 0.7 s  | 428 KB  |
//!
//! The deployable range extends up to `n*=16,383` (the working field's
//! 2-adicity ceiling) but the cached-initial-Merkle-tree footprint
//! scales as ~`N` Goldilocks elements — at the ceiling this stresses
//! consumer-class memory budgets.
//!
//! ## Construction (one paragraph)
//!
//! The secret is a univariate polynomial `f ∈ F[X]` of degree `D = M − 1` over
//! the quartic Goldilocks extension `F_{q_0^4}` (`|F| ≈ 2^256`), derived
//! deterministically from a 32-byte seed `σ`. The public key is a zk-WHIR
//! commitment to the length-`M` coefficient vector `c = (c_0, …, c_{M−1})`;
//! the Proposition 3.19 encoding randomness is sampled inside `WHIR.Commit`
//! from the same `σ` and never appears in the signer's user-facing API. A
//! signature on a message `M` opens `f` at `K = 16` message-derived positions
//! via a single batched zk-WHIR linear-form proof (Construction 6.3 sumcheck
//! plus Construction 7.2 base case). After `n_cliff = ⌈M/K⌉` signatures the
//! outsider has accumulated ≥ `D + 1` distinct evaluations of `f` and
//! reconstructs the secret by Lagrange interpolation.
//!  
//! For the full construction and security analysis see the Jevil paper. For
//! the per-construction compliance status against the zk-WHIR paper (ePrint
//! 2026/391), see `docs/zkwhir-spec-compliance.md`.
//!
//! ## Modules
//!
//! Most users will only touch the items re-exported from this crate root.
//! Internal modules implement the underlying primitives:
//!
//! - the Goldilocks quartic extension field and the position-to-field map ψ,
//! - the Poseidon2-Goldilocks sponge and SHAKE256 extendable-output function,
//! - a binary Merkle tree and the WHIR Reed–Solomon-proximity-test IOP,
//! - the Jevil-specific lift, transcript, and position-derivation procedures.
//!
//! ## License
//!
//! Licensed under either of Apache License, Version 2.0 or MIT license, at
//! your option.

#![forbid(unsafe_code)]
#![warn(
	missing_docs,
	rustdoc::broken_intra_doc_links,
	rustdoc::private_intra_doc_links
)]

mod alpha;
mod error;
mod field;
mod hash;
mod keygen;
mod lift;
mod merkle;
mod params;
mod positions;
mod sign;
mod transcript;
mod verify;
mod whir;

pub use crate::error::Error;
pub use crate::field::Goldilocks4;
pub use crate::keygen::{SignerCache, keygen};
pub use crate::params::Params;
pub use crate::sign::{Signature, sign};
pub use crate::verify::verify;

/// A Jevil public key. Realizes the `pk = (root, w, n*)` of paper §4.3,
/// Construction 1 (`KeyGen`).
///
/// Layout: 32-byte zk-WHIR commitment root, 32-byte OOD value
/// `w = f(z) ∈ F`, and a 4-byte little-endian `n_star`. The OOD point `z`
/// itself is not transmitted — both signer and verifier re-derive it from
/// `root` via the `JV-OOD` SHAKE256 stream. The signing budget is carried
/// in the public key so that verifiers can derive every subsidiary
/// parameter (`M`, `T`, `ν`, the commit dimension `N`) from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
	/// 32-byte zk-WHIR commitment root over the coefficient vector
	/// `c ∈ F^M`. Bound by the cap-binding theorem (paper Theorem 3):
	/// every accepting opening against this root reveals an evaluation of
	/// a degree-≤`D` polynomial.
	pub root: [u8; 32],
	/// OOD value `w = f(z) ∈ F` where `z` is derived from `root` via
	/// `JV-OOD`. Bound by the cap-binding theorem to be one publicly-known
	/// evaluation pair `(z, f(z))` of the committed polynomial; lets a
	/// single accepting signature pin down `g` within the proximity ball
	/// instead of requiring `⌈M/K⌉` accumulating ones (paper §6.1).
	pub w: Goldilocks4,
	/// Signing budget `n*` chosen at [`keygen`].
	pub n_star: u32,
}

impl PublicKey {
	/// The fixed serialised length of a `PublicKey`: 68 bytes
	/// (32 root + 32 OOD value `w` + 4 `n_star`).
	pub const BYTES: usize = 68;

	/// Serialise as `root ‖ w.to_bytes() ‖ n_star.to_le_bytes()`.
	pub fn to_bytes(&self) -> [u8; Self::BYTES] {
		let mut out = [0u8; Self::BYTES];
		out[..32].copy_from_slice(&self.root);
		out[32..64].copy_from_slice(&self.w.to_bytes());
		out[64..].copy_from_slice(&self.n_star.to_le_bytes());
		out
	}

	/// Parse exactly 68 bytes back into a `PublicKey`. Returns
	/// [`Error::NonCanonicalField`] if the OOD-value chunk is not a
	/// canonical `Goldilocks4` encoding.
	pub fn from_bytes(b: &[u8; Self::BYTES]) -> Result<Self, Error> {
		let mut root = [0u8; 32];
		root.copy_from_slice(&b[..32]);
		let w = Goldilocks4::from_bytes(&b[32..64]).ok_or(Error::NonCanonicalField)?;
		let n_star = u32::from_le_bytes(b[64..].try_into().unwrap());
		Ok(Self { root, w, n_star })
	}
}

/// A Jevil signing secret: a 32-byte seed from which every other signer-side
/// value is deterministically derived (paper §4.3, Construction 1 step 1:
/// `s ← {0,1}^256`).
///
/// The seed expands into the polynomial coefficients `c = (c_0, …, c_{M−1})`
/// via the `JV-SEED` SHAKE256 stream and is also passed to `WHIR.Commit`,
/// which uses the `JV-RZK` stream off the same seed to deterministically
/// derive its internal Prop. 3.19 encoding randomness.
///
/// `SecretKey` deliberately does **not** implement [`std::fmt::Debug`] or
/// [`std::fmt::Display`] to discourage accidental logging. The inner bytes are
/// accessible only through [`SecretKey::to_bytes`] (which clones them) and
/// [`SecretKey::from_bytes`].
///
/// On drop the inner bytes are zeroized via the [`zeroize`] crate (which uses
/// volatile writes internally to defeat compiler dead-store elimination).
#[derive(Clone, Eq, PartialEq, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; Self::BYTES]);

impl SecretKey {
	/// The fixed length of a `SecretKey`: 32 bytes.
	pub const BYTES: usize = 32;

	/// Construct a `SecretKey` from explicit bytes. Most callers should obtain
	/// a `SecretKey` through [`keygen`] instead.
	pub fn from_bytes(b: [u8; Self::BYTES]) -> Self {
		Self(b)
	}

	/// Return a copy of the underlying 32-byte seed.
	pub fn to_bytes(&self) -> [u8; Self::BYTES] {
		self.0
	}

	/// Borrow the seed bytes for use inside the crate.
	pub(crate) fn seed(&self) -> &[u8; Self::BYTES] {
		&self.0
	}
}
