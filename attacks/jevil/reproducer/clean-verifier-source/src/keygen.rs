//! Key generation — paper §4.3 (Construction 1).

use rand::{CryptoRng, Rng};

use crate::field::Goldilocks4;
use crate::hash::{JV_OOD, JV_SEED};
use crate::params::Params;
use crate::whir::{ConcreteWhirProtocol, WhirSignerState};
use crate::{PublicKey, SecretKey};

/// Cached signer state held in memory after [`keygen`] for fast signing.
///
/// The cache stores the coefficient vector `c ∈ F^M` plus an opaque
/// WHIR-side state produced by `WHIR.Commit`. That state holds the
/// Prop. 3.19 encoding randomness, the encoded codeword, and the
/// initial Merkle tree; signing reuses it instead of rebuilding the
/// tree per signature.
///
/// A signer that has lost the cache can rebuild it from the
/// [`SecretKey`] alone via [`SignerCache::from_secret`].
///
/// `c` is *secret* material, so on drop we zeroize the vector contents.
/// The cached codeword is not strictly secret (public-derivable from
/// `pk.root`) but lives on the same heap arenas; zeroized on drop for
/// defense in depth. **Memory cost**: the cached codeword scales linearly
/// with `N` (`N` grows roughly as `n* · θ`).
pub struct SignerCache {
	pub(crate) c: Vec<Goldilocks4>,
	pub(crate) whir_state: WhirSignerState,
}

impl Drop for SignerCache {
	fn drop(&mut self) {
		use zeroize::Zeroize;
		self.c.zeroize();
		self.whir_state.internal.zeroize();
		// The cached initial prover state holds the encoded codeword as
		// its `msg` field. The codeword is not strictly secret (it's
		// public-derivable from the published root) but lives on the same
		// heap arenas as `c`; zeroize for defense in depth.
		if let Some(state) = self.whir_state.initial_state.as_mut() {
			for g in state.msg.iter_mut() {
				g.zeroize();
			}
		}
	}
}

impl SignerCache {
	/// Rebuild the cache from the secret seed and the public-key parameters.
	pub fn from_secret(sk: &SecretKey, params: Params) -> Self {
		let c = derive_coefficient_vector(sk.seed(), params);
		let whir = build_whir_protocol(params);
		let (_root, state) = whir.commit(&c, sk.seed());
		Self {
			c,
			whir_state: state,
		}
	}
}

/// Generate a fresh `(PublicKey, SecretKey, SignerCache)` triple from a CSPRNG.
/// Realizes `Jevil.KeyGen` of the paper (`§4.3, Construction 1`).
///
/// `rng` is consumed only to draw a 32-byte uniform `σ`. The polynomial
/// coefficients `c` are derived from `σ` via `JV-SEED`, and `WHIR.Commit`
/// uses the same `σ` to deterministically derive its internal Prop. 3.19
/// encoding randomness via `JV-RZK`. The same `(rng-state, params)`
/// always produces the same public key.
pub fn keygen<R: Rng + CryptoRng>(
	rng: &mut R,
	params: Params,
) -> (PublicKey, SecretKey, SignerCache) {
	let mut sigma = [0u8; SecretKey::BYTES];
	rng.fill_bytes(&mut sigma);

	let c = derive_coefficient_vector(&sigma, params);
	let whir = build_whir_protocol(params);
	let (root, whir_state) = whir.commit(&c, &sigma);

	// Spec §4.3, Construction 1 steps 4–5: derive the OOD binding point
	// `z` from `root` via `JV-OOD` and publish `w = f(z)` in `pk`.
	let z = derive_ood_point(&root);
	let w = horner(&c, z);

	let pk = PublicKey {
		root,
		w,
		n_star: params.n_star,
	};
	let sk = SecretKey::from_bytes(sigma);
	let cache = SignerCache { c, whir_state };
	(pk, sk, cache)
}

/// Derive the OOD binding point `z ∈ F` from a zk-WHIR commitment root via
/// `JV-OOD` SHAKE256 with per-limb rejection sampling. Identical at
/// `KeyGen` time and at `Verify` time: the verifier never receives `z` on
/// the wire.
pub(crate) fn derive_ood_point(root: &[u8; 32]) -> Goldilocks4 {
	derive_field_elements(root, JV_OOD, 1)[0]
}

/// Horner evaluation of `Σ_k coeffs[k] · x^k`. Shared between `KeyGen`
/// (to compute `w = f(z)`) and `Sign` (to compute `y_t = f(x_t)`).
pub(crate) fn horner(coeffs: &[Goldilocks4], x: Goldilocks4) -> Goldilocks4 {
	let mut acc = Goldilocks4::ZERO;
	for c in coeffs.iter().rev() {
		acc = acc * x + *c;
	}
	acc
}

/// Derive the polynomial coefficient vector `c ∈ F^M` from a 32-byte
/// seed via `JV-SEED`.
pub(crate) fn derive_coefficient_vector(
	sigma: &[u8; SecretKey::BYTES],
	params: Params,
) -> Vec<Goldilocks4> {
	derive_field_elements(sigma, JV_SEED, params.m())
}

pub(crate) fn build_whir_protocol(params: Params) -> ConcreteWhirProtocol {
	let hvzk_budget = params.n() - params.m();
	ConcreteWhirProtocol::build(params.m(), hvzk_budget, 64, 64)
}

/// Pull `count` uniform `Goldilocks4` elements from the `SHAKE256(tag ‖ input)`
/// stream with per-limb rejection sampling. Used with `tag = JV-SEED` to
/// expand the secret seed into coefficients, and with `tag = JV-OOD` to
/// derive the OOD binding point `z` from a commitment root.
fn derive_field_elements(input: &[u8; 32], tag: [u8; 8], count: usize) -> Vec<Goldilocks4> {
	crate::hash::shake_field_elements(tag, &[input], count)
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::SeedableRng;
	use rand_chacha::ChaCha20Rng;

	#[test]
	fn derive_coefficient_vector_is_deterministic() {
		let params = Params::new(1);
		let sigma = [42u8; 32];
		let a = derive_coefficient_vector(&sigma, params);
		let b = derive_coefficient_vector(&sigma, params);
		assert_eq!(a, b);
		assert_eq!(a.len(), params.m());
	}

	#[test]
	fn keygen_is_deterministic_under_seeded_rng() {
		let params = Params::new(1);
		let mut a = ChaCha20Rng::seed_from_u64(0);
		let mut b = ChaCha20Rng::seed_from_u64(0);
		let (pk_a, _, _) = keygen(&mut a, params);
		let (pk_b, _, _) = keygen(&mut b, params);
		assert_eq!(pk_a.root, pk_b.root);
		assert_eq!(pk_a.w, pk_b.w);
		assert_eq!(pk_a.n_star, pk_b.n_star);
	}

	#[test]
	fn w_matches_horner_on_z() {
		let params = Params::new(1);
		let mut rng = ChaCha20Rng::seed_from_u64(11);
		let (pk, _sk, cache) = keygen(&mut rng, params);
		let z = derive_ood_point(&pk.root);
		assert_eq!(pk.w, horner(&cache.c, z));
	}

	#[test]
	fn signer_cache_from_secret_matches_keygen() {
		let params = Params::new(1);
		let mut rng = ChaCha20Rng::seed_from_u64(1);
		let (pk, sk, cache) = keygen(&mut rng, params);
		let cache2 = SignerCache::from_secret(&sk, params);
		assert_eq!(cache.c, cache2.c);
		assert_eq!(cache.whir_state.internal, cache2.whir_state.internal);
		let whir = build_whir_protocol(params);
		let (rebuilt_root, _) = whir.commit(&cache2.c, sk.seed());
		assert_eq!(pk.root, rebuilt_root);
	}
}
