//! Signing — paper §4.3 (Construction 2).

use spongefish::domain_separator;

use crate::field::{Goldilocks4, psi};
use crate::keygen::{SignerCache, build_whir_protocol, derive_ood_point, horner};
use crate::params::Params;
use crate::positions::derive_positions;
use crate::transcript::{derive_betas, prefix_bytes};
use crate::{Error, PublicKey, SecretKey};

/// A Jevil signature.
///
/// Layout: the `K` revealed evaluations `y_1, …, y_K` (32 bytes each)
/// followed by the inline WHIR proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
	/// The revealed `y_t = f(x_t)` values, one per sampled position.
	pub y_values: Vec<Goldilocks4>,
	/// The WHIR linear-form proof. Opaque blob — its layout is an
	/// implementation detail of the WHIR sub-protocol.
	pub whir_proof: Vec<u8>,
}

impl Signature {
	/// Serialise as `y_1.to_bytes() ‖ … ‖ y_K.to_bytes() ‖ whir_proof`.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut out = Vec::with_capacity(self.y_values.len() * 32 + self.whir_proof.len());
		for y in &self.y_values {
			out.extend_from_slice(&y.to_bytes());
		}
		out.extend_from_slice(&self.whir_proof);
		out
	}

	/// Parse exactly `K = Params::K` field elements followed by the WHIR proof.
	///
	/// Returns [`Error::InvalidLength`] if the input is too short, or
	/// [`Error::NonCanonicalField`] if any `y_t` chunk is not a canonical
	/// extension-field element.
	pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
		let k = Params::K as usize;
		let head_len = k * 32;
		if b.len() < head_len {
			return Err(Error::InvalidLength);
		}
		let mut y_values = Vec::with_capacity(k);
		for chunk in b[..head_len].chunks_exact(32) {
			let g = Goldilocks4::from_bytes(chunk).ok_or(Error::NonCanonicalField)?;
			y_values.push(g);
		}
		let whir_proof = b[head_len..].to_vec();
		Ok(Self {
			y_values,
			whir_proof,
		})
	}
}

/// Produce a Jevil signature on `msg` under `(pk, sk)`. Realizes
/// `Jevil.Sign` of the paper (`§4.3, Construction 2`).
///
/// `cache` must be the [`SignerCache`] returned by [`crate::keygen`] (or
/// rebuilt via [`SignerCache::from_secret`]) for this `sk`; passing a cache
/// from a different signer produces undefined output.
///
/// `sk` is consumed to derive the per-signature prover-randomness seed
/// `ρ = H_xof(JV-OPRD, s, root, msg, y_1, …, y_K; 32)` per paper §3.4 /
/// Construction 2 step 7: that seed deterministically drives every
/// internally-sampled value inside `WHIR.Open` (sumcheck masks,
/// code-switching masks, OOD answers), so `Sign` is a pure function of
/// `(sk, pk, msg)`.
pub fn sign(
	sk: &SecretKey,
	pk: &PublicKey,
	cache: &SignerCache,
	params: Params,
	msg: &[u8],
) -> Signature {
	let k = Params::K as usize;
	let t = params.t();
	let m = params.m();

	// 1. Positions and their ψ-images.
	let positions = derive_positions(&pk.root, msg, k, t);
	let xs_msg: Vec<Goldilocks4> = positions.iter().map(|&i| psi(i as u64, t as u64)).collect();

	// 2. y_t = f(x_t) via Horner over the M coefficients in `cache.c`.
	let ys: Vec<Goldilocks4> = xs_msg.iter().map(|&x| horner(&cache.c, x)).collect();

	// 3. Re-derive the OOD point `z` from `pk.root` (Construction 2 step 4 —
	//    identical derivation to KeyGen, so the signer recomputes the same
	//    `z` used there to fix `w`). Append `z` to the position list so the
	//    α-construction loop below produces α = Σ_{t≤K} β_t·u(x_t) +
	//    β_{K+1}·u(z).
	let z = derive_ood_point(&pk.root);
	let mut xs = xs_msg;
	xs.push(z);

	// 4. β challenges — K+1 of them: β_1..β_K for the message positions plus
	//    β_{K+1} for the OOD term (verifier re-derives the same vector from
	//    `(root, msg, ys)`; hash input is unchanged, just one more F-element
	//    is squeezed).
	let betas = derive_betas(&pk.root, msg, &ys);
	debug_assert_eq!(betas.len(), xs.len());

	// 5. Materialise the length-`M` lift α = Σ_t β_t · u(x_t) (plus the
	//    OOD term β_{K+1}·u(z), since `z` is appended to `xs` above) via a
	//    parallel Horner pass over the K+1 positions. α[k] = Σ_t β_t · x_t^k
	//    for k ∈ [0, M).
	let mut alpha = vec![Goldilocks4::ZERO; m];
	let mut x_powers = vec![Goldilocks4::ONE; xs.len()];
	for slot in alpha.iter_mut() {
		let mut sum = Goldilocks4::ZERO;
		for t in 0..xs.len() {
			sum += betas[t] * x_powers[t];
		}
		*slot = sum;
		for t in 0..xs.len() {
			x_powers[t] *= xs[t];
		}
	}

	// 6. Build the Fiat–Shamir transcript with the deterministic prefix
	//    binding (params, root, w, msg, ys) into its instance bytes — then
	//    run WHIR's prover on top.
	let prefix = prefix_bytes(params, &pk.root, &pk.w, msg, &ys);
	let domain = domain_separator!("jevil-v1")
		.without_session()
		.instance(&prefix);
	let mut transcript = domain.std_prover();

	// Derive the per-signature prover-randomness seed ρ from
	// (sk_seed, root, msg, y_1, …, y_K) under the JV-OPRD domain tag
	// (paper §3.4 / Construction 2 step 7). Deterministic but unique
	// per signature; the seed drives every internally-sampled value
	// inside `WHIR.Open` (sumcheck masks via Construction 6.3 of
	// eprint 2026/391, code-switching masks via Construction 9.7,
	// OOD answers via Lemma 9.3).
	let mask_seed = derive_prover_randomness_seed(sk, &pk.root, msg, &ys);

	let whir = build_whir_protocol(params);
	whir.prove(&mut transcript, &cache.whir_state, alpha, &mask_seed);

	Signature {
		y_values: ys,
		whir_proof: transcript.narg_string().to_vec(),
	}
}

/// Derive the per-signature prover-randomness seed `ρ` from
/// `(sk_seed, root, msg, y_1, …, y_K)` per paper §3.4 / Construction 2
/// step 7.
///
/// ## Spec interface vs. implementation chain
///
/// The spec describes `ρ` in two complementary ways:
///
/// - Construction 2 step 7: `ρ ← H_xof(JV-OPRD, s, root, M, y_1, …, y_K; ∞)`
///   — an XOF stream parametrised by all the per-signature inputs.
/// - Definition 5 (`WHIR.Open(st, α, v; ρ) → π`): "a 32-byte randomness
///   seed `ρ`" that drives the prover-internal randomness.
///
/// The two are consistent in the random-oracle model: an XOF stream over
/// `(JV-OPRD, …)` and a 32-byte seed thereof both produce the same per-
/// purpose downstream randomness under further RO-modelled expansion.
/// This function returns the 32-byte seed (Def. 5's interface);
/// downstream consumers — sumcheck round-poly masks, code-switching
/// padding masks, base-case mask companions — re-expand it per purpose
/// via `derive_field_vec(seed, purpose, …)` which calls
/// `H_xof(JV-OPRD, seed, purpose; ∞)`.
///
/// The chain is therefore:
/// `ρ_seed = H_xof(JV-OPRD, s, root, msg, y_1…y_K; 32)`
/// and `r_purpose = H_xof(JV-OPRD, ρ_seed, purpose; ∞)` per purpose.
/// In the RO model this is statistically indistinguishable from squeezing
/// a long stream from the original `H_xof(JV-OPRD, s, root, msg, ys; ∞)`
/// and splitting it deterministically per purpose. Both signer and
/// verifier never call this with the same `(s, root, msg, ys)` twice
/// unless the message and revealed evaluations are byte-identical, so
/// HVZK budget reuse across signatures cannot happen.
///
/// The hash inputs use the same length-prefixed framing as every other
/// `H_xof` call: `JV-OPRD ‖ len_8(s) ‖ s ‖ len_8(root) ‖ root ‖
/// len_8(msg) ‖ msg ‖ len_8(y_1) ‖ y_1 ‖ … ‖ len_8(y_K) ‖ y_K`. The seed
/// `s` MUST remain secret; the rest is public.
///
/// Deterministic — the same `(sk, pk, msg)` produces the same seed —
/// but unique across messages and `y_t` tuples, which is what HVZK
/// requires per signature.
fn derive_prover_randomness_seed(
	sk: &SecretKey,
	root: &[u8; 32],
	msg: &[u8],
	ys: &[Goldilocks4],
) -> [u8; 32] {
	use crate::hash::{JV_OPRD, hash};
	let y_bytes: Vec<[u8; 32]> = ys.iter().map(|y| y.to_bytes()).collect();
	let mut inputs: Vec<&[u8]> = Vec::with_capacity(3 + ys.len());
	inputs.push(sk.seed());
	inputs.push(root);
	inputs.push(msg);
	for yb in &y_bytes {
		inputs.push(yb);
	}
	let h = hash(JV_OPRD, &inputs, 32);
	let mut out = [0u8; 32];
	out.copy_from_slice(&h);
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::keygen::keygen;
	use rand::SeedableRng;
	use rand_chacha::ChaCha20Rng;

	#[test]
	fn signature_has_k_y_values_and_nonempty_proof() {
		let params = Params::new(1);
		let mut rng = ChaCha20Rng::seed_from_u64(0);
		let (pk, sk, cache) = keygen(&mut rng, params);
		let sig = sign(&sk, &pk, &cache, params, b"hello");
		assert_eq!(sig.y_values.len(), Params::K as usize);
		assert!(!sig.whir_proof.is_empty());
	}

	#[test]
	fn signature_serde_round_trip() {
		let params = Params::new(1);
		let mut rng = ChaCha20Rng::seed_from_u64(2);
		let (pk, sk, cache) = keygen(&mut rng, params);
		let sig = sign(&sk, &pk, &cache, params, b"round");
		let bytes = sig.to_bytes();
		let parsed = Signature::from_bytes(&bytes).unwrap();
		assert_eq!(parsed.y_values, sig.y_values);
		assert_eq!(parsed.whir_proof, sig.whir_proof);
	}
}
