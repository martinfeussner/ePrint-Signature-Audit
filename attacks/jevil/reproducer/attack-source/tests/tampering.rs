//! Tampered signatures must always be rejected.

use jevil::{
	Error, Goldilocks4, Params, PublicKey, SecretKey, Signature, SignerCache, keygen, sign, verify,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn setup() -> (PublicKey, SecretKey, SignerCache, Params) {
	let params = Params::new(3);
	let mut rng = ChaCha20Rng::seed_from_u64(42);
	let (pk, sk, cache) = keygen(&mut rng, params);
	(pk, sk, cache, params)
}

#[test]
fn rejects_tampered_y() {
	let (pk, sk, cache, params) = setup();
	let mut sig = sign(&sk, &pk, &cache, params, b"hi");
	sig.y_values[0] += Goldilocks4::ONE;
	assert!(verify(&pk, params, b"hi", &sig).is_err());
}

#[test]
fn rejects_tampered_whir_proof_byte() {
	let (pk, sk, cache, params) = setup();
	let mut sig = sign(&sk, &pk, &cache, params, b"hi");
	let mid = sig.whir_proof.len() / 2;
	sig.whir_proof[mid] ^= 0x80;
	assert!(verify(&pk, params, b"hi", &sig).is_err());
}

#[test]
fn rejects_wrong_root() {
	let (mut pk, sk, cache, params) = setup();
	let sig = sign(&sk, &pk, &cache, params, b"hi");
	pk.root[0] ^= 1;
	assert!(verify(&pk, params, b"hi", &sig).is_err());
}

#[test]
fn rejects_tampered_w() {
	// Flip the public OOD value w = f(z). The verifier folds β_{K+1}·w into the
	// batched target v, so a tampered w yields a v the WHIR proof does not open
	// to — guards the OOD-binding (paper §6.1, Theorem 3) at the integration
	// level (the y-value and root tampers above don't touch w).
	let (mut pk, sk, cache, params) = setup();
	let sig = sign(&sk, &pk, &cache, params, b"hi");
	pk.w += Goldilocks4::ONE;
	assert!(verify(&pk, params, b"hi", &sig).is_err());
}

#[test]
fn rejects_wrong_msg() {
	let (pk, sk, cache, params) = setup();
	let sig = sign(&sk, &pk, &cache, params, b"a");
	assert!(verify(&pk, params, b"b", &sig).is_err());
}

#[test]
fn rejects_wrong_n_star_in_params() {
	let (pk, sk, cache, params) = setup();
	let sig = sign(&sk, &pk, &cache, params, b"hi");
	// `setup` uses n_star = 3; pick the next legal value (7) so both sides
	// satisfy the recommended-regime check enforced by Params::new.
	assert_eq!(params.n_star, 3);
	let wrong = Params::new(7);
	assert_eq!(verify(&pk, wrong, b"hi", &sig), Err(Error::ParamsMismatch));
}

#[test]
fn rejects_short_signature() {
	let bytes = vec![0u8; 5];
	assert_eq!(Signature::from_bytes(&bytes), Err(Error::InvalidLength));
}

#[test]
fn rejects_non_canonical_y() {
	let k = Params::K as usize;
	let mut bytes = vec![0u8; k * 32 + 1];
	// First 8-byte limb = non-canonical Goldilocks value (≥ q₀).
	bytes[..8].copy_from_slice(&u64::MAX.to_le_bytes());
	assert_eq!(Signature::from_bytes(&bytes), Err(Error::NonCanonicalField));
}

/// Regression test: a forged WHIR proof claiming an enormous opening header
/// must be rejected as VerificationFailed *without* triggering an OOM
/// allocation. The verifier should bound-check `n_vals`/`n_sym`/`path_len`
/// against the protocol-known values before allocating.
#[test]
fn rejects_oversized_opening_header() {
	let (pk, sk, cache, params) = setup();
	let mut sig = sign(&sk, &pk, &cache, params, b"dos");
	// The WHIR proof starts with the initial commitment root (32 bytes), then
	// sumcheck round polys, then the first codeswitch round which contains an
	// inline opening. Rather than reverse-engineer the offset, just blanket-
	// overwrite the proof with a header that claims a huge `n_vals` — any
	// offset that lands on a length field will trigger the bound check.
	for byte in sig.whir_proof.iter_mut() {
		*byte = 0xff;
	}
	assert_eq!(
		verify(&pk, params, b"dos", &sig),
		Err(Error::VerificationFailed)
	);
}
