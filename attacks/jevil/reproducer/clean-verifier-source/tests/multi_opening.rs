//! Protocol-level exercises of the multi-opening regime (Lemma 11 of the
//! Jevil paper): one public key opened by up to `n*` signatures. These tests
//! check acceptance, non-malleability, cross-key non-transferability, and
//! determinism — they do NOT assert a zero-knowledge / hiding property (no
//! simulator-indistinguishability is exercised here).
//!
//! - `flagship_round_trip_at_full_budget` — every signature in a full `n*`
//!   budget run verifies, demonstrating that Constructions 6.3, 7.2, 9.7,
//!   and Theorem 4.5 compose into accepting transcripts end-to-end.
//! - `distinct_messages_produce_distinct_proofs` — signatures on different
//!   messages produce byte-distinct WHIR proofs while all verifying against
//!   the same public key.
//! - `distinct_seeds_produce_distinct_signatures` — independently-keyed
//!   signers produce byte-distinct signatures even on the same message.
//! - `cross_verification_rejected` — a signature from `sk_A` does NOT verify
//!   against `pk_B`; cap-binding is not transferable across keys.
//! - `deterministic_signatures_under_full_budget` — repeating the full
//!   (keygen + `n*` signs) run with the same RNG seed yields byte-identical
//!   artifacts; prover randomness is derived from the per-signature seed, not
//!   from the OS RNG.

use jevil::{Params, keygen, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn flagship_round_trip_at_full_budget() {
	let params = Params::new(3);
	let mut rng = ChaCha20Rng::seed_from_u64(0);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let msgs: Vec<Vec<u8>> = (0..params.n_star)
		.map(|i| format!("multi-opening-msg-{i}").into_bytes())
		.collect();
	let sigs: Vec<_> = msgs
		.iter()
		.map(|m| sign(&sk, &pk, &cache, params, m))
		.collect();
	for (m, sig) in msgs.iter().zip(&sigs) {
		verify(&pk, params, m, sig).expect("each of the n* signatures must verify");
	}
}

#[test]
fn distinct_messages_produce_distinct_proofs() {
	let params = Params::new(3);
	let mut rng = ChaCha20Rng::seed_from_u64(0);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let sig_a = sign(&sk, &pk, &cache, params, b"alpha");
	let sig_b = sign(&sk, &pk, &cache, params, b"beta");
	let sig_c = sign(&sk, &pk, &cache, params, b"gamma");
	// All verify.
	for (msg, sig) in [
		(&b"alpha"[..], &sig_a),
		(&b"beta"[..], &sig_b),
		(&b"gamma"[..], &sig_c),
	] {
		verify(&pk, params, msg, sig).unwrap();
	}
	// Pairwise distinct.
	assert_ne!(sig_a.whir_proof, sig_b.whir_proof);
	assert_ne!(sig_a.whir_proof, sig_c.whir_proof);
	assert_ne!(sig_b.whir_proof, sig_c.whir_proof);
}

#[test]
fn distinct_seeds_produce_distinct_signatures() {
	let params = Params::new(3);
	let mut rng_a = ChaCha20Rng::seed_from_u64(0);
	let mut rng_b = ChaCha20Rng::seed_from_u64(1);
	let (pk_a, sk_a, cache_a) = keygen(&mut rng_a, params);
	let (pk_b, sk_b, cache_b) = keygen(&mut rng_b, params);
	let sig_a = sign(&sk_a, &pk_a, &cache_a, params, b"same-message");
	let sig_b = sign(&sk_b, &pk_b, &cache_b, params, b"same-message");
	verify(&pk_a, params, b"same-message", &sig_a).unwrap();
	verify(&pk_b, params, b"same-message", &sig_b).unwrap();
	assert_ne!(sig_a.whir_proof, sig_b.whir_proof);
	assert_ne!(pk_a.root, pk_b.root);
}

#[test]
fn cross_verification_rejected() {
	// A signature from sk_a should NOT verify against pk_b. This guards against
	// any subtle leak where the WHIR proof is "transferable" across roots,
	// which would break the cap-binding theorem.
	let params = Params::new(3);
	let mut rng_a = ChaCha20Rng::seed_from_u64(0);
	let mut rng_b = ChaCha20Rng::seed_from_u64(1);
	let (pk_a, sk_a, cache_a) = keygen(&mut rng_a, params);
	let (pk_b, _sk_b, _cache_b) = keygen(&mut rng_b, params);
	let sig_a = sign(&sk_a, &pk_a, &cache_a, params, b"target");
	verify(&pk_a, params, b"target", &sig_a).expect("sig_a verifies under pk_a");
	verify(&pk_b, params, b"target", &sig_a).expect_err("sig_a must NOT verify under pk_b");
}

#[test]
fn deterministic_signatures_under_full_budget() {
	// Two independent runs of (keygen + n* signs) with the same RNG seed must
	// produce byte-identical artifacts — confirms HVZK randomness is
	// deterministically derived from per-signature mask seeds, not from any
	// fresh OS-RNG calls.
	let params = Params::new(3);
	let (pk_1, sigs_1) = full_budget_run(params, 42);
	let (pk_2, sigs_2) = full_budget_run(params, 42);
	assert_eq!(pk_1.to_bytes(), pk_2.to_bytes());
	assert_eq!(sigs_1.len(), sigs_2.len());
	for (a, b) in sigs_1.iter().zip(&sigs_2) {
		assert_eq!(a.to_bytes(), b.to_bytes());
	}
}

fn full_budget_run(params: Params, seed: u64) -> (jevil::PublicKey, Vec<jevil::Signature>) {
	let mut rng = ChaCha20Rng::seed_from_u64(seed);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let sigs: Vec<_> = (0..params.n_star)
		.map(|i| sign(&sk, &pk, &cache, params, format!("msg-{i}").as_bytes()))
		.collect();
	(pk, sigs)
}
