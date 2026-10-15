//! Known-answer test: pins the byte layout of `(pk, signature)` for a fixed
//! `(params, seed, msg)` triple. Catches accidental changes to hash framing,
//! Fiat–Shamir transcript layout, Goldilocks limb order, WHIR proof
//! serialisation, etc.
//!
//! When the protocol bytes are intentionally changed, regenerate fixtures
//! with `KAT_UPDATE=1 cargo test --test kat -- --nocapture`.

use jevil::{Params, keygen, sign};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

#[test]
fn kat_n_star_3() {
	let params = Params::new(3);
	let mut rng = ChaCha20Rng::seed_from_u64(0);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let sig = sign(&sk, &pk, &cache, params, b"jevil-kat-fixture");

	let pk_hex = hex::encode(pk.to_bytes());
	let sig_hash = hex::encode(Sha256::digest(sig.to_bytes()));

	if std::env::var("KAT_UPDATE").is_ok() {
		eprintln!("KAT pk:         {pk_hex}");
		eprintln!("KAT sig SHA256: {sig_hash}");
		return;
	}

	assert_eq!(
		pk_hex,
		"97deebe3cf95f2594e289107e44baad5fe3294fd8d09b1a557cf9eefd524a0d86202dacffe85dc6a610d32bc047a89c3a807b0d2ef1c8d638a449c5704322ae803000000"
	);
	assert_eq!(
		sig_hash,
		"1ae20cc295704b3c9edddab5d56d56fe9baa58a35757e2b0556ad42f88ab06f5"
	);
}
