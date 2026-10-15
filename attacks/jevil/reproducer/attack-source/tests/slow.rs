//! Slow round-trips at recommended parameter sizes.
//! Run with `cargo test --test slow -- --ignored`.

use jevil::{Params, keygen, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
#[ignore = "slow"]
fn slow_round_trip_n_star_127() {
	let params = Params::new(127);
	let mut rng = ChaCha20Rng::seed_from_u64(0);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let sig = sign(&sk, &pk, &cache, params, b"slow-127");
	verify(&pk, params, b"slow-127", &sig).unwrap();
}

#[test]
#[ignore = "slow"]
fn slow_round_trip_n_star_1023() {
	let params = Params::new(1023);
	let mut rng = ChaCha20Rng::seed_from_u64(0);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let sig = sign(&sk, &pk, &cache, params, b"slow-1023");
	verify(&pk, params, b"slow-1023", &sig).unwrap();
}
