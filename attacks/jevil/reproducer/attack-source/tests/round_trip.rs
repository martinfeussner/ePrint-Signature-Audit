//! Honest-path round-trip: keygen → sign → verify across a sweep of `n_star`.

use jevil::{Params, PublicKey, Signature, keygen, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn round_trip(n_star: u32) {
	let params = Params::new(n_star);
	let mut rng = ChaCha20Rng::seed_from_u64(n_star as u64 * 1000);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let sig = sign(&sk, &pk, &cache, params, b"round-trip-test");
	verify(&pk, params, b"round-trip-test", &sig).expect("honest signature must verify");
}

#[test]
fn round_trip_n_star_1() {
	round_trip(1);
}

#[test]
fn round_trip_n_star_3() {
	round_trip(3);
}

#[test]
fn round_trip_n_star_7() {
	round_trip(7);
}

#[test]
fn round_trip_n_star_15() {
	round_trip(15);
}

#[test]
fn round_trip_n_star_31() {
	round_trip(31);
}

#[test]
fn multiple_messages_same_key() {
	let params = Params::new(7);
	let mut rng = ChaCha20Rng::seed_from_u64(123);
	let (pk, sk, cache) = keygen(&mut rng, params);
	for i in 0..3 {
		let msg = format!("msg-{i}");
		let sig = sign(&sk, &pk, &cache, params, msg.as_bytes());
		verify(&pk, params, msg.as_bytes(), &sig).unwrap();
	}
}

#[test]
fn serialize_deserialize_pk_sig_round_trip() {
	let params = Params::new(3);
	let mut rng = ChaCha20Rng::seed_from_u64(7);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let sig = sign(&sk, &pk, &cache, params, b"serde");

	let pk_bytes = pk.to_bytes();
	let pk2 = PublicKey::from_bytes(&pk_bytes).expect("canonical pk round-trips");
	assert_eq!(pk, pk2);

	let sig_bytes = sig.to_bytes();
	let sig2 = Signature::from_bytes(&sig_bytes).unwrap();
	verify(&pk2, params, b"serde", &sig2).unwrap();
}
