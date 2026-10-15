//! The signature pipeline must be deterministic: same seed → same pk → same
//! byte-for-byte signature.

use jevil::{Params, keygen, sign};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn same_seed_same_pk() {
	let params = Params::new(3);
	let mut a = ChaCha20Rng::seed_from_u64(99);
	let mut b = ChaCha20Rng::seed_from_u64(99);
	let (pk_a, _, _) = keygen(&mut a, params);
	let (pk_b, _, _) = keygen(&mut b, params);
	assert_eq!(pk_a.to_bytes(), pk_b.to_bytes());
}

#[test]
fn same_inputs_byte_for_byte_signature() {
	let params = Params::new(3);
	let mut rng = ChaCha20Rng::seed_from_u64(7);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let s1 = sign(&sk, &pk, &cache, params, b"deterministic");
	let s2 = sign(&sk, &pk, &cache, params, b"deterministic");
	assert_eq!(s1.y_values, s2.y_values);
	assert_eq!(s1.whir_proof, s2.whir_proof);
}
