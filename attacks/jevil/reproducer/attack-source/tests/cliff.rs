//! Confirms the cliff property: at `n_cliff` signatures the outsider has
//! enough `(x, y)` pairs to recover `f` by Lagrange interpolation and forge.

mod common;

use std::collections::HashMap;

use jevil::{Goldilocks4, Params, SecretKey, keygen, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn lagrange_interpolate(pairs: &[(Goldilocks4, Goldilocks4)]) -> Vec<Goldilocks4> {
	let n = pairs.len();
	let mut coeffs = vec![Goldilocks4::ZERO; n];
	for i in 0..n {
		let mut num = vec![Goldilocks4::ONE];
		let mut den = Goldilocks4::ONE;
		for j in 0..n {
			if i == j {
				continue;
			}
			let mut next = vec![Goldilocks4::ZERO; num.len() + 1];
			for (k, c) in num.iter().enumerate() {
				next[k] -= *c * pairs[j].0;
				next[k + 1] += *c;
			}
			num = next;
			den *= pairs[i].0 - pairs[j].0;
		}
		let den_inv = den.try_inverse().expect("distinct points");
		for (k, c) in num.iter().enumerate() {
			coeffs[k] += pairs[i].1 * *c * den_inv;
		}
	}
	coeffs
}

#[test]
fn cliff_recovers_polynomial_at_n_cliff() {
	let params = Params::new(3);
	let mut rng = ChaCha20Rng::seed_from_u64(0);
	let (pk, sk, cache) = keygen(&mut rng, params);

	// Sign as many messages as needed to gather ≥ M distinct (x, y) pairs.
	let mut pairs: HashMap<[u8; 32], Goldilocks4> = HashMap::new();
	let t = params.t();
	let m = params.m();
	let mut signed = 0usize;
	while pairs.len() < m {
		let msg = format!("msg-{signed}");
		let sig = sign(&sk, &pk, &cache, params, msg.as_bytes());
		verify(&pk, params, msg.as_bytes(), &sig).unwrap();
		let positions = common::derive_positions(&pk.root, msg.as_bytes(), Params::K as usize, t);
		for (pos, y) in positions.iter().zip(&sig.y_values) {
			let x = common::psi(*pos as u64, t as u64);
			pairs.insert(x.to_bytes(), *y);
		}
		signed += 1;
		// n_cliff is the worst case; with hash-derived positions it may take
		// a few extra signatures. Cap at 2× to detect runaway.
		assert!(signed <= 2 * params.n_cliff(), "needed too many signatures");
	}

	let pts: Vec<(Goldilocks4, Goldilocks4)> = pairs
		.into_iter()
		.take(m)
		.map(|(xb, y)| (Goldilocks4::from_bytes(&xb).unwrap(), y))
		.collect();
	let recovered = lagrange_interpolate(&pts);
	let truth = derive_truth(&sk, m);
	assert_eq!(recovered, truth);
}

fn derive_truth(sk: &SecretKey, m: usize) -> Vec<Goldilocks4> {
	common::derive_coeffs(&sk.to_bytes(), m)
}
