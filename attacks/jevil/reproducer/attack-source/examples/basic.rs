//! Minimal Jevil usage example.
//!
//! Run with `cargo run --release --example basic`.

use jevil::{Params, keygen, sign, verify};

fn main() {
	// Params::new requires `n_star + 1` to be a power of two (1, 3, 7, 15, …).
	let params = Params::new(127);
	println!(
		"Jevil parameters · n* = {}, K = {}, M = {}, N = {}, T = {}, n_cliff = {}",
		params.n_star,
		Params::K,
		params.m(),
		params.n(),
		params.t(),
		params.n_cliff(),
	);

	// `rand::rng()` pulls fresh entropy from the operating system every run.
	let mut rng = rand::rng();
	println!("Generating key…");
	let (pk, sk, cache) = keygen(&mut rng, params);
	println!(
		"  pk.root[0..4] = {:02x}{:02x}{:02x}{:02x}",
		pk.root[0], pk.root[1], pk.root[2], pk.root[3]
	);

	let msg = b"firmware-release-v1.0.0";
	println!("Signing message {msg:?}…");
	let sig = sign(&sk, &pk, &cache, params, msg);
	println!(
		"  signature size: {} bytes  ({} y-values + {} WHIR-proof bytes)",
		sig.to_bytes().len(),
		sig.y_values.len() * 32,
		sig.whir_proof.len()
	);

	println!("Verifying…");
	verify(&pk, params, msg, &sig).expect("honest signature must verify");
	println!("  OK.");

	println!("\nTampering check: flipping a byte in the proof…");
	let mut bad = sig.clone();
	let mid = bad.whir_proof.len() / 2;
	bad.whir_proof[mid] ^= 0x80;
	assert!(verify(&pk, params, msg, &bad).is_err());
	println!("  Rejected, as expected.");
}
