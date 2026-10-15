//! Demonstrates the cliff property: after `n_cliff` signatures an outsider
//! has enough `(x, y)` pairs to recover the secret polynomial `f` via
//! Lagrange interpolation, at which point the secret key becomes publicly
//! recoverable.
//!
//! Run with `cargo run --release --example cliff -- 3` (defaults to
//! `n_star = 3`). Recall that `Params::new` only accepts `n_star ∈ {1, 3, 7,
//! 15, 31, 63, 127, 255, 511, 1023, …}` (i.e. `n_star + 1` a power of two);
//! anything else will panic at construction.
//!
//! This example re-implements the position-derivation procedure inline,
//! mirroring the spec — it does not reach into Jevil's private modules.

use std::collections::HashMap;
use std::env;

use jevil::{Goldilocks4, Params, keygen, sign, verify};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

fn main() {
	let n_star: u32 = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);
	if n_star == 0 || ((n_star + 1) & n_star) != 0 {
		eprintln!(
			"error: n_star + 1 must be a power of two; got n_star = {n_star}.\n\
			 valid values: 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, …"
		);
		std::process::exit(2);
	}

	let params = Params::new(n_star);
	println!("Cliff demo · n* = {n_star}, K = {}", Params::K);
	println!(
		"  M = {}, N = {}, T = {}, n_cliff (worst case) = {}",
		params.m(),
		params.n(),
		params.t(),
		params.n_cliff()
	);

	// Fresh entropy from the OS each run, so the recovered polynomial differs
	// every time you run this demo.
	let mut rng = rand::rng();
	let (pk, sk, cache) = keygen(&mut rng, params);
	println!(
		"Keygen done. Root prefix: {:02x}{:02x}…{:02x}{:02x}",
		pk.root[0], pk.root[1], pk.root[30], pk.root[31]
	);

	let t = params.t();
	let m = params.m();
	let mut pairs: HashMap<[u8; 32], Goldilocks4> = HashMap::new();
	let mut signed = 0usize;
	while pairs.len() < m {
		let msg = format!("msg-{signed}");
		let sig = sign(&sk, &pk, &cache, params, msg.as_bytes());
		verify(&pk, params, msg.as_bytes(), &sig).expect("honest sig verifies");

		let positions = derive_positions(&pk.root, msg.as_bytes(), Params::K as usize, t);
		for (pos, y) in positions.iter().zip(&sig.y_values) {
			let x = psi(*pos as u64, t as u64);
			pairs.insert(x.to_bytes(), *y);
		}
		signed += 1;
		println!(
			"  signed msg {signed:>4}: outsider has {:>5} distinct (x, y) pairs (M = {m})",
			pairs.len()
		);
		if signed > 4 * params.n_cliff() {
			println!("\nAborting after too many signatures.");
			return;
		}
	}

	let pts: Vec<(Goldilocks4, Goldilocks4)> = pairs
		.into_iter()
		.take(m)
		.map(|(xb, y)| (Goldilocks4::from_bytes(&xb).unwrap(), y))
		.collect();
	let recovered = lagrange_interpolate(&pts);

	println!(
		"\nLagrange-interpolated degree-{} polynomial — the signing key is now publicly recoverable.",
		recovered.len() - 1
	);
	println!("(c_0 = {:?})", recovered[0]);
}

// -----------------------------------------------------------------------------
// Spec-side reference implementations (don't reach into Jevil internals).
// -----------------------------------------------------------------------------

// O(n^2) Lagrange interpolation in coefficient form. Build the master
// polynomial P(X) = prod_j (X - x_j) once, then for each i recover
// L_i(X) = P(X) / (X - x_i) by synthetic division (O(n)) and the denominator
// d_i = prod_{j != i}(x_i - x_j) = L_i(x_i) by Horner (O(n)). The naive
// rebuild-from-scratch approach was O(n^3), which dominates the demo at
// large n_star (M = 4096 points at n* = 255).
fn lagrange_interpolate(pairs: &[(Goldilocks4, Goldilocks4)]) -> Vec<Goldilocks4> {
	let n = pairs.len();
	if n == 0 {
		return Vec::new();
	}

	// master[0..=n] holds P(X) = prod_j (X - x_j), low coefficient first.
	let mut master = vec![Goldilocks4::ZERO; n + 1];
	master[0] = Goldilocks4::ONE;
	let mut deg = 0usize;
	for &(x, _) in pairs {
		deg += 1;
		// Multiply in place by (X - x): new[k] = old[k-1] - x*old[k],
		// walking high-to-low so old[k-1] is still intact when read.
		for k in (0..=deg).rev() {
			let lower = if k >= 1 {
				master[k - 1]
			} else {
				Goldilocks4::ZERO
			};
			master[k] = lower - x * master[k];
		}
	}

	let mut coeffs = vec![Goldilocks4::ZERO; n];
	let mut quot = vec![Goldilocks4::ZERO; n]; // reused L_i buffer, degree n-1
	for &(xi, yi) in pairs {
		// Synthetic division of P (degree n) by the monic (X - xi); the
		// remainder is zero since xi is a root, leaving quot = L_i.
		quot[n - 1] = master[n];
		for k in (1..n).rev() {
			quot[k - 1] = master[k] + xi * quot[k];
		}
		// d_i = L_i(xi) = prod_{j != i}(xi - x_j), via Horner on quot.
		let mut den = Goldilocks4::ZERO;
		for k in (0..n).rev() {
			den = den * xi + quot[k];
		}
		let scale = yi * den.try_inverse().expect("distinct points");
		for k in 0..n {
			coeffs[k] += scale * quot[k];
		}
	}
	coeffs
}

// Paper §2.2: 8-byte ASCII strings right-padded with 0x20 (space).
const JV_POSN: [u8; 8] = *b"JV-POSN ";

fn psi(i: u64, t: u64) -> Goldilocks4 {
	assert!(t.is_power_of_two(), "psi: t must be a power of two");
	let log_t = t.trailing_zeros() as usize;
	Goldilocks4::two_adic_generator(log_t).pow(i)
}

fn derive_positions(root: &[u8; 32], msg: &[u8], k: usize, t: usize) -> Vec<usize> {
	let log_t = t.trailing_zeros() as usize;
	let b = log_t.div_ceil(8);
	// Single continuous SHAKE256 XOF stream, matching src/positions.rs and the
	// spec's H_xof(JV-POSN, root, msg; ∞) — no fixed-buffer tag-counter refill.
	let mut hasher = Shake256::default();
	hasher.update(&JV_POSN);
	for input in [root.as_slice(), msg] {
		hasher.update(&(input.len() as u64).to_le_bytes());
		hasher.update(input);
	}
	let mut reader = hasher.finalize_xof();
	let mut pool: Vec<usize> = (0..t).collect();
	let mut indices = Vec::with_capacity(k);
	let mut pool_size = t;
	for _ in 0..k {
		let m = pool_size as u64;
		let cutoff = ((1u128 << (8 * b)) / m as u128) * m as u128;
		let mask: u128 = if 8 * b == 128 {
			u128::MAX
		} else {
			(1u128 << (8 * b)) - 1
		};
		let j = loop {
			let mut buf = [0u8; 16];
			reader.read(&mut buf[..b]);
			let raw = u128::from_le_bytes(buf) & mask;
			if raw < cutoff {
				break (raw % m as u128) as usize;
			}
		};
		indices.push(pool[j]);
		let last = pool_size - 1;
		pool.swap(j, last);
		pool_size -= 1;
	}
	indices.sort_unstable();
	indices
}
