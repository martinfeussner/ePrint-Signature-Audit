//! Wide correctness sweep for `Goldilocks4::ntt`.
//!
//! Cross-checks the production NTT against direct Horner evaluation across
//! the full deployable `log_n` range (1..=18, covering every jevil
//! deployment from `n* = 1` up through `n* = 16,383`). For small sizes the
//! sweep is exhaustive (every output position checked); for the top end
//! eight random output positions are spot-checked.
//!
//! A second test confirms NTT linearity (`NTT(a + b) = NTT(a) + NTT(b)`),
//! which catches any per-butterfly arithmetic bug independent of the
//! twiddle sequence.

use jevil::Goldilocks4;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Evaluate `f(x) = Σ_k coeffs[k] · x^k` via Horner over the extension.
fn horner(coeffs: &[Goldilocks4], x: Goldilocks4) -> Goldilocks4 {
	let mut acc = Goldilocks4::ZERO;
	for c in coeffs.iter().rev() {
		acc = acc * x + *c;
	}
	acc
}

/// Draw a uniform `Goldilocks4` via per-32-byte rejection sampling on the
/// `from_bytes` canonical check.
fn random_g4(rng: &mut ChaCha20Rng) -> Goldilocks4 {
	loop {
		let mut buf = [0u8; 32];
		rng.fill_bytes(&mut buf);
		if let Some(g) = Goldilocks4::from_bytes(&buf) {
			return g;
		}
	}
}

#[test]
fn ntt_sweep_correctness_via_horner() {
	let mut rng = ChaCha20Rng::seed_from_u64(0xdead_beef);
	for log_n in 1usize..=18 {
		let n = 1usize << log_n;
		let coeffs: Vec<Goldilocks4> = (0..n).map(|_| random_g4(&mut rng)).collect();
		let g = Goldilocks4::two_adic_generator(log_n);
		let actual = Goldilocks4::ntt(coeffs.clone());
		assert_eq!(actual.len(), n);

		if log_n <= 8 {
			// Exhaustive: every output position. n² ≤ 65536 extension ops.
			let mut x = Goldilocks4::ONE;
			for (i, &out_i) in actual.iter().enumerate() {
				let expected = horner(&coeffs, x);
				assert_eq!(out_i, expected, "log_n={log_n} i={i}");
				x *= g;
			}
		} else {
			// Spot-check 8 random output positions. At log_n=18 the
			// exhaustive sweep would be 2^36 base muls.
			let n_u64 = n as u64;
			for _ in 0..8 {
				let i = (rng.next_u64() % n_u64) as usize;
				let x = g.pow(i as u64);
				let expected = horner(&coeffs, x);
				assert_eq!(actual[i], expected, "log_n={log_n} i={i}");
			}
		}
	}
}

#[test]
fn ntt_sweep_linearity() {
	let mut rng = ChaCha20Rng::seed_from_u64(0x1337_c0de);
	for log_n in 1usize..=18 {
		let n = 1usize << log_n;
		let a: Vec<Goldilocks4> = (0..n).map(|_| random_g4(&mut rng)).collect();
		let b: Vec<Goldilocks4> = (0..n).map(|_| random_g4(&mut rng)).collect();
		let ab: Vec<Goldilocks4> = a.iter().zip(&b).map(|(x, y)| *x + *y).collect();

		let na = Goldilocks4::ntt(a);
		let nb = Goldilocks4::ntt(b);
		let nab = Goldilocks4::ntt(ab);
		assert_eq!(na.len(), n);
		assert_eq!(nb.len(), n);
		assert_eq!(nab.len(), n);
		for i in 0..n {
			assert_eq!(na[i] + nb[i], nab[i], "log_n={log_n} i={i}");
		}
	}
}
