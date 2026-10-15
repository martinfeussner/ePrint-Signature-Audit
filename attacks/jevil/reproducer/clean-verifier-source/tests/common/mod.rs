//! Spec-side reference implementations of the procedures Jevil's integration
//! tests need to drive end-to-end. These re-implement the paper §4.4 / §4.1
//! procedures from scratch using only `shake` and the public `Goldilocks4`
//! type, so a bug in `jevil`'s private hash/positions/keygen code cannot
//! hide itself by silently matching the test's expectations.

#![allow(dead_code)]

use jevil::Goldilocks4;
use shake::{ExtendableOutput, Shake256, Update, XofReader};

// Paper §2.2: 8-byte ASCII strings right-padded with 0x20 (space).
pub const JV_SEED: [u8; 8] = *b"JV-SEED ";
pub const JV_POSN: [u8; 8] = *b"JV-POSN ";

/// SHAKE256 of `tag ‖ len_8(x_1) ‖ x_1 ‖ … ‖ len_8(x_k) ‖ x_k`, squeezed to
/// `out_len` bytes — Jevil's domain-tagged length-prefixed hash framing.
pub fn shake256_tagged(tag: [u8; 8], inputs: &[&[u8]], out_len: usize) -> Vec<u8> {
	let mut hasher = Shake256::default();
	hasher.update(&tag);
	for input in inputs {
		hasher.update(&(input.len() as u64).to_le_bytes());
		hasher.update(input);
	}
	let mut reader = hasher.finalize_xof();
	let mut out = vec![0u8; out_len];
	reader.read(&mut out);
	out
}

/// Spec-side `ψ_T(i) = g_T^i`. `t` must be a power of two with `log₂(t) ≤ 32`.
pub fn psi(i: u64, t: u64) -> Goldilocks4 {
	assert!(t.is_power_of_two());
	let log_t = t.trailing_zeros() as usize;
	Goldilocks4::two_adic_generator(log_t).pow(i)
}

/// Spec-side re-implementation of the partial Fisher–Yates position
/// derivation (paper §4.4). Mirrors the library's `src/positions.rs`: a single
/// continuous SHAKE256 XOF stream over `H_xof(JV-POSN, root, msg; ∞)`, read
/// `b = ⌈log₂(T)/8⌉` bytes per draw with unbiased rejection against the
/// per-step shrinking pool. Re-derived independently of Jevil's private code,
/// so a divergence surfaces as a test failure in `positions.rs` / `cliff.rs`.
pub fn derive_positions(root: &[u8; 32], msg: &[u8], k: usize, t: usize) -> Vec<usize> {
	let log_t = t.trailing_zeros() as usize;
	let b = log_t.div_ceil(8);

	// Single continuous XOF stream over the canonical tag||len8(x)||x framing.
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

/// Spec-side re-derivation of the `M` coefficients `(c_0, …, c_{M−1})` from
/// a 32-byte seed. Same chunk-and-reject parser as `derive_positions`.
pub fn derive_coeffs(sigma: &[u8; 32], m: usize) -> Vec<Goldilocks4> {
	let mut buffer_size = m * 32 * 2 + 32;
	loop {
		let stream = shake256_tagged(JV_SEED, &[sigma], buffer_size);
		let mut out = Vec::with_capacity(m);
		let mut cursor = 0;
		while out.len() < m && cursor + 32 <= stream.len() {
			let chunk = &stream[cursor..cursor + 32];
			cursor += 32;
			if let Some(g) = Goldilocks4::from_bytes(chunk) {
				out.push(g);
			}
		}
		if out.len() == m {
			return out;
		}
		buffer_size *= 2;
	}
}
