//! Fiat–Shamir helpers shared between signer and verifier.
//!
//! These functions derive the per-signature Fiat–Shamir state from a
//! deterministic prefix that binds the public key root, the message, and the
//! revealed y-values into the WHIR transcript. They must produce **identical
//! byte sequences** on signer and verifier; any divergence yields silent
//! incompatibility.

use crate::field::Goldilocks4;
use crate::hash::{JV_FSCH, JV_OPEN, shake_field_elements};
use crate::params::Params;

/// Construct the deterministic prefix bytes injected into the spongefish
/// domain separator's *instance* bytes by both signer and verifier.
///
/// Layout (paper §4.3, "Binding the zk-WHIR transcript" paragraph):
///
/// ```text
/// "JV-OPEN "                (8 bytes, paper §3.4 space-padded tag)
/// params.canonical_bytes()  (4 bytes — n_star LE; K is the global constant)
/// root                      (32 bytes)
/// w.to_bytes()              (32 bytes — OOD value f(z) from pk)
/// (msg.len() as u64).to_le_bytes()  (8 bytes)
/// msg                       (msg.len() bytes)
/// y_1.to_bytes(), …, y_K    (K · 32 bytes)
/// ```
pub(crate) fn prefix_bytes(
	params: Params,
	root: &[u8; 32],
	w: &Goldilocks4,
	msg: &[u8],
	ys: &[Goldilocks4],
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(8 + 4 + 32 + 32 + 8 + msg.len() + ys.len() * 32);
	buf.extend_from_slice(&JV_OPEN);
	buf.extend_from_slice(&params.canonical_bytes());
	buf.extend_from_slice(root);
	buf.extend_from_slice(&w.to_bytes());
	buf.extend_from_slice(&(msg.len() as u64).to_le_bytes());
	buf.extend_from_slice(msg);
	for y in ys {
		buf.extend_from_slice(&y.to_bytes());
	}
	buf
}

/// Derive `K + 1 = ys.len() + 1` Fiat–Shamir batching coefficients
/// `(β_1, …, β_K, β_{K+1})`.
///
/// Uses the `JV-FSCH` SHAKE256 stream with per-limb rejection sampling, so
/// each `β_t` is uniform in `F_{q₀⁴}`. The hashed sequence is exactly the
/// spec §4.3 Construction 2 step 5 layout — `root`, `msg`, then each `y_t` —
/// with the length prefix supplied automatically by [`crate::hash::hash`]'s
/// framing. The trailing `β_{K+1}` weights the OOD constraint `g(z) = w` per
/// Construction 2 step 6 (`α += β_{K+1} · u(z)`, `v += β_{K+1} · w`).
pub(crate) fn derive_betas(root: &[u8; 32], msg: &[u8], ys: &[Goldilocks4]) -> Vec<Goldilocks4> {
	let want = ys.len() + 1;
	let y_bytes: Vec<[u8; 32]> = ys.iter().map(|y| y.to_bytes()).collect();

	let mut inputs: Vec<&[u8]> = Vec::with_capacity(2 + ys.len());
	inputs.push(root);
	inputs.push(msg);
	for yb in &y_bytes {
		inputs.push(yb);
	}

	shake_field_elements(JV_FSCH, &inputs, want)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::field::Goldilocks;

	fn g(n: u64) -> Goldilocks4 {
		Goldilocks4::new([
			Goldilocks::new(n),
			Goldilocks::new(0),
			Goldilocks::new(0),
			Goldilocks::new(0),
		])
	}

	#[test]
	fn betas_count_and_determinism() {
		let ys = vec![g(1), g(2), g(3)];
		let a = derive_betas(&[0u8; 32], b"hello", &ys);
		let b = derive_betas(&[0u8; 32], b"hello", &ys);
		// K + 1 betas: K for the message-derived points, +1 for the OOD term.
		assert_eq!(a.len(), 4);
		assert_eq!(a, b);
	}

	#[test]
	fn betas_vary_with_root() {
		let ys = vec![g(1), g(2)];
		let a = derive_betas(&[0u8; 32], b"x", &ys);
		let b = derive_betas(&[1u8; 32], b"x", &ys);
		assert_ne!(a, b);
	}

	#[test]
	fn betas_vary_with_msg() {
		let ys = vec![g(1), g(2)];
		let a = derive_betas(&[0u8; 32], b"a", &ys);
		let b = derive_betas(&[0u8; 32], b"b", &ys);
		assert_ne!(a, b);
	}

	#[test]
	fn betas_vary_with_ys() {
		let a = derive_betas(&[0u8; 32], b"x", &[g(1), g(2)]);
		let b = derive_betas(&[0u8; 32], b"x", &[g(1), g(3)]);
		assert_ne!(a, b);
	}

	#[test]
	fn prefix_bytes_layout() {
		let params = Params::new(3);
		let root = [7u8; 32];
		let w = g(0xabcd);
		let msg = b"hi";
		let ys = vec![g(0xff), g(0xee)];
		let p = prefix_bytes(params, &root, &w, msg, &ys);
		// 8 + 4 + 32 + 32 + 8 + 2 + 2·32 = 150
		assert_eq!(p.len(), 150);
		assert_eq!(&p[..8], b"JV-OPEN ");
		assert_eq!(&p[8..12], &params.canonical_bytes());
		assert_eq!(&p[12..44], &root);
		assert_eq!(&p[44..76], &w.to_bytes());
		assert_eq!(&p[76..84], &(2u64).to_le_bytes());
		assert_eq!(&p[84..86], msg);
	}
}
