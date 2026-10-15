//! Partial Fisher–Yates position derivation (paper §4.3, Construction 2 step 2).
//!
//! Given `(root, msg)`, derive `K` *distinct* positions in `[0, T)` from the
//! `JV-POSN` SHAKE256 stream. The sampling is unbiased (no modulo bias) and
//! deterministic, identical between signer and verifier.
//!
//! The pool is the *lazy* identity `A[j] = j`: we only materialise the entries
//! the partial Fisher–Yates actually touches, via a `HashMap` overlay holding
//! ≤ `2·K` entries total. This keeps memory O(K) instead of O(T) — relevant at
//! the upper end of the parameter range where `T` reaches `2³⁴` (an eager
//! pool would be ~128 GB).

use std::collections::HashMap;

use shake::XofReader;

use crate::hash::{JV_POSN, shake256_xof};

/// Derive `K` distinct ascending position indices in `[0, T)` from `(root,
/// msg)` via the partial Fisher–Yates procedure of paper §4.3 (Construction 2
/// step 2).
///
/// `b = ⌈log₂(T) / 8⌉` bytes per draw. Unbiased rejection sampling: any raw
/// value `≥ floor(2^(8b) / m) · m` (where `m = pool_size` at that step) is
/// rejected, so `val mod m` is uniform on `[0, m)`. Bytes come from a single
/// continuous SHAKE256 XOF stream (matches the spec's "from H_xof(JV-POSN,
/// root, msg; ∞)" literally).
pub(crate) fn derive_positions(root: &[u8; 32], msg: &[u8], k: usize, t: usize) -> Vec<usize> {
	assert!(k > 0 && k <= t, "k={k} t={t}");
	assert!(t.is_power_of_two(), "t={t} must be a power of two");

	let log_t_bits = t.trailing_zeros() as usize;
	let b = log_t_bits.div_ceil(8);

	let mut reader = shake256_xof(JV_POSN, &[root, msg]);

	// `overlay[j] = v` means `A[j] = v` (others are the identity).
	let mut overlay: HashMap<usize, usize> = HashMap::with_capacity(2 * k);
	let pool_get = |overlay: &HashMap<usize, usize>, j: usize| *overlay.get(&j).unwrap_or(&j);

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

		let j_raw = loop {
			let mut buf = [0u8; 16];
			reader.read(&mut buf[..b]);
			let raw = u128::from_le_bytes(buf) & mask;
			if raw < cutoff {
				break (raw % m as u128) as usize;
			}
		};

		let last = pool_size - 1;
		let picked = pool_get(&overlay, j_raw);
		let last_val = pool_get(&overlay, last);

		indices.push(picked);

		// Swap A[j_raw] ↔ A[last], then shrink the pool. Future iterations
		// can never look up A[last] again, so we only need to keep A[j_raw]'s
		// new value (if it differs from the identity).
		if j_raw < last {
			if last_val == j_raw {
				overlay.remove(&j_raw);
			} else {
				overlay.insert(j_raw, last_val);
			}
		}
		overlay.remove(&last);

		pool_size -= 1;
	}

	indices.sort_unstable();
	indices
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashSet;

	#[test]
	fn k_distinct_in_range_and_sorted() {
		let p = derive_positions(&[0u8; 32], b"hello", 16, 1024);
		assert_eq!(p.len(), 16);
		assert_eq!(p.iter().collect::<HashSet<_>>().len(), 16);
		assert!(p.windows(2).all(|w| w[0] < w[1]));
		assert!(p.iter().all(|&x| x < 1024));
	}

	#[test]
	fn deterministic() {
		let a = derive_positions(&[1u8; 32], b"x", 8, 256);
		let b = derive_positions(&[1u8; 32], b"x", 8, 256);
		assert_eq!(a, b);
	}

	#[test]
	fn varies_with_root() {
		let a = derive_positions(&[1u8; 32], b"x", 8, 256);
		let b = derive_positions(&[2u8; 32], b"x", 8, 256);
		assert_ne!(a, b);
	}

	#[test]
	fn varies_with_msg() {
		let a = derive_positions(&[1u8; 32], b"a", 8, 256);
		let b = derive_positions(&[1u8; 32], b"b", 8, 256);
		assert_ne!(a, b);
	}

	#[test]
	fn k_equals_t_returns_full_permutation() {
		let p = derive_positions(&[0u8; 32], b"perm", 16, 16);
		let mut sorted = p.clone();
		sorted.sort();
		assert_eq!(sorted, (0..16usize).collect::<Vec<_>>());
	}

	#[test]
	fn low_bit_bias_check() {
		let t = 64;
		let mut seen = HashSet::new();
		for i in 0..1000 {
			let p = derive_positions(&[i as u8; 32], b"bias", 1, t);
			seen.insert(p[0]);
		}
		assert!(
			seen.len() >= 50,
			"only {} distinct positions seen",
			seen.len()
		);
	}
}
