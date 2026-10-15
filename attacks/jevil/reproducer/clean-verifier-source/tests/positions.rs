//! Integration-level checks on position derivation. Uses spec-side
//! re-implementations in `tests/common/` so any divergence from the paper
//! procedure surfaces as a test failure.

mod common;

use jevil::{Goldilocks4, Params};
use std::collections::HashSet;

#[test]
fn distinct_sorted_over_sweep() {
	let params = Params::new(7);
	let t = params.t();
	for seed in 0u8..32 {
		for msg_id in 0u8..8 {
			let p = common::derive_positions(&[seed; 32], &[msg_id; 8], 16, t);
			assert_eq!(p.len(), 16);
			assert_eq!(p.iter().collect::<HashSet<_>>().len(), 16);
			assert!(p.windows(2).all(|w| w[0] < w[1]));
			assert!(p.iter().all(|&x| x < t));
		}
	}
}

#[test]
fn psi_is_injective_on_t_subgroup() {
	let t = 1024u64;
	let xs: HashSet<[u8; 32]> = (0..t).map(|i| common::psi(i, t).to_bytes()).collect();
	assert_eq!(xs.len(), t as usize);
	assert_eq!(common::psi(0, t), Goldilocks4::ONE);
}
