//! Binary Merkle tree used internally by WHIR's vector commitment.
//!
//! This is a private utility — callers pass in pre-hashed leaves and get back
//! a root plus path-extraction / path-verification routines. The internal-node
//! hash uses [`crate::hash::hash_vc_node`] (H_VC^node per paper §3.4).
//!
//! ## Why leaf and internal-node hashes don't collide
//!
//! Both invocations sit under the same `JV-WHIR` IV constituent of H_VC, but
//! the IV's second slot distinguishes the two modes (`0` for leaves, `1` for
//! internal nodes) — see [`crate::hash::hash_vc_leaf`] and
//! [`crate::hash::hash_vc_node`]. Cross-mode collisions are bounded in the
//! random-oracle model by the H_VC capacity.

use rayon::prelude::*;

use crate::hash::hash_vc_node;

/// Minimum element count at which a hashing pass switches from serial to a
/// rayon parallel iterator. Below this, the work is too small to outweigh the
/// split/join overhead — and `sign` performs many tiny mask-oracle commits
/// (`m_zk = 1024` and smaller) where that overhead would otherwise dominate.
pub(crate) const PAR_THRESHOLD: usize = 256;

/// A binary Merkle tree over pre-hashed leaves.
///
/// `layers[0]` is the leaf-hash layer; `layers[k+1]` holds the parents of
/// `layers[k]`. The number of leaves is rounded up to the next power of two by
/// duplicating the last hash (no padding tag is used because the consumer
/// never accepts an opening for a padded index).
#[derive(Clone, Debug)]
pub(crate) struct MerkleTree {
	layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
	/// Build a Merkle tree over the given leaf hashes. Pads up to a power of
	/// two by duplicating the last hash if needed.
	///
	/// Panics if `leaf_hashes` is empty.
	pub(crate) fn build_from_hashes(mut leaf_hashes: Vec<[u8; 32]>) -> Self {
		assert!(
			!leaf_hashes.is_empty(),
			"MerkleTree::build_from_hashes: empty"
		);
		let n = leaf_hashes.len().next_power_of_two();
		while leaf_hashes.len() < n {
			leaf_hashes.push(*leaf_hashes.last().unwrap());
		}
		let mut layers = vec![leaf_hashes];
		while layers.last().unwrap().len() > 1 {
			let prev = layers.last().unwrap();
			// Node hashes within a layer are independent; parallelise wide
			// layers. `par_chunks(2)` is order-preserving, so the tree is
			// bit-for-bit identical to the serial build.
			let next: Vec<[u8; 32]> = if prev.len() >= PAR_THRESHOLD {
				prev.par_chunks(2)
					.map(|pair| hash_vc_node(&pair[0], &pair[1]))
					.collect()
			} else {
				prev.chunks(2)
					.map(|pair| hash_vc_node(&pair[0], &pair[1]))
					.collect()
			};
			layers.push(next);
		}
		Self { layers }
	}

	/// The 32-byte root.
	pub(crate) fn root(&self) -> [u8; 32] {
		self.layers.last().unwrap()[0]
	}

	/// BCS multiproof: emit only "outside" sibling hashes for the union of
	/// authentication paths to `sorted_unique_indices`. `sorted_unique_indices`
	/// MUST be sorted-ascending and deduplicated; the caller is responsible
	/// for that normalization.
	///
	/// At each layer, walks the sorted frontier in order and emits a node's
	/// sibling iff the sibling is not also a queried index at this layer.
	/// Shared ancestors are emitted only once — see paper §3.5 ("Merkle
	/// multiproof encoding").
	pub(crate) fn multiproof(&self, sorted_unique_indices: &[usize]) -> Vec<[u8; 32]> {
		use std::collections::BTreeSet;
		debug_assert!(
			sorted_unique_indices.windows(2).all(|w| w[0] < w[1]),
			"multiproof: indices must be sorted-ascending and deduplicated"
		);
		let mut frontier: BTreeSet<usize> = sorted_unique_indices.iter().copied().collect();
		let mut out = Vec::new();
		for layer in &self.layers[..self.layers.len() - 1] {
			let mut next: BTreeSet<usize> = BTreeSet::new();
			for &i in &frontier {
				let sib = i ^ 1;
				if !frontier.contains(&sib) {
					out.push(layer[sib]);
				}
				next.insert(i >> 1);
			}
			frontier = next;
		}
		out
	}
}

/// Pure function: how many sibling hashes a BCS multiproof for
/// `sorted_unique_indices` in a balanced tree of `depth` levels emits.
/// Both prover and verifier call this to size the transcript I/O for the
/// multiproof bytes — `sample_positions_*` is deterministic, so both
/// sides arrive at identical frontiers and identical counts.
pub(crate) fn multiproof_size(sorted_unique_indices: &[usize], depth: usize) -> usize {
	use std::collections::BTreeSet;
	debug_assert!(
		sorted_unique_indices.windows(2).all(|w| w[0] < w[1]),
		"multiproof_size: indices must be sorted-ascending and deduplicated"
	);
	let mut frontier: BTreeSet<usize> = sorted_unique_indices.iter().copied().collect();
	let mut count = 0usize;
	for _ in 0..depth {
		let mut next: BTreeSet<usize> = BTreeSet::new();
		for &i in &frontier {
			let sib = i ^ 1;
			if !frontier.contains(&sib) {
				count += 1;
			}
			next.insert(i >> 1);
		}
		frontier = next;
	}
	count
}

/// Verify a BCS multiproof: given `root`, the queried `sorted_unique_indices`
/// (matching the prover's normalization), the leaf hashes at those indices,
/// and the pruned proof, reconstruct the tree level-by-level and check that
/// the resulting root matches.
pub(crate) fn verify_multiproof(
	root: [u8; 32],
	num_leaves: usize,
	sorted_unique_indices: &[usize],
	leaf_hashes: &[[u8; 32]],
	proof: &[[u8; 32]],
) -> bool {
	use std::collections::BTreeMap;
	if sorted_unique_indices.len() != leaf_hashes.len() {
		return false;
	}
	if !sorted_unique_indices.windows(2).all(|w| w[0] < w[1]) {
		return false;
	}
	let depth = num_leaves.next_power_of_two().trailing_zeros() as usize;

	let mut nodes: BTreeMap<usize, [u8; 32]> = sorted_unique_indices
		.iter()
		.copied()
		.zip(leaf_hashes.iter().copied())
		.collect();
	let mut proof_iter = proof.iter().copied();

	for _ in 0..depth {
		let mut next: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
		let entries: Vec<(usize, [u8; 32])> = nodes.iter().map(|(&k, &v)| (k, v)).collect();
		let mut skip_next = false;
		for (k, &(i, node_hash)) in entries.iter().enumerate() {
			if skip_next {
				skip_next = false;
				continue;
			}
			let sib = i ^ 1;
			let sib_hash = match entries.get(k + 1) {
				Some(&(next_i, next_hash)) if next_i == sib => {
					skip_next = true;
					next_hash
				}
				_ => match proof_iter.next() {
					Some(h) => h,
					None => return false,
				},
			};
			let (l, r) = if i & 1 == 0 {
				(node_hash, sib_hash)
			} else {
				(sib_hash, node_hash)
			};
			let parent = crate::hash::hash_vc_node(&l, &r);
			next.insert(i >> 1, parent);
		}
		nodes = next;
	}

	if proof_iter.next().is_some() {
		return false; // proof had extra siblings
	}
	nodes.len() == 1 && nodes.values().next().copied() == Some(root)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn fake_hashes(n: usize) -> Vec<[u8; 32]> {
		(0..n)
			.map(|i| {
				let mut x = [0u8; 32];
				x[0] = i as u8;
				x
			})
			.collect()
	}

	/// `n` pairwise-distinct leaf hashes (first two bytes carry `i` as LE u16),
	/// so an intra-layer reordering bug actually changes the root.
	fn distinct_hashes(n: usize) -> Vec<[u8; 32]> {
		(0..n)
			.map(|i| {
				let mut x = [0u8; 32];
				x[0..2].copy_from_slice(&(i as u16).to_le_bytes());
				x
			})
			.collect()
	}

	#[test]
	fn build_root_matches_independent_serial_reference_at_scale() {
		// Equivalence oracle for the tree build: an independent dead-simple
		// serial pair-hash loop must produce the same root as
		// `build_from_hashes`, at a size large enough that a parallel build
		// splits work across threads. Distinct leaves mean any intra-layer
		// reordering changes the root. This guards the parallelization against
		// ordering/scale bugs the (n*=3) end-to-end KAT may not exercise.
		let n = 4096; // power of two → no padding to mirror in the reference
		let leaves = distinct_hashes(n);

		let mut layer = leaves.clone();
		while layer.len() > 1 {
			layer = layer
				.chunks(2)
				.map(|p| hash_vc_node(&p[0], &p[1]))
				.collect();
		}
		let expected_root = layer[0];

		let tree = MerkleTree::build_from_hashes(leaves);
		assert_eq!(tree.root(), expected_root);
	}

	#[test]
	fn pads_to_power_of_two() {
		let hashes = fake_hashes(13);
		let tree = MerkleTree::build_from_hashes(hashes);
		assert_eq!(tree.layers.len(), 5);
	}

	#[test]
	fn multiproof_round_trip() {
		let n = 64;
		let hashes = fake_hashes(n);
		let tree = MerkleTree::build_from_hashes(hashes.clone());
		let root = tree.root();
		// Spot-check pattern: every other index, a contiguous block, scattered.
		let probes: &[&[usize]] = &[
			&[0, 1, 2, 3, 4, 5, 6, 7],
			&[0, 8, 16, 24, 32, 40, 48, 56],
			&[3, 7, 11, 15, 19, 23, 27, 31],
			&[0, 1],
			&[0, 63],
		];
		for indices in probes {
			let mut sorted: Vec<usize> = indices.to_vec();
			sorted.sort_unstable();
			sorted.dedup();
			let proof = tree.multiproof(&sorted);
			let leaf_hashes: Vec<[u8; 32]> = sorted.iter().map(|&i| hashes[i]).collect();
			let expected_size = multiproof_size(&sorted, tree.layers.len() - 1);
			assert_eq!(
				proof.len(),
				expected_size,
				"multiproof size mismatch for {indices:?}"
			);
			assert!(
				verify_multiproof(root, n, &sorted, &leaf_hashes, &proof),
				"multiproof verify failed for {indices:?}"
			);
		}
	}

	#[test]
	fn multiproof_dense_query_set_emits_no_siblings() {
		// All leaves queried → proof must be empty (verifier can rebuild the
		// tree purely from the leaf hashes).
		let n = 64;
		let hashes = fake_hashes(n);
		let tree = MerkleTree::build_from_hashes(hashes.clone());
		let root = tree.root();
		let indices: Vec<usize> = (0..n).collect();
		let proof = tree.multiproof(&indices);
		assert!(
			proof.is_empty(),
			"full-query multiproof should be empty, got {} hashes",
			proof.len()
		);
		assert!(verify_multiproof(root, n, &indices, &hashes, &proof));
	}

	#[test]
	fn multiproof_tampering_rejected() {
		let n = 64;
		let hashes = fake_hashes(n);
		let tree = MerkleTree::build_from_hashes(hashes.clone());
		let root = tree.root();
		let indices: Vec<usize> = vec![3, 17, 42, 50];
		let proof = tree.multiproof(&indices);
		let mut leaf_hashes: Vec<[u8; 32]> = indices.iter().map(|&i| hashes[i]).collect();
		leaf_hashes[0][0] ^= 1; // tamper a leaf
		assert!(!verify_multiproof(root, n, &indices, &leaf_hashes, &proof));
	}

	#[test]
	fn multiproof_savings_match_formula() {
		// At q queries in a tree of depth d, BCS pruning emits approximately
		// q · (d − log₂ q + 1) siblings, vs q · d for the naive concat.
		let n = 1024; // depth = 10
		let hashes = fake_hashes(n);
		let tree = MerkleTree::build_from_hashes(hashes.clone());
		let depth = tree.layers.len() - 1;
		assert_eq!(depth, 10);

		// q = 8: expect ~ 8 · (10 - 3 + 1) = 64 emitted, vs naive 80.
		let mut indices: Vec<usize> = vec![3, 17, 42, 50, 99, 200, 500, 900];
		indices.sort_unstable();
		let proof = tree.multiproof(&indices);
		// Be permissive — concrete count depends on collisions, but it must
		// be strictly less than the naive q · d = 80.
		assert!(
			proof.len() < indices.len() * depth,
			"pruned proof {} must be smaller than naive {}",
			proof.len(),
			indices.len() * depth
		);
	}
}
