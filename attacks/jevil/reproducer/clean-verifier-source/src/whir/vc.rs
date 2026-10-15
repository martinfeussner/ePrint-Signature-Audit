//! Vector commitment used inside WHIR.
//!
//! WHIR is parameterised over an abstract [`VectorCommitment`] trait, but
//! Jevil only ever instantiates it with [`MerkleVc`] — a Poseidon2-Goldilocks
//! Merkle tree where each *leaf* is the hash of a `Vec<Goldilocks4>`
//! (corresponding to one position of an interleaved codeword) and each
//! *internal node* is the hash of its two children. See [`crate::merkle`] for
//! the tree primitive itself.

use rayon::prelude::*;
use spongefish::{Encoding, NargDeserialize};

use crate::field::Goldilocks4;
use crate::hash::hash_vc_leaf;
use crate::merkle::{MerkleTree, PAR_THRESHOLD};

/// An opened-position bundle for a vector commitment.
#[derive(spongefish::Encoding, spongefish::NargDeserialize)]
pub(crate) struct Opening<VC: VectorCommitment> {
	/// The opened symbols at the queried positions, in order.
	pub openings: Vec<VC::Alphabet>,
	/// Whatever proof material the underlying VC needs (e.g. Merkle paths).
	pub vc_proof: VC::OpeningProof,
}

/// Abstract interface to a position-binding vector commitment.
///
/// The concrete `commit` entry point is provided by inherent methods on
/// each implementor (e.g. [`MerkleVc::commit_slab`]) since jevil's only
/// codeword shape is a flat [`super::code::CodewordSlab`]. The trait
/// itself just bundles the associated types and the read-side methods
/// shared by the verifier path.
pub(crate) trait VectorCommitment: Sized {
	/// Symbol type of the committed vector.
	type Alphabet: Clone + Encoding;
	/// Commitment digest type.
	type Commitment: Encoding + NargDeserialize + Clone;
	/// Proof type that accompanies an opening.
	type OpeningProof: Encoding;
	/// Prover-side state retained between commit and [`Self::open`].
	type CommitState;

	/// Open the commitment at the given positions, returning the claimed
	/// symbols together with a proof.
	fn open(&self, state: &Self::CommitState, indexes: &[usize]) -> Opening<Self>;

	/// Verify an opening against `commitment` at the given positions.
	fn verify(
		&self,
		commitment: &Self::Commitment,
		indexes: &[usize],
		proof: &Opening<Self>,
	) -> bool;
}

// ---------------------------------------------------------------------------
// MerkleVc
// ---------------------------------------------------------------------------

/// A binary Merkle vector commitment whose alphabet is `Vec<Goldilocks4>`
/// (one position of an interleaved codeword).
///
/// The leaf hash for position `i` is [`crate::hash::hash_vc_leaf`] applied
/// to the position's Goldilocks4 symbols (H_VC^leaf per paper §3.4).
pub(crate) struct MerkleVc {
	/// Number of committed positions.
	pub(crate) n: usize,
}

impl MerkleVc {
	/// Construct an `MerkleVc` for `n` positions.
	pub(crate) fn new(n: usize) -> Self {
		Self { n }
	}
}

impl MerkleVc {
	/// Flat-storage commit: hash each `width`-stride position of `slab` into
	/// a Merkle leaf, build the tree, return `(root, (tree, slab))`. Used
	/// by both the interleaved-codeword path (CodeCommitment::commit) and
	/// the width-1 mask-leaf path.
	pub(crate) fn commit_slab(
		&self,
		slab: super::code::CodewordSlab,
	) -> ([u8; 32], (MerkleTree, super::code::CodewordSlab)) {
		assert_eq!(
			slab.positions(),
			self.n,
			"MerkleVc::commit_slab: positions ({}) != n ({})",
			slab.positions(),
			self.n
		);
		// Leaf hashes are independent; parallelise the wide initial/early-round
		// commits. `par_chunks_exact` is order-preserving, so leaf `i` keeps
		// position `i` and the resulting root is identical to the serial path.
		let leaf_hashes: Vec<[u8; 32]> = if slab.positions() >= PAR_THRESHOLD {
			slab.data
				.par_chunks_exact(slab.width)
				.map(hash_vc_leaf)
				.collect()
		} else {
			slab.iter_positions().map(hash_vc_leaf).collect()
		};
		let tree = MerkleTree::build_from_hashes(leaf_hashes);
		let root = tree.root();
		(root, (tree, slab))
	}
}

impl VectorCommitment for MerkleVc {
	type Alphabet = Vec<Goldilocks4>;
	type Commitment = [u8; 32];
	type OpeningProof = Vec<[u8; 32]>;
	type CommitState = (MerkleTree, super::code::CodewordSlab);

	fn open(&self, state: &Self::CommitState, indexes: &[usize]) -> Opening<Self> {
		let (tree, slab) = state;
		// `openings` are in the caller's index order (matches `indexes[i]`).
		let openings: Vec<Vec<Goldilocks4>> =
			indexes.iter().map(|&i| slab.position(i).to_vec()).collect();
		// `vc_proof` is a single BCS multiproof for the sorted-unique index set.
		let mut sorted_unique: Vec<usize> = indexes.to_vec();
		sorted_unique.sort_unstable();
		sorted_unique.dedup();
		let vc_proof = tree.multiproof(&sorted_unique);
		Opening { openings, vc_proof }
	}

	fn verify(
		&self,
		commitment: &Self::Commitment,
		indexes: &[usize],
		proof: &Opening<Self>,
	) -> bool {
		if proof.openings.len() != indexes.len() {
			return false;
		}
		// Recompute leaf hashes in the input order (matches `indexes[i]`).
		let leaf_hashes_input_order: Vec<[u8; 32]> = proof
			.openings
			.iter()
			.map(|symbols| hash_vc_leaf(symbols))
			.collect();

		// Build the sorted-unique (index, leaf_hash) view. Duplicate indices
		// must agree on the leaf hash.
		let mut sorted_unique: Vec<(usize, [u8; 32])> = Vec::new();
		for (k, &idx) in indexes.iter().enumerate() {
			let leaf_hash = leaf_hashes_input_order[k];
			match sorted_unique.binary_search_by_key(&idx, |&(x, _)| x) {
				Ok(pos) => {
					if sorted_unique[pos].1 != leaf_hash {
						return false;
					}
				}
				Err(pos) => {
					sorted_unique.insert(pos, (idx, leaf_hash));
				}
			}
		}
		let sorted_indices: Vec<usize> = sorted_unique.iter().map(|&(i, _)| i).collect();
		let sorted_leaf_hashes: Vec<[u8; 32]> = sorted_unique.iter().map(|&(_, h)| h).collect();

		crate::merkle::verify_multiproof(
			*commitment,
			self.n,
			&sorted_indices,
			&sorted_leaf_hashes,
			&proof.vc_proof,
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::field::Goldilocks;

	fn dummy_symbols(i: usize, k: usize) -> Vec<Goldilocks4> {
		(0..k)
			.map(|j| {
				Goldilocks4::new([
					Goldilocks::new((i * 100 + j) as u64),
					Goldilocks::new(0),
					Goldilocks::new(0),
					Goldilocks::new(0),
				])
			})
			.collect()
	}

	fn dummy_slab(n: usize, k: usize) -> super::super::code::CodewordSlab {
		let mut data: Vec<Goldilocks4> = Vec::with_capacity(n * k);
		for i in 0..n {
			data.extend(dummy_symbols(i, k));
		}
		super::super::code::CodewordSlab::new(data, k)
	}

	#[test]
	fn round_trip() {
		let n = 64;
		let k = 4;
		let vc = MerkleVc::new(n);
		let (commit, state) = vc.commit_slab(dummy_slab(n, k));
		let indexes = [3, 17, 42, 50];
		let opening = vc.open(&state, &indexes);
		assert!(vc.verify(&commit, &indexes, &opening));
	}

	#[test]
	fn tampering_rejected() {
		let n = 32;
		let k = 4;
		let vc = MerkleVc::new(n);
		let (commit, state) = vc.commit_slab(dummy_slab(n, k));
		let indexes = [10];
		let mut opening = vc.open(&state, &indexes);
		opening.openings[0][0] += Goldilocks4::ONE;
		assert!(!vc.verify(&commit, &indexes, &opening));
	}
}
