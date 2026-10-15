//! Reed–Solomon codes and their interleaved variant.
//!
//! WHIR commits to a length-`N` message via two layers:
//!
//! 1. an inner Reed–Solomon code that encodes a polynomial of degree `< k`
//!    by evaluating it at the `4k`-th roots of unity (rate `1/4`);
//! 2. an interleaving layer that groups `k_int` adjacent symbols into a
//!    single "alphabet" symbol so the vector commitment hashes vectors, not
//!    individual scalars.
//!
//! Both layers are wired through the [`AdditiveCode`] / [`LinearCode`] traits
//! defined in this file.

use core::marker::PhantomData;

use rayon::prelude::*;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use crate::field::Goldilocks4;
use crate::field::SumcheckField;
use crate::merkle::PAR_THRESHOLD;

// ---------------------------------------------------------------------------
// Field trait bundle (encodes the trait bounds WHIR needs on its alphabet)
// ---------------------------------------------------------------------------

/// Marker trait for field types usable as a WHIR-protocol alphabet.
pub(crate) trait Field:
	SumcheckField + Encoding + Decoding + NargSerialize + NargDeserialize
{
}

impl<F> Field for F where F: SumcheckField + Encoding + Decoding + NargSerialize + NargDeserialize {}

// ---------------------------------------------------------------------------
// AdditiveCode / LinearCode traits
// ---------------------------------------------------------------------------

/// An error-correcting code whose encoding map is `F`-linear in the input.
///
/// `InputAlphabet` is the symbol type of the *message*; `OutputAlphabet` is
/// the symbol type of the *codeword*. For a plain Reed–Solomon code these
/// coincide; for [`InterleavedCode`] the codeword symbols are vectors.
pub(crate) trait AdditiveCode {
	/// Symbol type of messages.
	type InputAlphabet: Field;
	/// Symbol type of codewords.
	type OutputAlphabet: Clone + Eq;

	/// Number of message symbols.
	fn msg_len(&self) -> usize;
	/// Number of codeword symbols.
	fn codeword_len(&self) -> usize;
	/// Encode a message into a codeword.
	fn encode(&self, input: &[Self::InputAlphabet]) -> Vec<Self::OutputAlphabet>;
}

/// An [`AdditiveCode`] whose message and codeword symbols share the same
/// alphabet — i.e. a plain linear code.
pub(crate) trait LinearCode:
	AdditiveCode<InputAlphabet = Self::Alphabet, OutputAlphabet = Self::Alphabet>
{
	/// The common alphabet for both messages and codewords.
	type Alphabet: Field;
}

// ---------------------------------------------------------------------------
// ReedSolomon
// ---------------------------------------------------------------------------

/// Reed–Solomon code over `F`, rate `1/4` (codeword length `= 4 · msg_len`).
///
/// This is plain RS encoding `Enc(m) := NTT(m)` of a length-`msg_len` message
/// (zero-padded to the `4 · msg_len` codeword length before the transform).
/// The Prop. 3.19 ZK encoding randomness `r_zk` is **not** applied here: the
/// WHIR commitment layer builds the committed vector as `c ‖ r_zk` (length `N`)
/// upstream and hands the already-padded message to this code, so the
/// `t`-query perfect-ZK property is a property of that length-`N` input, not of
/// this encoder.
pub(crate) struct ReedSolomon<F> {
	/// Length of the message (polynomial degree + 1).
	pub(crate) msg_len: usize,
	/// Length of the codeword (`4 · msg_len`).
	pub(crate) codeword_len: usize,
	_f: PhantomData<F>,
}

impl<F> ReedSolomon<F> {
	/// Rate-1/4 Reed–Solomon code with the given message length. `msg_len`
	/// must be a power of two (required by the NTT).
	pub(crate) fn new(msg_len: usize) -> Self {
		assert!(
			msg_len.is_power_of_two(),
			"ReedSolomon::new: msg_len must be a power of 2, got {msg_len}"
		);
		Self {
			msg_len,
			codeword_len: msg_len * 4,
			_f: PhantomData,
		}
	}
}

impl AdditiveCode for ReedSolomon<Goldilocks4> {
	type InputAlphabet = Goldilocks4;
	type OutputAlphabet = Goldilocks4;

	fn msg_len(&self) -> usize {
		self.msg_len
	}

	fn codeword_len(&self) -> usize {
		self.codeword_len
	}

	fn encode(&self, input: &[Self::InputAlphabet]) -> Vec<Self::OutputAlphabet> {
		assert_eq!(
			input.len(),
			self.msg_len,
			"ReedSolomon::encode: input length mismatch"
		);
		let mut padded = input.to_vec();
		padded.resize(self.codeword_len, Goldilocks4::default());
		Goldilocks4::ntt(padded)
	}
}

impl LinearCode for ReedSolomon<Goldilocks4> {
	type Alphabet = Goldilocks4;
}

// ---------------------------------------------------------------------------
// InterleavedCode
// ---------------------------------------------------------------------------

/// Interleave `interleaving_factor` codewords of an inner code into a single
/// outer code whose codeword symbols are vectors.
///
/// The outer message of length `k_int · k_inner` is split into `k_int`
/// independent messages of length `k_inner`, each encoded under the inner
/// code, and the resulting codewords are transposed: position `i` of the
/// outer codeword is the vector `[c₁[i], c₂[i], …, c_{k_int}[i]]`.
pub(crate) struct InterleavedCode<EC> {
	interleaving_factor: usize,
	inner_code: EC,
}

impl<EC> InterleavedCode<EC> {
	/// Construct an interleaved code from `inner_code` with the given
	/// `interleaving_factor`.
	pub(crate) fn new(inner_code: EC, interleaving_factor: usize) -> Self {
		Self {
			interleaving_factor,
			inner_code,
		}
	}

	/// The number of inner codewords interleaved per outer codeword symbol.
	pub(crate) fn interleaving_factor(&self) -> usize {
		self.interleaving_factor
	}

	/// Borrow the inner code.
	pub(crate) fn inner_code(&self) -> &EC {
		&self.inner_code
	}
}

impl<EC> AdditiveCode for InterleavedCode<EC>
where
	EC: AdditiveCode,
{
	type InputAlphabet = EC::InputAlphabet;
	type OutputAlphabet = Vec<EC::OutputAlphabet>;

	fn msg_len(&self) -> usize {
		self.inner_code.msg_len() * self.interleaving_factor
	}

	fn codeword_len(&self) -> usize {
		self.inner_code.codeword_len()
	}

	fn encode(&self, input: &[Self::InputAlphabet]) -> Vec<Self::OutputAlphabet> {
		assert!(self.interleaving_factor > 0);
		assert!(input.len().is_multiple_of(self.interleaving_factor));
		assert_eq!(input.len(), self.msg_len());

		let chunk_size = input.len() / self.interleaving_factor;
		assert_eq!(chunk_size, self.inner_code.msg_len());

		let codeword_len = self.codeword_len();
		let encoded_chunks: Vec<_> = input
			.chunks_exact(chunk_size)
			.map(|chunk| self.inner_code.encode(chunk))
			.collect();

		(0..codeword_len)
			.map(|i| encoded_chunks.iter().map(|c| c[i].clone()).collect())
			.collect()
	}
}

impl InterleavedCode<ReedSolomon<Goldilocks4>> {
	/// Flat-storage encode: returns a [`CodewordSlab`] with stride =
	/// `interleaving_factor`. Bytes-equivalent to [`AdditiveCode::encode`]
	/// but produces a contiguous `Vec<Goldilocks4>` instead of the
	/// `Vec<Vec<Goldilocks4>>` allocator storm.
	pub(crate) fn encode_slab(&self, input: &[Goldilocks4]) -> CodewordSlab {
		let k_int = self.interleaving_factor;
		assert!(k_int > 0);
		assert_eq!(input.len(), self.msg_len());

		let chunk_size = input.len() / k_int;
		let codeword_len = self.codeword_len();

		// The `k_int` inner codewords are independent NTTs; run them
		// concurrently for the wide (initial / early-round) commits. Output
		// order matches `chunks_exact`, so the interleaving below is unchanged.
		let encoded_chunks: Vec<Vec<Goldilocks4>> = if codeword_len >= PAR_THRESHOLD {
			input
				.par_chunks_exact(chunk_size)
				.map(|chunk| self.inner_code.encode(chunk))
				.collect()
		} else {
			input
				.chunks_exact(chunk_size)
				.map(|chunk| self.inner_code.encode(chunk))
				.collect()
		};

		let mut flat: Vec<Goldilocks4> = Vec::with_capacity(codeword_len * k_int);
		for i in 0..codeword_len {
			for chunk_enc in &encoded_chunks {
				flat.push(chunk_enc[i]);
			}
		}

		CodewordSlab::new(flat, k_int)
	}
}

// ---------------------------------------------------------------------------
// CodewordSlab — flat replacement for `Vec<Vec<Goldilocks4>>`
// ---------------------------------------------------------------------------

/// A flat codeword representation. Each "position" of the (possibly
/// interleaved) codeword is a stride of `width` Goldilocks4 elements in
/// `data`.
///
/// Replaces the prior `Vec<Vec<Goldilocks4>>` representation: that form
/// allocated one small `Vec` per codeword position, generating
/// O(codeword_len) small allocations per `WHIR.Commit`. `CodewordSlab`
/// holds one contiguous buffer instead.
#[derive(Clone, Debug)]
pub(crate) struct CodewordSlab {
	pub(crate) data: Vec<Goldilocks4>,
	pub(crate) width: usize,
}

impl CodewordSlab {
	pub(crate) fn new(data: Vec<Goldilocks4>, width: usize) -> Self {
		assert!(width > 0);
		assert_eq!(
			data.len() % width,
			0,
			"CodewordSlab::new: data.len() ({}) not a multiple of width ({})",
			data.len(),
			width
		);
		Self { data, width }
	}

	pub(crate) fn positions(&self) -> usize {
		self.data.len() / self.width
	}

	pub(crate) fn position(&self, i: usize) -> &[Goldilocks4] {
		&self.data[i * self.width..(i + 1) * self.width]
	}

	pub(crate) fn iter_positions(&self) -> impl Iterator<Item = &[Goldilocks4]> + '_ {
		self.data.chunks_exact(self.width)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use crate::field::Goldilocks;

	fn from_base(g: Goldilocks) -> Goldilocks4 {
		Goldilocks4::new([
			g,
			Goldilocks::new(0),
			Goldilocks::new(0),
			Goldilocks::new(0),
		])
	}

	#[test]
	fn reed_solomon_evaluates_polynomial_at_subgroup() {
		let k = 8;
		let code = ReedSolomon::<Goldilocks4>::new(k);

		// f(X) = 2 + X
		let mut msg = vec![Goldilocks4::default(); k];
		msg[0] = from_base(Goldilocks::new(2));
		msg[1] = from_base(Goldilocks::new(1));

		let codeword = code.encode(&msg);
		assert_eq!(codeword.len(), 32);

		let g = Goldilocks4::two_adic_generator(5);
		for (i, cw_i) in codeword.iter().enumerate() {
			let x = g.pow(i as u64);
			let expected = from_base(Goldilocks::new(2)) + x;
			assert_eq!(*cw_i, expected, "i={i}");
		}
	}

	#[test]
	fn reed_solomon_linearity() {
		let k = 16;
		let code = ReedSolomon::<Goldilocks4>::new(k);

		let m1: Vec<_> = (0..k)
			.map(|i| from_base(Goldilocks::new(i as u64)))
			.collect();
		let m2: Vec<_> = (0..k)
			.map(|i| from_base(Goldilocks::new((i * 3) as u64)))
			.collect();
		let sum: Vec<_> = m1.iter().zip(&m2).map(|(a, b)| *a + *b).collect();

		let c1 = code.encode(&m1);
		let c2 = code.encode(&m2);
		let cs = code.encode(&sum);

		for (i, (a, (b, c))) in cs.iter().zip(c1.iter().zip(c2.iter())).enumerate() {
			assert_eq!(*a, *b + *c, "linearity failed at i={i}");
		}
	}

	#[test]
	fn encode_slab_matches_encode_layout() {
		use crate::field::Goldilocks;
		let inner = ReedSolomon::<Goldilocks4>::new(8);
		let ic = InterleavedCode::new(inner, 4);
		let zero = Goldilocks::new(0);
		let msg: Vec<Goldilocks4> = (0..32u64)
			.map(|n| Goldilocks4::new([Goldilocks::new(n), Goldilocks::new(n + 100), zero, zero]))
			.collect();
		let nested = ic.encode(&msg);
		let slab = ic.encode_slab(&msg);

		assert_eq!(nested.len(), slab.positions());
		for (i, pos) in nested.iter().enumerate() {
			assert_eq!(slab.position(i), pos.as_slice(), "mismatch at position {i}");
		}
	}

	#[test]
	fn codeword_slab_position_iteration() {
		use crate::field::Goldilocks;
		let zero = Goldilocks::new(0);
		let data: Vec<Goldilocks4> = (0..12u64)
			.map(|n| Goldilocks4::new([Goldilocks::new(n), zero, zero, zero]))
			.collect();
		let slab = CodewordSlab::new(data, 3);
		assert_eq!(slab.positions(), 4);
		assert_eq!(slab.position(0).len(), 3);
		assert_eq!(slab.iter_positions().count(), 4);
	}
}
