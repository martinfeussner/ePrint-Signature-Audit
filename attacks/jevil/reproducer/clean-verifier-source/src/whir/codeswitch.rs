//! Per-round "codeswitch" handles used by the WHIR verifier.
//!
//! Each in-domain query at codeword position `i` reveals the value
//! `codeword[i] = ⟨(1, ωⁱ, ω²ⁱ, …, ω^{(k−1)·i}), msg⟩` (for `ω` the primitive
//! root of unity used by the Reed–Solomon code). The verifier never
//! materialises this length-`k` row; instead it asks for a
//! [`LinearFormHandle`] that knows how to compute its multilinear-fold on
//! demand. The implementations below provide that.
//!
//! The prover side uses [`TransposeCode::apply_transpose`] (on the same
//! Reed–Solomon code) to compute `Mᵀ · selector` via an NTT.

use super::code::{LinearCode, ReedSolomon};
use super::linear_form::LinearFormHandle;
use crate::field::Goldilocks4;

// ---------------------------------------------------------------------------
// Prover-side: TransposeCode
// ---------------------------------------------------------------------------

/// A [`LinearCode`] whose encoding matrix `M` admits efficient transpose
/// application `selector ↦ Mᵀ · selector`.
///
/// For Reed–Solomon, `M[i, j] = ω^{i·j}` and `Mᵀ = M`, so `Mᵀ · selector =
/// NTT(selector)[..msg_len]`.
pub(crate) trait TransposeCode: LinearCode {
	/// Apply the transpose of the encoding matrix to `input`. `input` must
	/// have length `codeword_len`; the output has length `msg_len`.
	fn apply_transpose(&self, input: &[Self::Alphabet]) -> Vec<Self::Alphabet>;
}

impl TransposeCode for ReedSolomon<Goldilocks4> {
	fn apply_transpose(&self, input: &[Goldilocks4]) -> Vec<Goldilocks4> {
		assert_eq!(input.len(), self.codeword_len);
		let ntt_out = Goldilocks4::ntt(input.to_vec());
		ntt_out.into_iter().take(self.msg_len).collect()
	}
}

// ---------------------------------------------------------------------------
// Verifier-side: CodeswitchHandle
// ---------------------------------------------------------------------------

/// Verifier-side hook to produce the linear-form handle for an in-domain
/// codeword query at position `index`.
pub(crate) trait CodeswitchHandle: LinearCode {
	type TransposeHandle: LinearFormHandle<Alphabet = Self::Alphabet>;

	fn apply_transpose_handle(&self, index: usize) -> Self::TransposeHandle;
}

/// Reed–Solomon transpose handle: holds the row
/// `(1, ω^index, ω^{2·index}, …, ω^{(k−1)·index})`.
pub(crate) struct ReedSolomonTransposeHandle {
	coefficients: Vec<Goldilocks4>,
}

impl LinearFormHandle for ReedSolomonTransposeHandle {
	type Alphabet = Goldilocks4;

	fn form_size(&self) -> usize {
		self.coefficients.len()
	}

	fn folded_form(&self, rand: &[Goldilocks4]) -> Vec<Goldilocks4> {
		assert!(
			self.coefficients.len().is_power_of_two(),
			"ReedSolomonTransposeHandle: coefficient length must be a power of two"
		);
		assert!(
			rand.len() <= self.coefficients.len().ilog2() as usize,
			"ReedSolomonTransposeHandle: too many fold challenges"
		);
		let mut values = self.coefficients.clone();
		for &w in rand {
			let half = values.len() / 2;
			values = (0..half)
				.map(|k| values[k] + (values[k + half] - values[k]) * w)
				.collect();
		}
		values
	}
}

impl CodeswitchHandle for ReedSolomon<Goldilocks4> {
	type TransposeHandle = ReedSolomonTransposeHandle;

	fn apply_transpose_handle(&self, index: usize) -> Self::TransposeHandle {
		assert!(
			index < self.codeword_len,
			"ReedSolomon::apply_transpose_handle: index {index} >= codeword_len {}",
			self.codeword_len
		);
		let log_n = self.codeword_len.trailing_zeros() as usize;
		let omega = Goldilocks4::two_adic_generator(log_n);
		let point = omega.pow(index as u64);
		let mut coefficients = Vec::with_capacity(self.msg_len);
		let mut p = Goldilocks4::ONE;
		for _ in 0..self.msg_len {
			coefficients.push(p);
			p *= point;
		}
		ReedSolomonTransposeHandle { coefficients }
	}
}
