//! Out-of-domain (DEEP-FRI) zero evader.
//!
//! In each WHIR codeswitch round, before issuing in-domain Merkle queries the
//! verifier challenges the prover with `η` random *out-of-domain* points
//! `α_1, …, α_η ∈ F` and asks for the polynomial's evaluations there. This
//! "zero evader" mechanism is the DEEP-FRI sampling-outside-the-box trick,
//! which restores tight soundness for low-rate Reed–Solomon proximity tests.
//!
//! Jevil fixes `η = 2` (spec §3.5, Table 4): two independent OOD seeds are drawn from
//! the transcript each round, and the prover returns two evaluations and two
//! corresponding linear-form constraints.
//!
//! [`OodEvader`] is the prover-side: given a message `m` of length `k`
//! (coefficient form) and the seeds, it returns `(m(α_1), …, m(α_η))` together
//! with the corresponding linear functionals (rows of powers of each `α_i`).
//!
//! [`OodEvaderHandle`] / [`OodLinearFormHandle`] are the verifier-side
//! companions: each handle pretends to hold the explicit
//! `(1, α_i, α_i², …, α_i^{k−1})` row and exposes its multilinear-fold on
//! demand.
//!
//! The Lemma 9.3 privacy-padding step (additive `M[i]·r` term that hides the
//! witness in the OOD answer) is realised at the protocol level in
//! [`super::protocol::ProverCodeswitch::prove`]: a fresh `C_zk`-encoded
//! padding mask oracle is committed per codeswitch round, its first `ETA`
//! message entries serve as `r'`, and the OOD answer is `y_i = ze(α_i)·m +
//! r'[i]`. The mask is pushed onto the [`super::mask_stack::MaskStack`] with
//! `sl_o = (batch_rand[0..ETA], 0, …)`, so the joint base-case check binds
//! the padding contribution. This module therefore needs to know only about
//! the `ze(α_i)·m` half.

use super::linear_form::LinearFormHandle;
use crate::field::Goldilocks4;

/// Fixed number of OOD evader queries per codeswitch round.
///
/// Spec §3.5 (Table 4) specifies `η = 2`; the WHIR soundness analysis (~2⁻¹²⁸ at the
/// reference parameters) depends on this value.
pub(crate) const ETA: usize = 2;

// ---------------------------------------------------------------------------
// Prover-side: OodEvader
// ---------------------------------------------------------------------------

/// DEEP-FRI out-of-domain evader. Each call issues `η` linear-form constraints
/// of the shape `(1, α_i, α_i², …, α_i^{k−1})`, which is the functional
/// `m ↦ m(α_i)`.
pub(crate) struct OodEvader {
	pub(crate) k: usize,
}

impl OodEvader {
	/// Construct an OOD evader for messages of length `k`.
	pub(crate) fn new(k: usize) -> Self {
		Self { k }
	}

	/// `apply(msg, seeds)[i] = msg(seeds[i])`, computed by Horner evaluation.
	pub(crate) fn apply(&self, msg: &[Goldilocks4], seeds: &[Goldilocks4]) -> Vec<Goldilocks4> {
		assert_eq!(msg.len(), self.k);
		seeds
			.iter()
			.map(|seed| {
				let mut acc = Goldilocks4::ZERO;
				for c in msg.iter().rev() {
					acc = acc * *seed + *c;
				}
				acc
			})
			.collect()
	}

	/// `expanded_constraint(seeds)[i]` = the row `(1, seeds[i], seeds[i]², …,
	/// seeds[i]^{k-1})`.
	pub(crate) fn expanded_constraint(&self, seeds: &[Goldilocks4]) -> Vec<Vec<Goldilocks4>> {
		seeds
			.iter()
			.map(|seed| {
				let mut row = Vec::with_capacity(self.k);
				let mut p = Goldilocks4::ONE;
				for _ in 0..self.k {
					row.push(p);
					p *= *seed;
				}
				row
			})
			.collect()
	}
}

// ---------------------------------------------------------------------------
// Verifier-side: OodEvaderHandle / OodLinearFormHandle
// ---------------------------------------------------------------------------

/// Verifier-side handle for the OOD evader's linear functional.
pub(crate) struct OodLinearFormHandle {
	pub(crate) k: usize,
	seed: Goldilocks4,
}

impl OodLinearFormHandle {
	pub(crate) fn new(k: usize, seed: Goldilocks4) -> Self {
		Self { k, seed }
	}
}

impl LinearFormHandle for OodLinearFormHandle {
	type Alphabet = Goldilocks4;

	fn form_size(&self) -> usize {
		self.k
	}

	fn folded_form(&self, rand: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
		assert!(
			self.k.is_power_of_two(),
			"OodLinearFormHandle: k must be a power of two"
		);
		assert!(
			rand.len() <= self.k.ilog2() as usize,
			"OodLinearFormHandle: too many fold challenges"
		);

		// Build (1, α, α², …, α^(k-1)) then half-split-fold.
		let mut values: Vec<Goldilocks4> = {
			let mut v = Vec::with_capacity(self.k);
			let mut p = Goldilocks4::ONE;
			for _ in 0..self.k {
				v.push(p);
				p *= self.seed;
			}
			v
		};
		for &w in rand {
			let half = values.len() / 2;
			values = (0..half)
				.map(|k| values[k] + (values[k + half] - values[k]) * w)
				.collect();
		}
		values
	}
}

/// Verifier-side handle for the DEEP-FRI OOD zero-evader protocol step.
pub(crate) struct OodEvaderHandle {
	pub(crate) k: usize,
}

impl OodEvaderHandle {
	pub(crate) fn new(k: usize) -> Self {
		Self { k }
	}

	/// Materialise the per-output linear-form handles for the given seeds.
	pub(crate) fn zero_evader_handles(&self, seeds: &[Goldilocks4]) -> Vec<OodLinearFormHandle> {
		seeds
			.iter()
			.map(|s| OodLinearFormHandle::new(self.k, *s))
			.collect()
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use crate::field::Goldilocks;

	fn g4(v: u64) -> Goldilocks4 {
		Goldilocks4::new([
			Goldilocks::new(v),
			Goldilocks::new(0),
			Goldilocks::new(0),
			Goldilocks::new(0),
		])
	}

	#[test]
	fn ood_apply_matches_dot_product_with_constraint() {
		let m: Vec<Goldilocks4> = (0..16).map(|i| g4(i as u64)).collect();
		let seeds = [g4(7), g4(11)];
		let evader = OodEvader::new(16);
		let applied = evader.apply(&m, &seeds);
		let constraints = evader.expanded_constraint(&seeds);
		assert_eq!(applied.len(), 2);
		assert_eq!(constraints.len(), 2);
		for (answer, constraint) in applied.iter().zip(constraints.iter()) {
			let dot: Goldilocks4 = m
				.iter()
				.zip(constraint)
				.map(|(a, b)| *a * *b)
				.fold(Goldilocks4::ZERO, |acc, x| acc + x);
			assert_eq!(*answer, dot);
		}
	}

	#[test]
	fn ood_apply_evaluates_polynomial() {
		// f(X) = 1 + 2X + 3X² at X = 5 → 1 + 10 + 75 = 86; at X = 2 → 1 + 4 + 12 = 17.
		let m = vec![g4(1), g4(2), g4(3)];
		let seeds = [g4(5), g4(2)];
		let evader = OodEvader::new(3);
		assert_eq!(evader.apply(&m, &seeds), vec![g4(86), g4(17)]);
	}

	#[test]
	fn handle_no_fold_returns_powers() {
		let alpha = g4(5);
		let h = OodEvaderHandle::new(8);
		let handles = h.zero_evader_handles(&[alpha]);
		let form = handles[0].folded_form(&[]);
		let expected: Vec<Goldilocks4> = (0..8).map(|i| alpha.pow(i as u64)).collect();
		assert_eq!(form, expected);
	}

	#[test]
	fn handle_one_fold_matches_manual() {
		let alpha = g4(3);
		let w = g4(11);
		let h = OodEvaderHandle::new(8);
		let handles = h.zero_evader_handles(&[alpha]);

		let powers: Vec<Goldilocks4> = (0..8).map(|i| alpha.pow(i as u64)).collect();
		let half = 4;
		let manual: Vec<Goldilocks4> = (0..half)
			.map(|k| powers[k] + (powers[k + half] - powers[k]) * w)
			.collect();

		let got = handles[0].folded_form(&[w]);
		assert_eq!(got, manual);
	}

	#[test]
	fn handle_two_seeds_produces_two_handles() {
		let h = OodEvaderHandle::new(8);
		let handles = h.zero_evader_handles(&[g4(3), g4(7)]);
		assert_eq!(handles.len(), 2);
	}
}
