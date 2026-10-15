//! Linear forms and their verifier-side "handles".
//!
//! A *linear form* is a vector `α ∈ F^M` defining the functional `m ↦ ⟨m, α⟩`.
//! WHIR opens claims of the shape `⟨c, α⟩ = v` against a committed `c`.
//!
//! - On the prover side, [`LinearForm`] is the concrete length-`M` vector.
//! - On the verifier side, we never want to materialise an `M`-vector when
//!   `M` is `2¹⁴` or larger. Instead the verifier uses the
//!   [`LinearFormHandle`] trait: a *symbolic* description of `α` that knows
//!   how to compute its multilinear-extension fold at any sumcheck challenge
//!   point on demand. [`FoldedFormHandle`] and [`LinearCombinationForm`] are
//!   the two combinators the WHIR verifier needs.

use core::ops::{Add, AddAssign, Mul};

use crate::field::SumcheckField;

use super::code::Field;

// ---------------------------------------------------------------------------
// Prover-side: concrete LinearForm
// ---------------------------------------------------------------------------

/// A concrete linear form: the coefficient vector `α` itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinearForm<F>(Vec<F>);

impl<F> LinearForm<F> {
	/// Construct from explicit coefficients.
	pub(crate) fn new(coefficients: Vec<F>) -> Self {
		Self(coefficients)
	}

	/// Borrow the coefficients.
	pub(crate) fn coefficients(&self) -> &[F] {
		&self.0
	}

	/// Take ownership of the coefficients.
	pub(crate) fn into_coefficients(self) -> Vec<F> {
		self.0
	}
}

impl<F: SumcheckField> Add for LinearForm<F> {
	type Output = Self;
	fn add(mut self, rhs: Self) -> Self::Output {
		self += rhs;
		self
	}
}

impl<F: SumcheckField> AddAssign for LinearForm<F> {
	fn add_assign(&mut self, rhs: Self) {
		assert_eq!(self.0.len(), rhs.0.len());
		for (acc, term) in self.0.iter_mut().zip(rhs.0) {
			*acc += term;
		}
	}
}

impl<F: SumcheckField> Mul<F> for LinearForm<F> {
	type Output = Self;
	fn mul(mut self, rhs: F) -> Self::Output {
		for coeff in self.0.iter_mut() {
			*coeff *= rhs;
		}
		self
	}
}

// ---------------------------------------------------------------------------
// Verifier-side: LinearFormHandle trait + impls
// ---------------------------------------------------------------------------

/// Verifier-side handle for a linear form.
///
/// The verifier never materialises the length-`N` α vector. Instead, when
/// WHIR's sumcheck binds a coordinate `s_j` to a challenge `r_j` (MSB-first),
/// the verifier asks the handle for the *folded* MLE
/// `α(r₁, …, r_k, ·, …, ·)` of length `2^(ν' − k)`. The structure of the
/// concrete `α` (a sum of tensor-factorisable monomial lifts) lets us compute
/// this fold in `O(K · ν')` rather than `O(N)`.
pub(crate) trait LinearFormHandle {
	/// Field type of the form's coefficients.
	type Alphabet: Field;

	/// Length of the (unfolded) form. Must be a power of two.
	fn form_size(&self) -> usize;

	/// Apply `rand.len()` MSB-first fold steps and return the resulting
	/// length-`form_size() / 2^rand.len()` vector.
	fn folded_form(&self, rand: &[Self::Alphabet]) -> Vec<Self::Alphabet>;
}

/// A linear-form claim: the form together with its expected dot-product value.
pub(crate) struct LinearConstraint<LFH: LinearFormHandle> {
	pub(crate) linear_form_handle: LFH,
	pub(crate) value: LFH::Alphabet,
}

/// A handle wrapping another handle that has already had some prefix of fold
/// challenges applied, optionally also scaling the output by a constant
/// factor. The scaling is used by the HVZK sumcheck (Construction 6.3) to
/// bake `mask_rlc = ε` into the output linear form: after a `k`-round HVZK
/// sumcheck, the new main linear form is `ε · Fold(main_lf, γ)` rather than
/// just `Fold(main_lf, γ)`.
pub(crate) struct FoldedFormHandle<F> {
	pub(crate) linear_form_handle: Box<dyn LinearFormHandle<Alphabet = F>>,
	pub(crate) rand: Vec<F>,
	/// Multiplicative scaling applied to `folded_form`'s output. `F::ONE`
	/// when there is no scaling (non-HVZK sumcheck) or when the handle was
	/// constructed before HVZK landed.
	pub(crate) scale: F,
}

impl<F: Field> LinearFormHandle for FoldedFormHandle<F> {
	type Alphabet = F;

	fn form_size(&self) -> usize {
		folded_len(self.linear_form_handle.form_size(), self.rand.len())
	}

	fn folded_form(&self, rand: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
		let mut combined = Vec::with_capacity(self.rand.len() + rand.len());
		combined.extend_from_slice(&self.rand);
		combined.extend_from_slice(rand);
		let mut out = self.linear_form_handle.folded_form(&combined);
		if self.scale != F::ONE {
			for x in out.iter_mut() {
				*x *= self.scale;
			}
		}
		out
	}
}

/// A handle for a random linear combination of other handles: `Σ_i rand_i · h_i`.
pub(crate) struct LinearCombinationForm<F> {
	pub(crate) linear_form_handles: Vec<Box<dyn LinearFormHandle<Alphabet = F>>>,
	pub(crate) combination_rand: Vec<F>,
}

impl<F: Field> LinearFormHandle for LinearCombinationForm<F> {
	type Alphabet = F;

	fn form_size(&self) -> usize {
		let Some(first) = self.linear_form_handles.first() else {
			return 0;
		};
		let size = first.form_size();
		assert!(
			self.linear_form_handles
				.iter()
				.all(|h| h.form_size() == size)
		);
		size
	}

	fn folded_form(&self, rand: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
		assert_eq!(self.linear_form_handles.len(), self.combination_rand.len());
		let form_size = self.form_size();
		if form_size == 0 {
			return Vec::new();
		}
		let mut acc = vec![F::ZERO; folded_len(form_size, rand.len())];
		for (handle, &coeff) in self.linear_form_handles.iter().zip(&self.combination_rand) {
			let folded = handle.folded_form(rand);
			assert_eq!(acc.len(), folded.len());
			for (a, t) in acc.iter_mut().zip(folded) {
				*a += t * coeff;
			}
		}
		acc
	}
}

// ---------------------------------------------------------------------------
// Multilinear half-split fold (MSB-first)
// ---------------------------------------------------------------------------

/// One MSB half-split fold step: `v[k] ← v[k] + w · (v[k + half] − v[k])`.
fn fold_step<F>(values: &mut Vec<F>, w: F)
where
	F: Copy + core::ops::Add<Output = F> + core::ops::Sub<Output = F> + core::ops::Mul<Output = F>,
{
	let half = values.len() / 2;
	for k in 0..half {
		let lo = values[k];
		let hi = values[k + half];
		values[k] = lo + w * (hi - lo);
	}
	values.truncate(half);
}

/// Fold `values` via successive MSB half-splits at the given challenges.
pub(crate) fn fold_evaluations<F: Field>(values: Vec<F>, rand: &[F]) -> Vec<F> {
	assert!(values.len().is_power_of_two());
	assert!(rand.len() <= values.len().ilog2() as usize);
	rand.iter().copied().fold(values, |mut values, w| {
		fold_step(&mut values, w);
		values
	})
}

/// `size >> rounds` with assertions guarding the call.
fn folded_len(size: usize, rounds: usize) -> usize {
	if size == 0 {
		return 0;
	}
	assert!(size.is_power_of_two());
	assert!(rounds <= size.ilog2() as usize);
	size >> rounds
}
