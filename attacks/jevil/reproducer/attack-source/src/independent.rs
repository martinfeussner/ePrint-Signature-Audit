//! Independently written helpers for the JEVIL-EXP-002 reproduction.
//!
//! These helpers are deliberately outside the ordinary Jevil API. They expose
//! authenticated initial openings after an otherwise ordinary verification,
//! perform erasure interpolation, and construct an equivalent signer from a
//! recovered complete commitment message.

use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::field::{Goldilocks, Goldilocks4};
use crate::keygen::{SignerCache, build_whir_protocol, derive_ood_point, horner};
use crate::{Error, Params, PublicKey, SecretKey, Signature, sign, verify};

/// One authenticated leaf from the initial width-four commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedOpening {
	/// Position in the length-131,072 outer Reed--Solomon domain.
	pub position: u32,
	/// The four interleaved extension-field symbols at that position.
	pub symbols: [Goldilocks4; 4],
}

enum CaptureState {
	Idle,
	Active(Vec<AuthenticatedOpening>),
}

thread_local! {
	static OPENING_CAPTURE: RefCell<CaptureState> = RefCell::new(CaptureState::Idle);
}

pub(crate) fn record_initial_openings(positions: &[usize], openings: &[Vec<Goldilocks4>]) {
	OPENING_CAPTURE.with(|slot| {
		let mut state = slot.borrow_mut();
		let CaptureState::Active(out) = &mut *state else {
			return;
		};
		// The first code-switch round opens the original commitment. Later
		// rounds open derived commitments and must not enter the attack data.
		if !out.is_empty() {
			return;
		}
		if positions.len() != openings.len() || openings.iter().any(|v| v.len() != 4) {
			return;
		}
		out.reserve(positions.len());
		for (&position, symbols) in positions.iter().zip(openings) {
			out.push(AuthenticatedOpening {
				position: position as u32,
				symbols: symbols.as_slice().try_into().expect("checked width four"),
			});
		}
	});
}

/// Run the unchanged ordinary verifier and return its authenticated initial
/// width-four openings only after full verification and end-of-proof checks.
pub fn verify_and_observe_initial(
	pk: &PublicKey,
	params: Params,
	msg: &[u8],
	sig: &Signature,
) -> Result<Vec<AuthenticatedOpening>, Error> {
	OPENING_CAPTURE.with(|slot| {
		let mut state = slot.borrow_mut();
		if !matches!(&*state, CaptureState::Idle) {
			return Err(Error::VerificationFailed);
		}
		*state = CaptureState::Active(Vec::new());
		Ok(())
	})?;

	let verdict = verify(pk, params, msg, sig);
	let captured = OPENING_CAPTURE.with(|slot| {
		let mut state = slot.borrow_mut();
		match std::mem::replace(&mut *state, CaptureState::Idle) {
			CaptureState::Active(v) => v,
			CaptureState::Idle => Vec::new(),
		}
	});
	verdict?;
	if captured.len() != 64 {
		return Err(Error::VerificationFailed);
	}
	Ok(captured)
}

/// Why recovered rows could not be accepted as equivalent signing state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
	/// A row length did not match one quarter of the internal commitment message.
	WrongRowLength,
	/// Re-committing the recovered state did not reproduce the public root.
	RootMismatch,
	/// The recovered coefficient prefix did not reproduce the public OOD value.
	PublicEvaluationMismatch,
	/// The interpolation input did not meet its structural requirements.
	InvalidInterpolationInput,
	/// Duplicate public openings assigned different values to one position.
	ConflictingOpening,
	/// A selected interpolation denominator was zero.
	ZeroDenominator,
	/// A recovered row did not re-encode to all authenticated openings.
	ReencodeMismatch,
}

impl core::fmt::Display for RecoveryError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{self:?}")
	}
}

impl std::error::Error for RecoveryError {}

/// Equivalent signing state reconstructed from the four initial RS rows.
pub struct RecoveredSigner {
	pk: PublicKey,
	params: Params,
	cache: SignerCache,
	randomness_key: SecretKey,
}

impl RecoveredSigner {
	/// Validate four recovered rows against `pk` and construct signing state.
	/// `randomness_seed` is independent fresh prover randomness; it is not the
	/// target's secret seed and is used only by the ordinary signing algorithm's
	/// mask derivation.
	pub fn from_rows(
		rows: &[Vec<Goldilocks4>; 4],
		pk: &PublicKey,
		params: Params,
		randomness_seed: [u8; 32],
	) -> Result<Self, RecoveryError> {
		let row_len = params.n() / 4;
		if rows.iter().any(|row| row.len() != row_len) {
			return Err(RecoveryError::WrongRowLength);
		}
		let mut internal = Vec::with_capacity(params.n());
		for row in rows {
			internal.extend_from_slice(row);
		}
		let c = internal[..params.m()].to_vec();
		let whir = build_whir_protocol(params);
		let (root, whir_state) = whir.commit_recovered_internal(internal);
		if root != pk.root {
			return Err(RecoveryError::RootMismatch);
		}
		let z = derive_ood_point(&pk.root);
		if horner(&c, z) != pk.w {
			return Err(RecoveryError::PublicEvaluationMismatch);
		}
		Ok(Self {
			pk: pk.clone(),
			params,
			cache: SignerCache { c, whir_state },
			randomness_key: SecretKey::from_bytes(randomness_seed),
		})
	}

	/// Sign a fresh message with the recovered equivalent state through the
	/// ordinary Jevil signing algorithm.
	pub fn sign(&self, msg: &[u8]) -> Signature {
		sign(
			&self.randomness_key,
			&self.pk,
			&self.cache,
			self.params,
			msg,
		)
	}
}

/// Interpolate four degree-below-`dimension` rows from authenticated openings.
///
/// The implementation uses a subproduct tree over exactly `dimension`
/// distinct domain points. From its derivative it derives the complementary
/// erasure locator on the full radix-two domain, reconstructs each row times
/// that locator by inverse transform, and performs fast power-series division.
/// Every recovered row is then re-encoded and compared with every supplied
/// opening, including openings beyond the interpolation subset.
pub fn interpolate_four_rows(
	openings: &BTreeMap<u32, [Goldilocks4; 4]>,
	dimension: usize,
	domain_size: usize,
) -> Result<[Vec<Goldilocks4>; 4], RecoveryError> {
	if dimension == 0
		|| !dimension.is_power_of_two()
		|| !domain_size.is_power_of_two()
		|| domain_size != 4 * dimension
		|| openings.len() < dimension
		|| openings.keys().any(|&p| p as usize >= domain_size)
	{
		return Err(RecoveryError::InvalidInterpolationInput);
	}

	let selected: Vec<(usize, [Goldilocks4; 4])> = openings
		.iter()
		.take(dimension)
		.map(|(&p, &v)| (p as usize, v))
		.collect();
	let omega = Goldilocks4::two_adic_generator(domain_size.trailing_zeros() as usize);
	let points: Vec<Goldilocks4> = selected
		.iter()
		.map(|(position, _)| omega.pow(*position as u64))
		.collect();

	let mut product_level: Vec<Vec<Goldilocks4>> =
		points.iter().map(|&x| vec![-x, Goldilocks4::ONE]).collect();
	while product_level.len() > 1 {
		let mut next = Vec::with_capacity(product_level.len() / 2);
		for pair in product_level.chunks_exact(2) {
			next.push(poly_mul(&pair[0], &pair[1]));
		}
		product_level = next;
	}
	let root_product = product_level.pop().expect("root product");
	if root_product.len() != dimension + 1 {
		return Err(RecoveryError::InvalidInterpolationInput);
	}

	let mut derivative = vec![Goldilocks4::ZERO; dimension];
	for i in 1..root_product.len() {
		derivative[i - 1] = root_product[i] * from_u64(i as u64);
	}
	derivative.resize(domain_size, Goldilocks4::ZERO);
	fft_in_place(&mut derivative, false);

	let mut inverse_denominators = Vec::with_capacity(dimension);
	for (position, _) in &selected {
		let d = derivative[*position];
		if d.is_zero() {
			return Err(RecoveryError::ZeroDenominator);
		}
		inverse_denominators.push(d.inverse());
	}

	// Let A(X) be the product over selected points and Z(X) the product over
	// the complementary domain points. Since X^N - 1 = A(X)Z(X), at a
	// selected root x_i we have Z(x_i) = N*x_i^{-1}/A'(x_i), while Z is zero
	// at every unselected root. One inverse transform therefore recovers Z.
	let n_scalar = from_u64(domain_size as u64);
	let mut locator_values = vec![Goldilocks4::ZERO; domain_size];
	for (index, ((position, _), denominator_inverse)) in
		selected.iter().zip(&inverse_denominators).enumerate()
	{
		locator_values[*position] = n_scalar * points[index].inverse() * *denominator_inverse;
	}
	let mut locator_coefficients = locator_values.clone();
	fft_in_place(&mut locator_coefficients, true);
	let locator_degree = domain_size - dimension;
	if locator_coefficients[locator_degree] != Goldilocks4::ONE
		|| locator_coefficients[locator_degree + 1..]
			.iter()
			.any(|value| !value.is_zero())
	{
		return Err(RecoveryError::InvalidInterpolationInput);
	}

	// Reverse Z around its known degree and invert it modulo X^dimension.
	// For Q=FZ with deg(F)<dimension, the first `dimension` coefficients of
	// rev(Q) determine rev(F) by one truncated series multiplication.
	let locator_reversed: Vec<Goldilocks4> = (0..dimension)
		.map(|i| locator_coefficients[locator_degree - i])
		.collect();
	let locator_inverse = series_inverse(&locator_reversed, dimension)?;

	let mut rows: [Vec<Goldilocks4>; 4] = std::array::from_fn(|_| Vec::new());
	for row_index in 0..4 {
		let mut product_values = vec![Goldilocks4::ZERO; domain_size];
		for (position, values) in &selected {
			product_values[*position] = values[row_index] * locator_values[*position];
		}
		fft_in_place(&mut product_values, true);
		let product_reversed: Vec<Goldilocks4> = (0..dimension)
			.map(|i| product_values[domain_size - 1 - i])
			.collect();
		let mut row_reversed = poly_mul(&product_reversed, &locator_inverse);
		row_reversed.truncate(dimension);
		row_reversed.resize(dimension, Goldilocks4::ZERO);
		row_reversed.reverse();
		rows[row_index] = row_reversed;
	}

	for row_index in 0..4 {
		let mut encoded = rows[row_index].clone();
		encoded.resize(domain_size, Goldilocks4::ZERO);
		fft_in_place(&mut encoded, false);
		for (&position, values) in openings {
			if encoded[position as usize] != values[row_index] {
				return Err(RecoveryError::ReencodeMismatch);
			}
		}
	}
	Ok(rows)
}

fn from_u64(x: u64) -> Goldilocks4 {
	Goldilocks4::new([
		Goldilocks::new(x),
		Goldilocks::new(0),
		Goldilocks::new(0),
		Goldilocks::new(0),
	])
}

fn poly_mul(a: &[Goldilocks4], b: &[Goldilocks4]) -> Vec<Goldilocks4> {
	if a.is_empty() || b.is_empty() {
		return Vec::new();
	}
	let result_len = a.len() + b.len() - 1;
	if a.len().min(b.len()) <= 16 || result_len <= 64 {
		let mut out = vec![Goldilocks4::ZERO; result_len];
		for (i, &x) in a.iter().enumerate() {
			for (j, &y) in b.iter().enumerate() {
				out[i + j] += x * y;
			}
		}
		return out;
	}
	let transform_len = result_len.next_power_of_two();
	let mut left = vec![Goldilocks4::ZERO; transform_len];
	let mut right = vec![Goldilocks4::ZERO; transform_len];
	left[..a.len()].copy_from_slice(a);
	right[..b.len()].copy_from_slice(b);
	fft_in_place(&mut left, false);
	fft_in_place(&mut right, false);
	for (x, y) in left.iter_mut().zip(right) {
		*x *= y;
	}
	fft_in_place(&mut left, true);
	left.truncate(result_len);
	left
}

fn series_inverse(
	series: &[Goldilocks4],
	length: usize,
) -> Result<Vec<Goldilocks4>, RecoveryError> {
	if series.is_empty() || series[0].is_zero() || length == 0 {
		return Err(RecoveryError::InvalidInterpolationInput);
	}
	let mut inverse = vec![series[0].inverse()];
	while inverse.len() < length {
		let next_len = (2 * inverse.len()).min(length);
		let series_prefix = &series[..series.len().min(next_len)];
		let mut product = poly_mul(series_prefix, &inverse);
		product.truncate(next_len);
		product.resize(next_len, Goldilocks4::ZERO);
		product[0] = from_u64(2) - product[0];
		for coefficient in &mut product[1..] {
			*coefficient = -*coefficient;
		}
		inverse = poly_mul(&inverse, &product);
		inverse.truncate(next_len);
	}
	Ok(inverse)
}

fn fft_in_place(values: &mut [Goldilocks4], inverse: bool) {
	let n = values.len();
	assert!(n.is_power_of_two());
	if n <= 1 {
		return;
	}
	let mut j = 0usize;
	for i in 1..n {
		let mut bit = n >> 1;
		while j & bit != 0 {
			j ^= bit;
			bit >>= 1;
		}
		j ^= bit;
		if i < j {
			values.swap(i, j);
		}
	}

	let log_n = n.trailing_zeros() as usize;
	let base = Goldilocks4::two_adic_generator(log_n);
	let mut width = 2usize;
	while width <= n {
		let mut step = base.pow((n / width) as u64);
		if inverse {
			step = step.inverse();
		}
		for block in (0..n).step_by(width) {
			let mut twiddle = Goldilocks4::ONE;
			for offset in 0..width / 2 {
				let lo = values[block + offset];
				let hi = values[block + offset + width / 2] * twiddle;
				values[block + offset] = lo + hi;
				values[block + offset + width / 2] = lo - hi;
				twiddle *= step;
			}
		}
		width <<= 1;
	}
	if inverse {
		let scale = from_u64(n as u64).inverse();
		for value in values {
			*value *= scale;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn subproduct_interpolation_recovers_four_small_rows() {
		let dimension = 8;
		let domain_size = 32;
		let rows: [Vec<Goldilocks4>; 4] = std::array::from_fn(|row| {
			(0..dimension)
				.map(|i| from_u64((100 * row + 3 * i + 1) as u64))
				.collect()
		});
		let encoded: [Vec<Goldilocks4>; 4] = std::array::from_fn(|row| {
			let mut values = rows[row].clone();
			values.resize(domain_size, Goldilocks4::ZERO);
			fft_in_place(&mut values, false);
			values
		});
		let positions = [0usize, 2, 5, 9, 13, 18, 24, 31];
		let mut openings = BTreeMap::new();
		for position in positions {
			openings.insert(
				position as u32,
				std::array::from_fn(|row| encoded[row][position]),
			);
		}
		let recovered = interpolate_four_rows(&openings, dimension, domain_size).unwrap();
		assert_eq!(recovered, rows);
	}
}
