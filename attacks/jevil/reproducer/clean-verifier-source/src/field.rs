//! The Goldilocks quartic-extension field `F = F_{q₀^4}` and its operations.
//!
//! Jevil's working field is the degree-4 extension of the Goldilocks prime
//! field `F_{q₀}` with `q₀ = 2⁶⁴ − 2³² + 1`, built as the tower
//!
//! ```text
//! F_{q₀²} = F_{q₀}[X] / (X² − 7),
//! F_{q₀⁴} = F_{q₀²}[Y] / (Y² − X).
//! ```
//!
//! An element of `F` is stored as four base-field coefficients `[c₀, c₁, c₂,
//! c₃]` representing `c₀ + c₁·X + c₂·Y + c₃·X·Y`. `|F| = q₀⁴ ≈ 2²⁵⁶`, which is
//! what gives Jevil its ≥ 128-bit *quantum* security against generic search
//! over `y_t` values (`√|F| = 2¹²⁸`).
//!
//! ## What this module provides
//!
//! - [`Goldilocks4`]: the quartic-extension element type, with field
//!   arithmetic, exponentiation, multiplicative inverse, byte serialisation,
//!   2-adic generators, and a radix-2 NTT.
//! - [`Goldilocks`] (re-exported from Plonky3): the base prime field.
//! - [`psi`]: the position-to-field map `ψ_T(i) = g_T^i` used to convert
//!   sampled positions into evaluation points.
//! - Adapter implementations of [`spongefish::Encoding`],
//!   [`spongefish::Decoding`], [`spongefish::NargDeserialize`], and the local
//!   [`SumcheckField`] trait so that `Goldilocks4` plugs directly into the
//!   WHIR and sumcheck machinery.

use core::fmt::Debug;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::sync::OnceLock;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
pub use p3_goldilocks::Goldilocks;
use spongefish::{
	ByteArray, Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult,
};

mod ntt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Goldilocks prime: `q₀ = 2⁶⁴ − 2³² + 1`.
const Q0: u64 = 0xFFFF_FFFF_0000_0001;

/// Inner-extension constant: `X² = W` in `F_{q₀²}`. The paper picks `W = 7`,
/// which matches Plonky3's `BinomialExtensionField<Goldilocks, 2>`.
const W: u64 = 7;

/// `−1 ≡ q₀ − 1 (mod q₀)`, used as a multiply-by-(−1) constant.
const GL_NEG_ONE: u64 = 0xFFFF_FFFF_0000_0000;

// ---------------------------------------------------------------------------
// Goldilocks4
// ---------------------------------------------------------------------------

/// Quartic extension field element `F_{q₀⁴}` represented as four base-field
/// coefficients in the basis `{1, X, Y, XY}` with `X² = 7` and `Y² = X`.
///
/// All arithmetic operators are the standard ones (`+`, `-`, `*`, `+=`, `-=`,
/// `*=`); see [`Goldilocks4::inverse`] for multiplicative inversion.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Goldilocks4 {
	/// Coefficient vector `[c₀, c₁, c₂, c₃]` for `c₀ + c₁·X + c₂·Y + c₃·X·Y`.
	pub c: [Goldilocks; 4],
}

impl Goldilocks4 {
	/// Construct from explicit base-field coefficients.
	#[inline]
	pub const fn new(c: [Goldilocks; 4]) -> Self {
		Self { c }
	}

	/// Additive identity `0`.
	pub const ZERO: Self = Self {
		c: [Goldilocks::new(0); 4],
	};

	/// Multiplicative identity `1`.
	pub const ONE: Self = Self {
		c: [
			Goldilocks::new(1),
			Goldilocks::new(0),
			Goldilocks::new(0),
			Goldilocks::new(0),
		],
	};

	/// `true` if `self == 0`.
	#[inline]
	pub fn is_zero(&self) -> bool {
		self.c.iter().all(|x| x.is_zero())
	}

	/// Multiplicative inverse. Panics on zero — use
	/// [`Goldilocks4::try_inverse`] for the fallible variant.
	#[inline]
	pub fn inverse(self) -> Self {
		self.try_inverse()
			.expect("tried to invert zero in Goldilocks4")
	}

	/// Multiplicative inverse via tower inversion. Returns `None` on zero.
	///
	/// Write `α = P + Q·Y` with `P, Q ∈ F_{q₀²}`. The norm of `α` over
	/// `F_{q₀²}` is `N = P² − X·Q²`, and `α⁻¹ = (P − Q·Y) · N⁻¹`. Inverting
	/// `N` in `F_{q₀²}` uses the same trick one level down.
	pub fn try_inverse(self) -> Option<Self> {
		if self.is_zero() {
			return None;
		}

		let [c0, c1, c2, c3] = self.c;
		let w = Goldilocks::new(W);

		// P² in F_{q₀²}: (c0 + c1·X)² = c0² + W·c1² + 2·c0·c1·X.
		let p0_sq = c0.square() + w * c1.square();
		let p1_sq = Goldilocks::new(2) * c0 * c1;

		// Q² in F_{q₀²}: (c2 + c3·X)² = c2² + W·c3² + 2·c2·c3·X.
		let q0_sq = c2.square() + w * c3.square();
		let q1_sq = Goldilocks::new(2) * c2 * c3;

		// X · Q² in F_{q₀²}: [a₀, a₁] * X = [W·a₁, a₀].
		let xq0_sq = w * q1_sq;
		let xq1_sq = q0_sq;

		// N = P² − X·Q² ∈ F_{q₀²}.
		let n0 = p0_sq - xq0_sq;
		let n1 = p1_sq - xq1_sq;

		// Invert N in F_{q₀²} via its norm to F_{q₀}.
		let norm = n0.square() - w * n1.square();
		let norm_inv = norm.try_inverse()?;
		let n0_inv = n0 * norm_inv;
		let n1_inv = Goldilocks::new(GL_NEG_ONE) * n1 * norm_inv;

		// α⁻¹ = conj(α) · N⁻¹ where conj(α) = c0 + c1·X − c2·Y − c3·X·Y.
		let neg_c2 = -c2;
		let neg_c3 = -c3;

		let r0 = c0 * n0_inv + w * c1 * n1_inv;
		let r1 = c0 * n1_inv + c1 * n0_inv;
		let r2 = neg_c2 * n0_inv + w * neg_c3 * n1_inv;
		let r3 = neg_c3 * n0_inv + neg_c2 * n1_inv;

		Some(Self::new([r0, r1, r2, r3]))
	}

	/// Standard square-and-multiply exponentiation. Returns `self^exp`.
	#[inline]
	pub fn pow(self, mut exp: u64) -> Self {
		if exp == 0 {
			return Self::ONE;
		}
		let mut result = Self::ONE;
		let mut base = self;
		while exp > 0 {
			if exp & 1 == 1 {
				result *= base;
			}
			base *= base;
			exp >>= 1;
		}
		result
	}

	/// Serialise to 32 bytes: each of the four base-field limbs in canonical
	/// 8-byte little-endian form.
	pub fn to_bytes(self) -> [u8; 32] {
		let mut out = [0u8; 32];
		for i in 0..4 {
			out[i * 8..(i + 1) * 8].copy_from_slice(&self.c[i].as_canonical_u64().to_le_bytes());
		}
		out
	}

	/// Deserialise from exactly 32 bytes. Returns `None` if any 8-byte limb is
	/// `≥ q₀` (i.e. not a canonical Goldilocks value).
	pub fn from_bytes(b: &[u8]) -> Option<Self> {
		if b.len() != 32 {
			return None;
		}
		let mut c = [Goldilocks::new(0); 4];
		for i in 0..4 {
			let v = u64::from_le_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
			if v >= Q0 {
				return None;
			}
			c[i] = Goldilocks::new(v);
		}
		Some(Self { c })
	}

	/// A primitive `2^log_n`-th root of unity in `F_{q₀⁴}`.
	///
	/// For `log_n ≤ 32`, returns the Goldilocks base-field generator lifted
	/// into the constant subfield of the extension. For `log_n ∈ {33, 34}`,
	/// derives the extension-level generator from a precomputed
	/// `omega_34 ∈ F_{q₀⁴}` of order exactly `2³⁴` (the full 2-adicity of
	/// `F_{q₀⁴}^×`) by squaring `(34 − log_n)` times. The `omega_34` constant
	/// itself is computed once on first use via Tonelli–Shanks in the base
	/// field and a tower square root, then cached.
	pub fn two_adic_generator(log_n: usize) -> Self {
		assert!(
			log_n <= 34,
			"two_adic_generator: log_n = {log_n} > 34 exceeds the 2-adicity \
             of F_{{q₀⁴}}^× (which is 34)."
		);
		if log_n <= 32 {
			let g_base = Goldilocks::two_adic_generator(log_n);
			return Self::new([
				g_base,
				Goldilocks::new(0),
				Goldilocks::new(0),
				Goldilocks::new(0),
			]);
		}
		// log_n ∈ {33, 34}: derive from omega_34 by repeated squaring.
		let mut g = *omega_34();
		for _ in log_n..34 {
			g = g * g;
		}
		g
	}

	/// Iterative in-place radix-2 DIT Cooley–Tukey NTT.
	///
	/// On entry `coeffs` holds polynomial coefficients of length `n` (a power
	/// of two). On return, `coeffs[i]` holds the evaluation at `g^i` where
	/// `g = two_adic_generator(log₂ n)`. Complexity is `O(n log n)`
	/// extension-field multiplications.
	pub fn ntt(mut coeffs: Vec<Goldilocks4>) -> Vec<Goldilocks4> {
		ntt::ntt_in_place(&mut coeffs);
		coeffs
	}
}

// ---------------------------------------------------------------------------
// Arithmetic operator impls
// ---------------------------------------------------------------------------

impl Neg for Goldilocks4 {
	type Output = Self;
	#[inline]
	fn neg(self) -> Self {
		Self::new(self.c.map(|x| -x))
	}
}

impl Add for Goldilocks4 {
	type Output = Self;
	#[inline]
	fn add(self, rhs: Self) -> Self {
		Self::new(core::array::from_fn(|i| self.c[i] + rhs.c[i]))
	}
}

impl AddAssign for Goldilocks4 {
	#[inline]
	fn add_assign(&mut self, rhs: Self) {
		*self = *self + rhs;
	}
}

impl Sub for Goldilocks4 {
	type Output = Self;
	#[inline]
	fn sub(self, rhs: Self) -> Self {
		Self::new(core::array::from_fn(|i| self.c[i] - rhs.c[i]))
	}
}

impl SubAssign for Goldilocks4 {
	#[inline]
	fn sub_assign(&mut self, rhs: Self) {
		*self = *self - rhs;
	}
}

impl Mul for Goldilocks4 {
	type Output = Self;
	/// Multiply two `F_{q₀⁴}` elements via the basis `{1, X, Y, XY}` with
	/// `X² = W = 7` and `Y² = X`. Derived from the product table:
	///
	/// ```text
	/// X·X = W,    Y·Y = X,     Y·XY = W,
	/// XY·X = W·Y,  XY·XY = W·X.
	/// ```
	#[inline]
	fn mul(self, rhs: Self) -> Self {
		let [a0, a1, a2, a3] = self.c;
		let [b0, b1, b2, b3] = rhs.c;
		let w = Goldilocks::new(W);

		let r0 = a0 * b0 + w * a1 * b1 + w * a2 * b3 + w * a3 * b2;
		let r1 = a0 * b1 + a1 * b0 + a2 * b2 + w * a3 * b3;
		let r2 = a0 * b2 + w * a1 * b3 + a2 * b0 + w * a3 * b1;
		let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;

		Self::new([r0, r1, r2, r3])
	}
}

impl MulAssign for Goldilocks4 {
	#[inline]
	fn mul_assign(&mut self, rhs: Self) {
		*self = *self * rhs;
	}
}

impl Sum for Goldilocks4 {
	fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.fold(Goldilocks4::ZERO, |acc, x| acc + x)
	}
}

// ---------------------------------------------------------------------------
// Zeroize
// ---------------------------------------------------------------------------

impl zeroize::Zeroize for Goldilocks4 {
	/// Overwrite this element with the additive identity. The crate forbids
	/// `unsafe`, so this delegates to the per-limb writes via `Goldilocks::ZERO`;
	/// the compiler is *theoretically* free to elide the writes, but in
	/// practice does not because `Drop` runs at the end of the value's lifetime.
	/// Callers that need stronger guarantees should hold their secrets in
	/// `Zeroizing<Vec<u8>>` (which the `zeroize` crate implements via volatile
	/// stores) and convert on demand.
	fn zeroize(&mut self) {
		for limb in &mut self.c {
			*limb = Goldilocks::ZERO;
		}
	}
}

// ---------------------------------------------------------------------------
// spongefish adapters (Fiat–Shamir transcript serialisation)
// ---------------------------------------------------------------------------

impl Encoding<[u8]> for Goldilocks4 {
	fn encode(&self) -> impl AsRef<[u8]> {
		self.to_bytes()
	}
}

impl Decoding<[u8]> for Goldilocks4 {
	type Repr = ByteArray<64>;

	/// Squeeze 64 bytes from the Fiat–Shamir sponge per `F_{q₀⁴}` challenge:
	/// 16 bytes per base-field limb, interpreted as a little-endian `u128`
	/// and reduced mod `q₀`. The exact total-variation distance from uniform
	/// on `[0, q₀)` is `(q₀ − r)·r / (q₀·2¹²⁸)` with `r = 2¹²⁸ mod q₀`, i.e.
	/// `≈ 2⁻⁹⁶` per limb (`≈ 2⁻⁹⁴` per `F`-element); the loose `q₀/2¹²⁸ ≈ 2⁻⁶⁴`
	/// bound holds too. Either way far below the soundness target.
	///
	/// **Why 64 bytes, not 32 with `raw < q₀ ? raw : raw - q₀`?** The shorter
	/// path is a single-subtraction modular reduction on a 64-bit raw input,
	/// which biases values in `[0, 2⁶⁴ - q₀) = [0, 2³² - 1)` by a factor of
	/// 2 over the rest of the field — TV distance `≈ 2⁻³²` per limb. That
	/// margin is fine for honest random oracle outputs but the spec wants
	/// uniform-on-F challenges, and a malicious grinder could in principle
	/// amplify the bias. Doubling the per-element sponge squeeze removes
	/// the bias entirely (down to the negligible `≈ 2⁻⁹⁶`-per-limb residue from
	/// 128→64-bit reduction). Costs at most a few KB of sponge work per
	/// signature; verifies the same on both sides because both squeeze 64.
	fn decode(buf: Self::Repr) -> Self {
		let bytes: &[u8; 64] = buf.as_ref();
		let q0_u128 = Q0 as u128;
		let mut c = [Goldilocks::new(0); 4];
		for i in 0..4 {
			let raw = u128::from_le_bytes(bytes[i * 16..(i + 1) * 16].try_into().unwrap());
			let val = (raw % q0_u128) as u64;
			c[i] = Goldilocks::new(val);
		}
		Goldilocks4::new(c)
	}
}

impl NargDeserialize for Goldilocks4 {
	fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
		if buf.len() < 32 {
			return Err(VerificationError);
		}
		let (head, tail) = buf.split_at(32);
		let mut c = [Goldilocks::new(0); 4];
		for i in 0..4 {
			let v = u64::from_le_bytes(head[i * 8..(i + 1) * 8].try_into().unwrap());
			if v >= Q0 {
				return Err(VerificationError);
			}
			c[i] = Goldilocks::new(v);
		}
		*buf = tail;
		Ok(Goldilocks4::new(c))
	}
}

// ---------------------------------------------------------------------------
// SumcheckField
// ---------------------------------------------------------------------------

/// Minimum field interface required by the WHIR sumcheck machinery.
///
/// This is the small arithmetic surface the generic code in [`crate::whir`]
/// is written against: the two distinguished constants, a multiplicative
/// inverse, and additive doubling, on top of the standard operator traits.
pub trait SumcheckField:
	Sized
	+ Copy
	+ Send
	+ Sync
	+ PartialEq
	+ Debug
	+ Add<Output = Self>
	+ Sub<Output = Self>
	+ Mul<Output = Self>
	+ Neg<Output = Self>
	+ AddAssign
	+ SubAssign
	+ MulAssign
	+ Sum
	+ 'static
{
	/// Additive identity.
	const ZERO: Self;

	/// Multiplicative identity.
	const ONE: Self;

	/// Multiplicative inverse, or `None` for zero.
	fn inverse(&self) -> Option<Self>;

	/// Double this element (additive).
	#[inline]
	fn double(&self) -> Self {
		*self + *self
	}
}

impl SumcheckField for Goldilocks4 {
	const ZERO: Self = Goldilocks4::ZERO;
	const ONE: Self = Goldilocks4::ONE;

	#[inline]
	fn inverse(&self) -> Option<Self> {
		self.try_inverse()
	}
}

// ---------------------------------------------------------------------------
// Extension-level 2-adic generators (log_n = 33, 34)
// ---------------------------------------------------------------------------

/// `omega_34 ∈ F_{q₀⁴}` of multiplicative order exactly `2³⁴` — the full
/// 2-adicity of the extension. Cached after first computation.
///
/// Derivation. Plonky3 hardcodes `omega_33 = b·X ∈ F_{q₀²}` of order `2³³`
/// with `b = 15_659_105_665_374_529_263 ∈ F_{q₀}` (so `b² · 7 = g_32`, the
/// base-field `2³²`-th root of unity). In the tower `F_{q₀⁴} =
/// F_{q₀²}[Y]/(Y² − X)` we want `ω₃₄ ∈ F_{q₀⁴}` with `ω₃₄² = ω₃₃`. Setting
/// `ω₃₄ = c · Y` in the basis `{1, X, Y, XY}` gives `(c·Y)² = c²·X`; matching
/// against `ω₃₃ = b·X` forces `c² = b`. Whichever of `{b, b/7}` is a square
/// in `F_{q₀}` yields `ω₃₄` (either `c·Y` or `d·XY` with `d² = b/7`); the
/// other isn't. Either way the resulting `ω₃₄` has order `2³⁴` because
/// `ω₃₄² = ω₃₃` and `ord(ω₃₃) = 2³³` (in the cyclic 2-Sylow subgroup,
/// squaring halves the order exactly).
fn omega_34() -> &'static Goldilocks4 {
	static CELL: OnceLock<Goldilocks4> = OnceLock::new();
	CELL.get_or_init(|| {
		// Plonky3's hardcoded omega_33 coefficient: omega_33 = b * X in F_{q₀²}.
		let b = Goldilocks::new(15_659_105_665_374_529_263);
		let zero = Goldilocks::new(0);

		// Try omega_34 = (0, 0, c, 0) with c² = b ⇒ omega_34² = c²·Y² = b·X.
		if let Some(c) = goldilocks_sqrt(b) {
			let candidate = Goldilocks4::new([zero, zero, c, zero]);
			debug_assert_eq!(
				candidate * candidate,
				Goldilocks4::new([zero, b, zero, zero]),
				"omega_34² ≠ omega_33 (case Y)"
			);
			return candidate;
		}
		// Otherwise omega_34 = (0, 0, 0, d) with d² = b/7
		//   ⇒ omega_34² = d²·(XY)² = (b/7)·7·X = b·X.
		let seven_inv = Goldilocks::new(7).inverse();
		let target = b * seven_inv;
		let d = goldilocks_sqrt(target).expect("either b or b/7 must be a square in F_{q₀}");
		let candidate = Goldilocks4::new([zero, zero, zero, d]);
		debug_assert_eq!(
			candidate * candidate,
			Goldilocks4::new([zero, b, zero, zero]),
			"omega_34² ≠ omega_33 (case XY)"
		);
		candidate
	})
}

/// Tonelli–Shanks square root in `F_{q₀}`. Returns `Some(r)` with `r² =
/// target` when `target` is a quadratic residue, otherwise `None`.
///
/// `q₀ − 1 = 2³² · m` with `m = 2³² − 1` (odd); `S = 32`. The non-residue
/// witness is `7` (paper §3.3 confirms `(7/q₀) = −1` via reciprocity).
fn goldilocks_sqrt(target: Goldilocks) -> Option<Goldilocks> {
	if target.is_zero() {
		return Some(Goldilocks::new(0));
	}
	let s: u32 = 32;
	let m_odd: u64 = (1u64 << 32) - 1;
	// Euler's criterion: target is a QR iff target^((q-1)/2) = 1.
	let q_minus_one_half_low: u64 = m_odd; // (q-1)/2 = 2^31 · m_odd; we exponent in pieces
	let euler = {
		let mut acc = target.exp_u64(q_minus_one_half_low);
		acc = acc.exp_power_of_2(31);
		acc
	};
	if !euler.is_one() {
		return None;
	}
	let z = Goldilocks::new(7); // non-residue witness
	let mut m_curr: u32 = s;
	let mut c = z.exp_u64(m_odd);
	let mut t = target.exp_u64(m_odd);
	let mut r = target.exp_u64(m_odd.div_ceil(2));
	loop {
		if t.is_one() {
			return Some(r);
		}
		// Smallest i ∈ [1, m_curr) with t^(2^i) = 1.
		let mut i: u32 = 0;
		let mut tmp = t;
		while !tmp.is_one() {
			tmp = tmp.square();
			i += 1;
			if i >= m_curr {
				return None; // unreachable when target is a QR
			}
		}
		let b = c.exp_power_of_2((m_curr - i - 1) as usize);
		m_curr = i;
		c = b.square();
		t *= c;
		r *= b;
	}
}

// ---------------------------------------------------------------------------
// ψ : position-to-field map
// ---------------------------------------------------------------------------

/// Position-to-field map `ψ_T(i) = g_T^i`, where `g_T` is the primitive `T`-th
/// root of unity in `F_{q₀⁴}` returned by [`Goldilocks4::two_adic_generator`].
///
/// `T` must be a power of two and `log₂(T) ≤ 34` (the 2-adicity of
/// `F_{q₀⁴}^×`; the paper's largest reference deployment `n* = 16_383` hits
/// `log₂(T) = 34`). `ψ` is deterministic,
/// identical for every signer, and injective on `{0, …, T − 1}`. This is
/// consistent with [`Goldilocks4::ntt`]: an NTT of a length-`T` vector produces
/// evaluations at `ψ_T(0), ψ_T(1), …, ψ_T(T − 1)` using the same generator.
pub fn psi(i: u64, t: u64) -> Goldilocks4 {
	assert!(
		t.is_power_of_two(),
		"psi: t must be a power of two, got {t}"
	);
	let log_t = t.trailing_zeros() as usize;
	Goldilocks4::two_adic_generator(log_t).pow(i)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use rand::SeedableRng;
	use rand_chacha::ChaCha20Rng;
	use std::collections::HashSet;

	fn random_gl(rng: &mut ChaCha20Rng) -> Goldilocks {
		use rand::Rng;
		loop {
			let v: u64 = rng.next_u64();
			if v < Q0 {
				return Goldilocks::new(v);
			}
		}
	}

	fn random_g4(rng: &mut ChaCha20Rng) -> Goldilocks4 {
		Goldilocks4::new([
			random_gl(rng),
			random_gl(rng),
			random_gl(rng),
			random_gl(rng),
		])
	}

	fn random_nonzero_g4(rng: &mut ChaCha20Rng) -> Goldilocks4 {
		loop {
			let v = random_g4(rng);
			if !v.is_zero() {
				return v;
			}
		}
	}

	#[test]
	fn addition_commutative() {
		let mut rng = ChaCha20Rng::seed_from_u64(0);
		for _ in 0..100 {
			let a = random_g4(&mut rng);
			let b = random_g4(&mut rng);
			assert_eq!(a + b, b + a);
		}
	}

	#[test]
	fn multiplicative_inverse() {
		let mut rng = ChaCha20Rng::seed_from_u64(0);
		for _ in 0..100 {
			let a = random_nonzero_g4(&mut rng);
			assert_eq!(a * a.inverse(), Goldilocks4::ONE);
		}
	}

	#[test]
	fn distributivity() {
		let mut rng = ChaCha20Rng::seed_from_u64(0);
		for _ in 0..100 {
			let a = random_g4(&mut rng);
			let b = random_g4(&mut rng);
			let c = random_g4(&mut rng);
			assert_eq!(a * (b + c), a * b + a * c);
		}
	}

	#[test]
	fn pow_zero_is_one() {
		let mut rng = ChaCha20Rng::seed_from_u64(10);
		for _ in 0..20 {
			let a = random_g4(&mut rng);
			assert_eq!(a.pow(0), Goldilocks4::ONE);
		}
		assert_eq!(Goldilocks4::ZERO.pow(0), Goldilocks4::ONE);
	}

	#[test]
	fn two_adic_generator_order() {
		let log_n = 8usize;
		let g = Goldilocks4::two_adic_generator(log_n);
		let order = 1u64 << log_n;
		assert_eq!(g.pow(order), Goldilocks4::ONE);
		assert_ne!(g.pow(order / 2), Goldilocks4::ONE);
	}

	#[test]
	fn two_adic_generator_extension_levels_have_correct_order() {
		// log_n = 33 and 34 use the extension-level tower-sqrt path.
		for log_n in [33usize, 34] {
			let g = Goldilocks4::two_adic_generator(log_n);
			let order = 1u64 << log_n;
			assert_eq!(
				g.pow(order),
				Goldilocks4::ONE,
				"g^{order} ≠ 1 at log_n={log_n}"
			);
			assert_ne!(
				g.pow(order / 2),
				Goldilocks4::ONE,
				"g^{} = 1 at log_n={log_n} — order is smaller than 2^{log_n}",
				order / 2
			);
		}
	}

	#[test]
	fn omega_34_squared_is_omega_33() {
		// Cross-check: omega_34^2 must equal Plonky3's hardcoded omega_33.
		let omega_34 = Goldilocks4::two_adic_generator(34);
		let omega_33 = Goldilocks4::two_adic_generator(33);
		assert_eq!(omega_34 * omega_34, omega_33);
	}

	#[test]
	fn omega_33_squared_is_g_32() {
		// Cross-check: omega_33^2 must equal the base-field 2^32-th generator.
		let omega_33 = Goldilocks4::two_adic_generator(33);
		let g_32 = Goldilocks4::two_adic_generator(32);
		assert_eq!(omega_33 * omega_33, g_32);
	}

	#[test]
	fn goldilocks_sqrt_round_trips_on_squares() {
		// (1) Zero squares to zero.
		assert_eq!(
			goldilocks_sqrt(Goldilocks::new(0)),
			Some(Goldilocks::new(0))
		);
		// (2) For random elements, a² is always a square — and (sqrt(a²))² = a².
		let mut rng = ChaCha20Rng::seed_from_u64(7);
		for _ in 0..50 {
			let a = random_gl(&mut rng);
			let sq = a * a;
			let root = goldilocks_sqrt(sq).expect("squares are squares");
			assert_eq!(root * root, sq);
		}
		// (3) Non-residues return None. 7 is the witness used in Tonelli–Shanks
		// itself; pick another known non-residue. By Euler/QR, 7 · 7 = 49 is a
		// square, so we test 7 directly.
		assert_eq!(goldilocks_sqrt(Goldilocks::new(7)), None);
	}

	#[test]
	fn to_bytes_round_trip() {
		let mut rng = ChaCha20Rng::seed_from_u64(3);
		for _ in 0..100 {
			let a = random_g4(&mut rng);
			let bytes = a.to_bytes();
			assert_eq!(bytes.len(), 32);
			let back = Goldilocks4::from_bytes(&bytes).unwrap();
			assert_eq!(a, back);
		}
	}

	#[test]
	fn from_bytes_rejects_non_canonical() {
		let mut buf = [0u8; 32];
		buf[..8].copy_from_slice(&Q0.to_le_bytes());
		assert!(Goldilocks4::from_bytes(&buf).is_none());
	}

	#[test]
	fn narg_deserialize_rejects_non_canonical() {
		let mut buf = [0u8; 32];
		buf[..8].copy_from_slice(&Q0.to_le_bytes());
		let mut slice: &[u8] = &buf;
		assert!(Goldilocks4::deserialize_from_narg(&mut slice).is_err());
	}

	#[test]
	fn narg_deserialize_rejects_short_buffer() {
		let buf = [0u8; 16];
		let mut slice: &[u8] = &buf;
		assert!(Goldilocks4::deserialize_from_narg(&mut slice).is_err());
	}

	#[test]
	fn psi_zero_is_one() {
		assert_eq!(psi(0, 1 << 22), Goldilocks4::ONE);
	}

	#[test]
	fn psi_is_injective() {
		let t = 1u64 << 22;
		let mut seen = HashSet::new();
		for i in 0..1000u64 {
			let v = psi(i, t);
			assert!(seen.insert(v.to_bytes()), "ψ({i}) collides");
		}
	}

	#[test]
	fn psi_is_multiplicative() {
		let t = 1u64 << 22;
		assert_eq!(psi(1, t) * psi(1, t), psi(2, t));
		assert_eq!(psi(3, t) * psi(5, t), psi(8, t));
	}

	#[test]
	fn psi_works_at_extension_2_adicity_ceiling() {
		// The paper's largest reference configuration (n* = 16,383) needs
		// T = 2^34, which falls on the extension-level 2-adic generator path.
		// Spot-check injectivity, multiplicativity, and order at this T.
		let t = 1u64 << 34;
		assert_eq!(psi(0, t), Goldilocks4::ONE);
		assert_eq!(psi(1, t).pow(t), Goldilocks4::ONE);
		assert_ne!(psi(1, t).pow(t / 2), Goldilocks4::ONE);
		assert_eq!(psi(7, t) * psi(11, t), psi(18, t));
	}
}
