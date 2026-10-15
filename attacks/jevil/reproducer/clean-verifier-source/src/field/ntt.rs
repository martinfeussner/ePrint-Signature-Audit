//! Iterative in-place radix-2 DIT Cooley–Tukey NTT for [`Goldilocks4`].
//!
//! `ntt_in_place(a)` overwrites `a` (length a power of two) with its NTT:
//! on return `a[i] = Σ_k input[k] · g^{ik}` where
//! `g = Goldilocks4::two_adic_generator(log₂ a.len())`. Bit-for-bit identical
//! to the recursive predecessor it replaces.
//!
//! Twiddle factors `[ω_n^0, ω_n^1, …, ω_n^{n/2 - 1}]` are computed once per
//! `log_n` on first use and cached in a `OnceLock` array.
//!
//! Every jevil deployment has `log_n ≤ 21` for the commit-dimension NTT: the
//! largest deployable configuration, `n* = 16,383`, gives `N = 2²¹` (`M = 2¹⁸`
//! plus the `n*·θ` HVZK budget), and the initial-commitment NTT runs over `N`
//! symbols. In that range `Goldilocks4::two_adic_generator(log_n)` lifts from the
//! Goldilocks base field (`[g, 0, 0, 0]`), so all its powers stay in the
//! constant subfield — we store the twiddle table as `[Goldilocks]` and
//! butterflies multiply via the 4-base-mul [`mul_by_base`] rather than the
//! 16-base-mul extension multiplication. `MAX_LOG_N = 32` caps the
//! supported size at the boundary where this base-field property still
//! holds.

use std::sync::OnceLock;

use super::{Goldilocks, Goldilocks4};

/// Largest supported `log_n`. Bounded above by the base-field 2-adicity
/// (`32` for `F_{q₀}^×`); at every value in this range
/// `Goldilocks4::two_adic_generator(log_n)` lifts from the base field.
const MAX_LOG_N: usize = 32;

/// Cached length-`n/2` table of base-field twiddle factors for a specific
/// `log_n`. Empty for `log_n = 0`.
struct TwiddleTable {
	twiddles: Box<[Goldilocks]>,
}

/// Per-`log_n` `OnceLock` accessor. First call for a given `log_n` fills the
/// table; subsequent calls return the cached pointer.
fn twiddle_table(log_n: usize) -> &'static TwiddleTable {
	static CELLS: [OnceLock<TwiddleTable>; MAX_LOG_N + 1] =
		[const { OnceLock::new() }; MAX_LOG_N + 1];
	assert!(
		log_n <= MAX_LOG_N,
		"ntt: log_n = {log_n} > {MAX_LOG_N} exceeds the largest supported NTT size"
	);
	CELLS[log_n].get_or_init(|| build_twiddle_table(log_n))
}

/// Build the length-`n/2` base-field twiddle table for the given `log_n`.
fn build_twiddle_table(log_n: usize) -> TwiddleTable {
	if log_n == 0 {
		return TwiddleTable {
			twiddles: Box::new([]),
		};
	}
	let half = 1usize << (log_n - 1);
	// At log_n ≤ 32 the generator is [b, 0, 0, 0]; every power stays in the
	// constant subfield.
	let b = Goldilocks4::two_adic_generator(log_n).c[0];
	let mut table = Vec::with_capacity(half);
	let mut acc = Goldilocks::new(1);
	for _ in 0..half {
		table.push(acc);
		acc *= b;
	}
	TwiddleTable {
		twiddles: table.into_boxed_slice(),
	}
}

/// Multiply a `Goldilocks4` by a base-field scalar in 4 base-field muls
/// (vs 16 for the general extension multiplication).
#[inline]
fn mul_by_base(g4: Goldilocks4, b: Goldilocks) -> Goldilocks4 {
	Goldilocks4::new([g4.c[0] * b, g4.c[1] * b, g4.c[2] * b, g4.c[3] * b])
}

/// In-place radix-2 DIT NTT.
pub(super) fn ntt_in_place(a: &mut [Goldilocks4]) {
	let n = a.len();
	assert!(
		n.is_power_of_two(),
		"ntt: length must be a power of 2, got {n}"
	);
	if n <= 1 {
		return;
	}
	let log_n = n.trailing_zeros() as usize;

	bit_reverse_in_place(a);

	let table = &twiddle_table(log_n).twiddles;

	for s in 1..=log_n {
		let m = 1usize << s;
		let half = m >> 1;
		// At level s, the level-`m` twiddle ω_m^k equals ω_n^{k · (n/m)} —
		// i.e. index `k * stride` into the cached length-`n/2` table.
		let stride = n >> s;
		let mut block = 0usize;
		while block < n {
			for k in 0..half {
				let w = table[k * stride];
				let lo = a[block + k];
				let t = mul_by_base(a[block + k + half], w);
				a[block + k] = lo + t;
				a[block + k + half] = lo - t;
			}
			block += m;
		}
	}
}

/// In-place bit-reversal permutation. After the call, position `i` holds
/// what was originally at the bit-reversal of `i` over `log₂(n)` bits.
fn bit_reverse_in_place(a: &mut [Goldilocks4]) {
	let n = a.len();
	if n <= 2 {
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
			a.swap(i, j);
		}
	}
}
