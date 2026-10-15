//! Reed–Solomon ZK encoding per Proposition 3.19 of eprint 2026/391.
//!
//! For Reed–Solomon `C := RS[F, L, ℓ + t]` the Prop 3.19 ZK encoding is
//!
//! ```text
//! Enc_C(msg, r) := NTT(msg ‖ r) padded to codeword_len = 4·(ℓ + t).
//! ```
//!
//! Any subset `S ⊆ [codeword_len]` with `|S| ≤ t` is statistically independent
//! of `msg` over uniformly random `r` — perfect ZK (`ζ_C = 0` for RS).
//!
//! This module exposes only the deterministic [`ZkEncoding::encode_with`]
//! constructor, which is what `keygen`, the codeswitch padding mask, and the
//! sumcheck / base-case mask oracles need. The randomness `r` is always
//! derived deterministically from the per-signature `JV-OPRD` seed (or, for
//! the public-key commitment, the long-term `JV-RZK` seed); fresh OS-RNG
//! sampling is intentionally not supported here.

use crate::field::Goldilocks4;

/// Reed–Solomon ZK encoding with Prop 3.19 randomness sizing.
pub(crate) struct ZkEncoding {
	/// Length of the honest message (call it `ℓ`).
	pub(crate) msg_len: usize,
	/// Length of the Prop 3.19 encoding randomness (call it `t`). Any subset
	/// of ≤ `t` codeword positions is statistically independent of the honest
	/// message over uniform `r`.
	pub(crate) rand_len: usize,
	/// Codeword length, `4 · (msg_len + rand_len)`. Must be a power of two.
	pub(crate) codeword_len: usize,
}

impl ZkEncoding {
	/// Construct a ZK encoding at rate `1 / rate_inv`. Panics unless
	/// `msg_len + rand_len` is a power of two (required by the underlying NTT)
	/// and `rate_inv` is a power of two (so the codeword length stays
	/// NTT-friendly).
	pub(crate) fn new_at_rate(msg_len: usize, rand_len: usize, rate_inv: usize) -> Self {
		let total = msg_len + rand_len;
		assert!(
			total.is_power_of_two(),
			"ZkEncoding::new_at_rate: msg_len + rand_len must be a power of two, got {total}"
		);
		assert!(
			rate_inv.is_power_of_two(),
			"ZkEncoding::new_at_rate: rate_inv must be a power of two, got {rate_inv}"
		);
		Self {
			msg_len,
			rand_len,
			codeword_len: total * rate_inv,
		}
	}

	/// Construct a ZK encoding at the C_zk rate (`ρ_zk = 1/16` per paper
	/// §3.5). Equivalent to `new_at_rate(msg_len, rand_len, Params::RATE_INV_ZK)`.
	pub(crate) fn new(msg_len: usize, rand_len: usize) -> Self {
		Self::new_at_rate(msg_len, rand_len, crate::params::Params::RATE_INV_ZK)
	}

	/// Encode with caller-supplied randomness. Used by [`crate::keygen`]
	/// (which derives `r` deterministically from the secret seed via `JV-RZK`)
	/// and by the per-signature mask oracles in
	/// [`super::sumcheck`] / [`super::base_case`] / [`super::protocol`]
	/// (which derive `r` deterministically from the per-signature `JV-OPRD`
	/// seed).
	pub(crate) fn encode_with(&self, msg: &[Goldilocks4], r: &[Goldilocks4]) -> Vec<Goldilocks4> {
		assert_eq!(msg.len(), self.msg_len);
		assert_eq!(r.len(), self.rand_len);
		let mut padded: Vec<Goldilocks4> = Vec::with_capacity(self.codeword_len);
		padded.extend_from_slice(msg);
		padded.extend_from_slice(r);
		padded.resize(self.codeword_len, Goldilocks4::default());
		Goldilocks4::ntt(padded)
	}
}

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
	fn encoding_is_linear() {
		// Enc(m1 + m2, r1 + r2) = Enc(m1, r1) + Enc(m2, r2). A regression
		// guard on the NTT linearity property underpinning the whole
		// codeswitch + base case algebra: if the encoding stopped being
		// linear, every joint linear-form check downstream would still
		// "verify" but for the wrong claim.
		let enc = ZkEncoding::new(4, 4);
		let m1: Vec<_> = (0..4).map(|i| g4(i as u64)).collect();
		let m2: Vec<_> = (0..4).map(|i| g4(10 + i as u64)).collect();
		let r1: Vec<_> = (0..4).map(|i| g4(100 + i as u64)).collect();
		let r2: Vec<_> = (0..4).map(|i| g4(200 + i as u64)).collect();
		let c1 = enc.encode_with(&m1, &r1);
		let c2 = enc.encode_with(&m2, &r2);
		let m_sum: Vec<_> = m1.iter().zip(&m2).map(|(a, b)| *a + *b).collect();
		let r_sum: Vec<_> = r1.iter().zip(&r2).map(|(a, b)| *a + *b).collect();
		let c_sum = enc.encode_with(&m_sum, &r_sum);
		for i in 0..enc.codeword_len {
			assert_eq!(c1[i] + c2[i], c_sum[i], "linearity at i={i}");
		}
	}
}
