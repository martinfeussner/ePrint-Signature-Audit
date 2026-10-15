//! Mask-oracle stack carried between IOR rounds within one signature.
//!
//! Each sumcheck round (Construction 6.3 of eprint 2026/391) pushes `k`
//! mask handles via [`MaskStack::push_sumcheck_masks`]. Each code-switching
//! round (Construction 9.7) pushes one randomness-padding mask via
//! [`MaskStack::push_padding_mask`]. The base case (Construction 7.2)
//! consumes the entire stack — opening each mask oracle and checking
//! per-oracle codeword consistency.
//!
//! Two flavours of handle coexist in [`MaskOracleHandle`]: a prover-side
//! [`MaskOracleHandle::Prover`] variant that owns the message + encoding
//! randomness + Merkle state (used for both sumcheck masks and codeswitch
//! padding masks — the runtime shape is identical), and a verifier-side
//! [`MaskOracleHandle::VerifierRootOnly`] variant that holds only the
//! root (used to verify openings against the same root the prover
//! committed to).

use super::vc::{MerkleVc, Opening, VectorCommitment};
use crate::field::Goldilocks4;

/// Per-mask-oracle handle.
///
/// The [`MaskOracleHandle::Prover`] variant carries everything the prover
/// needs to open the oracle at base-case spot positions and to combine it
/// into the joint linear form; it is used uniformly for both Construction
/// 6.3 sumcheck masks and Construction 9.7 codeswitch padding masks (their
/// runtime shape is identical — a `C_zk`-encoded message + Prop 3.19
/// randomness + Merkle state). The [`MaskOracleHandle::VerifierRootOnly`]
/// variant reconstructs the same shape from only the committed root.
pub(crate) enum MaskOracleHandle {
	/// Prover-side handle: owns the message, encoding randomness, and Merkle
	/// commit state. Used for both sumcheck masks and codeswitch padding
	/// masks.
	Prover {
		msg: Vec<Goldilocks4>,
		r: Vec<Goldilocks4>,
		vc: MerkleVc,
		vc_state: <MerkleVc as VectorCommitment>::CommitState,
	},
	/// Verifier-side handle: only the root is known.
	VerifierRootOnly { root: [u8; 32] },
}

impl MaskOracleHandle {
	/// Construct a prover-side mask handle. Used by both the sumcheck IOR
	/// (Construction 6.3, via [`super::sumcheck::prove_sumcheck_zk`]) and
	/// the codeswitch IOR (Construction 9.7, via
	/// [`super::protocol::ProverCodeswitch::prove`]).
	pub(crate) fn new_prover(
		msg: Vec<Goldilocks4>,
		r: Vec<Goldilocks4>,
		vc: MerkleVc,
		vc_state: <MerkleVc as VectorCommitment>::CommitState,
	) -> Self {
		Self::Prover {
			msg,
			r,
			vc,
			vc_state,
		}
	}

	pub(crate) fn verifier_root_only(root: [u8; 32]) -> Self {
		Self::VerifierRootOnly { root }
	}

	/// Borrow the underlying message. Panics on the verifier-side variant.
	pub(crate) fn message(&self) -> &[Goldilocks4] {
		match self {
			Self::Prover { msg, .. } => msg,
			Self::VerifierRootOnly { .. } => panic!("verifier handle has no message"),
		}
	}

	/// Borrow the encoding randomness. Panics on the verifier-side variant.
	pub(crate) fn randomness(&self) -> &[Goldilocks4] {
		match self {
			Self::Prover { r, .. } => r,
			Self::VerifierRootOnly { .. } => panic!("verifier handle has no randomness"),
		}
	}

	/// Open the underlying VC at the given positions. Panics on the
	/// verifier-side variant (the verifier verifies, it does not open).
	pub(crate) fn open(&self, positions: &[usize]) -> Opening<MerkleVc> {
		match self {
			Self::Prover { vc, vc_state, .. } => vc.open(vc_state, positions),
			Self::VerifierRootOnly { .. } => panic!("verifier handle cannot open"),
		}
	}

	/// Verify openings against the held root, returning the opened scalar
	/// values (one per position). Panics on prover-side variants — those
	/// should call [`Self::open`] instead.
	pub(crate) fn verify_openings(
		&self,
		positions: &[usize],
		proof: &Opening<MerkleVc>,
	) -> Result<Vec<Goldilocks4>, spongefish::VerificationError> {
		match self {
			Self::VerifierRootOnly { root } => {
				if proof.openings.len() != positions.len() {
					return Err(spongefish::VerificationError);
				}
				let codeword_len = mask_codeword_len();
				let vc = MerkleVc::new(codeword_len);
				if !vc.verify(root, positions, proof) {
					return Err(spongefish::VerificationError);
				}
				Ok(proof.openings.iter().map(|o| o[0]).collect())
			}
			_ => panic!("prover handle cannot verify"),
		}
	}

	/// Number of Merkle-path hashes per opened position (constant for the
	/// fixed C_zk codeword length).
	pub(crate) fn path_len(&self) -> usize {
		mask_codeword_len().next_power_of_two().trailing_zeros() as usize
	}
}

/// Codeword length of the fixed C_zk encoding shared by every mask oracle.
///
/// `Params::M_ZK` is the total NTT-input size (honest message + Prop 3.19
/// randomness); the honest-message portion is `M_ZK - T_ZK` and the
/// randomness portion is `T_ZK`.
fn mask_codeword_len() -> usize {
	let m_zk = crate::params::Params::M_ZK;
	let t_zk = crate::params::Params::T_ZK;
	super::encoding::ZkEncoding::new(m_zk - t_zk, t_zk).codeword_len
}

/// Per-oracle constraint metadata `(α_i, μ_i, sl_{o,i})`.
///
/// `sl_{o,i}` is the multilinear-extension evaluation point applied to the
/// mask's message vector (length `M_ZK - T_ZK = L_ZK_INNER = 32`). For
/// Construction 6.3 sumcheck masks this is `(1, γ_j, γ_j², 0, …, 0)` where
/// `γ_j` is the j-th sumcheck challenge of the round that pushed the mask.
///
/// `alpha` is the running coefficient of this mask in the joint linear form:
/// each subsequent sumcheck's combination randomness ε multiplies every
/// carry-in mask's alpha. Initial alpha at push time is `1` (the per-round
/// `constant_adj_j` in `sumcheck.rs` absorbs the carry-in with weight 1
/// regardless of `k`, so the final claim's mask contribution is
/// `M_k(γ_k) = μ_1 + μ_2 + … + μ_k`).
///
/// `target` is the per-oracle local target μ_i. For sumcheck masks this is
/// the prover-sent `s_j(γ_j)`; for codeswitch padding masks it is the
/// prover-sent `sl_o · padding_msg`.
pub(crate) struct MaskConstraint {
	/// Coefficient of this mask in the joint linear form.
	pub alpha: Goldilocks4,
	/// The local target value `μ_i`.
	pub target: Goldilocks4,
	/// The succinct linear form `sl_{o,i}` evaluated at the per-oracle
	/// state, as a length-`L_ZK_INNER` coefficient vector. `L_ZK_INNER =
	/// M_ZK - T_ZK = 32`.
	pub sl_o_eval_point: Vec<Goldilocks4>,
}

impl MaskConstraint {
	/// Evaluate `sl_{o,i}(st_{o,i}) · msg` as the dot product of the
	/// stored eval-point coefficients with the mask message.
	pub fn evaluate_sl(&self, msg: &[Goldilocks4]) -> Goldilocks4 {
		assert_eq!(msg.len(), self.sl_o_eval_point.len());
		msg.iter()
			.zip(&self.sl_o_eval_point)
			.map(|(a, b)| *a * *b)
			.sum()
	}
}

/// Carry-through state for one signature's IOR run.
pub(crate) struct MaskStack {
	pub oracles: Vec<MaskOracleHandle>,
	pub constraints: Vec<MaskConstraint>,
}

impl MaskStack {
	pub fn new() -> Self {
		Self {
			oracles: Vec::new(),
			constraints: Vec::new(),
		}
	}

	pub fn len(&self) -> usize {
		debug_assert_eq!(self.oracles.len(), self.constraints.len());
		self.oracles.len()
	}

	pub fn is_empty(&self) -> bool {
		self.oracles.is_empty()
	}

	/// Multiply every existing mask's `alpha` by `epsilon`. Called at the
	/// start of each new sumcheck when its `mask_rlc = ε` rescales the
	/// running joint claim.
	pub fn scale_alphas(&mut self, epsilon: Goldilocks4) {
		for mc in &mut self.constraints {
			mc.alpha *= epsilon;
		}
	}

	/// Push `k` masks introduced by a sumcheck round, computing the initial
	/// `alpha_j` and `sl_j` from the sumcheck challenges. The `gammas` are
	/// the `k` sumcheck challenges `(γ_1, …, γ_k)` IN ORDER. The `targets`
	/// are the per-mask `μ_j = sl_j · s_j_msg` values — the polynomial
	/// evaluations at `γ_j` that the prover sends and the verifier reads
	/// during the sumcheck-zk wrapper. These bind the joint constraint
	/// across IORs without leaking witness information (the masks are
	/// fresh random polynomials, so their evaluations are uniform random
	/// independent of the witness `f`).
	pub fn push_sumcheck_masks(
		&mut self,
		masks: Vec<MaskOracleHandle>,
		gammas: Vec<Goldilocks4>,
		targets: Vec<Goldilocks4>,
	) {
		assert_eq!(masks.len(), gammas.len());
		assert_eq!(masks.len(), targets.len());
		for ((mask, gamma), target) in masks.into_iter().zip(gammas).zip(targets) {
			let sl_o_eval_point = build_sumcheck_sl(gamma);
			self.oracles.push(mask);
			self.constraints.push(MaskConstraint {
				alpha: Goldilocks4::ONE,
				target,
				sl_o_eval_point,
			});
		}
	}

	/// Compute the joint mask-side contribution to the running claim:
	/// `Σ_i α_i · target_i`. The verifier subtracts this from the running
	/// claim before passing to the next sumcheck (so the sumcheck operates
	/// on just the main-message part), then adds back `ε · this_value` to
	/// restore the joint formulation.
	pub fn joint_mask_value(&self) -> Goldilocks4 {
		self.constraints.iter().map(|mc| mc.alpha * mc.target).sum()
	}

	/// Push one randomness-padding mask introduced by a code-switching round
	/// (Construction 9.7). The caller patches `constraints.last_mut().target`
	/// to the prover-sent `sl_o · padding_msg` value before relying on the
	/// joint check.
	pub fn push_padding_mask(
		&mut self,
		mask: MaskOracleHandle,
		alpha: Goldilocks4,
		sl_o_eval_point: Vec<Goldilocks4>,
	) {
		self.oracles.push(mask);
		self.constraints.push(MaskConstraint {
			alpha,
			target: Goldilocks4::ZERO,
			sl_o_eval_point,
		});
	}
}

/// Build the per-sumcheck-mask `sl_j` linear-form coefficient vector
/// `(1, γ, γ², 0, …, 0)` of length `L_ZK_INNER = M_ZK − T_ZK`.
pub(crate) fn build_sumcheck_sl(gamma: Goldilocks4) -> Vec<Goldilocks4> {
	let l_zk_inner = crate::params::Params::M_ZK - crate::params::Params::T_ZK;
	debug_assert!(
		l_zk_inner >= 3,
		"L_ZK_INNER must accommodate degree-2 mask polynomial"
	);
	let mut sl = vec![Goldilocks4::ZERO; l_zk_inner];
	sl[0] = Goldilocks4::ONE;
	sl[1] = gamma;
	sl[2] = gamma * gamma;
	sl
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
	fn new_mask_stack_is_empty() {
		let stack = MaskStack::new();
		assert!(stack.is_empty());
		assert_eq!(stack.len(), 0);
	}

	#[test]
	fn push_sumcheck_masks_grows_by_k_and_sets_alphas() {
		let mut stack = MaskStack::new();
		let masks = vec![
			MaskOracleHandle::verifier_root_only([1u8; 32]),
			MaskOracleHandle::verifier_root_only([2u8; 32]),
		];
		let gammas = vec![g4(7), g4(11)];
		let targets = vec![g4(100), g4(200)];
		stack.push_sumcheck_masks(masks, gammas, targets);
		assert_eq!(stack.len(), 2);
		// Per the actual HVZK round-polynomial: M_k(γ_k) = Σ μ_i with α_i = 1.
		assert_eq!(stack.constraints[0].alpha, g4(1));
		assert_eq!(stack.constraints[1].alpha, g4(1));
		assert_eq!(stack.constraints[0].target, g4(100));
		assert_eq!(stack.constraints[1].target, g4(200));
		// sl_j starts with (1, γ_j, γ_j²).
		assert_eq!(stack.constraints[0].sl_o_eval_point[0], g4(1));
		assert_eq!(stack.constraints[0].sl_o_eval_point[1], g4(7));
		assert_eq!(stack.constraints[0].sl_o_eval_point[2], g4(49));
		assert_eq!(stack.constraints[1].sl_o_eval_point[0], g4(1));
		assert_eq!(stack.constraints[1].sl_o_eval_point[1], g4(11));
		assert_eq!(stack.constraints[1].sl_o_eval_point[2], g4(121));
	}

	#[test]
	fn scale_alphas_multiplies_all_in_place() {
		let mut stack = MaskStack::new();
		let masks = vec![
			MaskOracleHandle::verifier_root_only([1u8; 32]),
			MaskOracleHandle::verifier_root_only([2u8; 32]),
		];
		stack.push_sumcheck_masks(masks, vec![g4(1), g4(2)], vec![g4(0), g4(0)]);
		stack.scale_alphas(g4(5));
		assert_eq!(stack.constraints[0].alpha, g4(5)); // 1 * 5
		assert_eq!(stack.constraints[1].alpha, g4(5)); // 1 * 5
	}

	#[test]
	fn joint_mask_value_sums_alpha_times_target() {
		let mut stack = MaskStack::new();
		stack.push_sumcheck_masks(
			vec![
				MaskOracleHandle::verifier_root_only([1u8; 32]),
				MaskOracleHandle::verifier_root_only([2u8; 32]),
			],
			vec![g4(1), g4(2)],
			vec![g4(10), g4(20)],
		);
		// α=(1, 1), target=(10, 20) → joint = 10 + 20 = 30
		assert_eq!(stack.joint_mask_value(), g4(30));
	}

	#[test]
	fn push_padding_mask_grows_by_one() {
		let mut stack = MaskStack::new();
		stack.push_padding_mask(
			MaskOracleHandle::verifier_root_only([7u8; 32]),
			g4(3),
			vec![g4(0); crate::params::Params::M_ZK - crate::params::Params::T_ZK],
		);
		assert_eq!(stack.len(), 1);
		assert_eq!(stack.constraints[0].alpha, g4(3));
	}

	#[test]
	fn mask_constraint_evaluate_sl_is_dot_product() {
		let msg = vec![g4(1), g4(2), g4(3)];
		let eval_point = vec![g4(10), g4(20), g4(30)];
		let mc = MaskConstraint {
			alpha: g4(1),
			target: g4(0),
			sl_o_eval_point: eval_point,
		};
		assert_eq!(mc.evaluate_sl(&msg), g4(10 + 40 + 90));
	}

	#[test]
	#[should_panic(expected = "verifier handle has no message")]
	fn verifier_handle_message_panics() {
		let h = MaskOracleHandle::verifier_root_only([0u8; 32]);
		let _ = h.message();
	}

	#[test]
	#[should_panic(expected = "verifier handle cannot open")]
	fn verifier_handle_open_panics() {
		let h = MaskOracleHandle::verifier_root_only([0u8; 32]);
		let _ = h.open(&[0]);
	}
}
