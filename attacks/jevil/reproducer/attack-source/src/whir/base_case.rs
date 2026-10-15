//! HVZK base-case IOPP — Construction 7.2 of eprint 2026/391.
//!
//! Closes the WHIR recursion at the leaf with a γ-batched mask reveal over
//! both the main folded codeword `f` and every input mask oracle `ξ_i`
//! carried through the [`MaskStack`].
//!
//! Wire format (prover → verifier):
//! 1. Merkle root of `g` (fresh main-code mask of length `input_msg_len`).
//! 2. Per mask `ξ_i` in the stack: Merkle root of `s_i_bc` (fresh `C_zk`
//!    mask of length `L_ZK_INNER + T_ZK = M_ZK`).
//! 3. Joint target `μ' = ⟨g, coefficients⟩ + Σ_i α_i · ⟨s_i_bc_msg, sl_i⟩`.
//! 4. Verifier sends `γ_bc`.
//! 5. `f* = g_msg + γ_bc · f_msg` (length `input_msg_len`).
//! 6. Per mask: `ξ_i* = (s_i_bc_msg + γ_bc · ξ_i_msg, s_i_bc_r + γ_bc ·
//!    ξ_i_r)` (length `M_ZK`).
//! 7. `f` spot positions sampled; `f` and `g` openings written.
//! 8. Shared mask spot positions sampled (one set used by every mask).
//! 9. Per mask: opening of `ξ_i` (the carry-in mask) and opening of
//!    `s_i_bc` (the fresh BC companion).
//!
//! Verifier checks:
//! - **Per-mask local target check**:
//!   `sl_{o,i}·ξ_i*_msg = μ_i' + γ_bc · μ_i_carry_in` for every carry-in
//!   mask `i`. Binds the previously-published `μ_i` (carried on the
//!   transcript from the prior IOR) to the Merkle-committed mask message;
//!   combined with the per-mask codeword consistency check below, this
//!   prevents an equivocating prover from lying about `μ_i` in the prior
//!   IOR. HVZK is preserved: `μ_i` is a uniform-random field element
//!   independent of the witness (sumcheck masks: `s_j(γ_j)` for fresh
//!   random `s_j`; codeswitch padding masks: `Σ batch_rand · r'` for
//!   fresh random `r'`).
//! - **Joint target check**:
//!   `⟨f*, coefficients⟩ + Σ_i α_i · ⟨ξ_i*_msg, sl_i⟩ = μ' + γ_bc · joint_value`
//!   where `joint_value` is the running joint claim (the sumcheck-final
//!   claim of the immediately-preceding IOR).
//! - **Main-code spot checks**: `Enc_C(f*)[pos] = g[pos] + γ_bc · f[pos]`.
//! - **Per-mask spot checks**: `Enc_{C_zk}(ξ_i*_msg, ξ_i*_r)[pos] =
//!   s_i_bc[pos] + γ_bc · ξ_i[pos]` at shared sampled positions for every
//!   mask in the stack.

use spongefish::{ProverState, VerificationError, VerificationResult, VerifierState};

use super::code::{AdditiveCode, ReedSolomon};
use super::commitment::{
	CodeCommitmentHandle, CodeCommitmentProverHandle, FoldedCodeCommitmentHandle,
};
use super::encoding::ZkEncoding;
use super::linear_form::{FoldedFormHandle, LinearConstraint, LinearFormHandle};
use super::mask_stack::MaskStack;
use super::transcript_io::{
	read_opening, sample_positions_prover, sample_positions_verifier, write_opening,
};
use super::vc::{MerkleVc, VectorCommitment};
use crate::field::Goldilocks4;

/// Inner-symbol width of the main mask `g`. `g` is committed without
/// interleaving, so each Merkle leaf holds a single `Goldilocks4` wrapped
/// in a length-1 `Vec` to fit the [`MerkleVc`] alphabet.
const G_LEAF_WIDTH: usize = 1;

/// Parameters for the base case.
pub(crate) struct BaseCase {
	/// Number of in-domain spot checks on the main code `C`.
	pub(crate) queries: usize,
	/// Number of in-domain spot checks on the shared `C_zk` spot set used
	/// by every mask in the stack.
	pub(crate) mask_queries: usize,
}

impl BaseCase {
	pub(crate) fn new(queries: usize, mask_queries: usize) -> Self {
		Self {
			queries,
			mask_queries,
		}
	}

	/// Run the prover side of Construction 7.2.
	pub(crate) fn prove<CCH>(
		&self,
		transcript: &mut ProverState,
		input: CCH,
		coefficients: &[Goldilocks4],
		mask_stack: &MaskStack,
		mask_seed: &[u8; 32],
	) where
		CCH: CodeCommitmentProverHandle<
				VC = MerkleVc,
				Code: AdditiveCode<InputAlphabet = Goldilocks4>,
			>,
	{
		let f_msg = input.msg();
		let input_msg_len = f_msg.len();
		assert_eq!(coefficients.len(), input_msg_len);

		// 1. Sample g_msg, encode, commit Merkle root.
		let g_msg = derive_field_vec(mask_seed, b"base_case::g_msg", input_msg_len);
		let g_code = ReedSolomon::<Goldilocks4>::new(input_msg_len);
		let g_codeword = g_code.encode(&g_msg);
		let g_slab = super::code::CodewordSlab::new(g_codeword, 1);
		let g_vc = MerkleVc::new(g_slab.positions());
		let (g_root, g_vc_state) = g_vc.commit_slab(g_slab);
		transcript.prover_message(&g_root);

		// 2. Per mask in stack: commit s_i_bc (fresh C_zk mask) and its root.
		let l_zk_inner = crate::params::Params::M_ZK - crate::params::Params::T_ZK;
		let t_zk = crate::params::Params::T_ZK;
		let zk_enc = ZkEncoding::new(l_zk_inner, t_zk);
		let mut s_bc_states: Vec<SOracleProverState> = Vec::with_capacity(mask_stack.len());
		for i in 0..mask_stack.len() {
			let s_bc_msg = derive_field_vec_indexed(mask_seed, b"bc::s_msg", i, l_zk_inner);
			let s_bc_r = derive_field_vec_indexed(mask_seed, b"bc::s_r", i, t_zk);
			let s_bc_codeword = zk_enc.encode_with(&s_bc_msg, &s_bc_r);
			let s_bc_slab = super::code::CodewordSlab::new(s_bc_codeword, 1);
			let s_bc_vc = MerkleVc::new(s_bc_slab.positions());
			let (s_bc_root, s_bc_vc_state) = s_bc_vc.commit_slab(s_bc_slab);
			transcript.prover_message(&s_bc_root);
			s_bc_states.push(SOracleProverState {
				msg: s_bc_msg,
				r: s_bc_r,
				vc: s_bc_vc,
				vc_state: s_bc_vc_state,
			});
		}

		// 3. Joint target μ' = ⟨g, coefficients⟩ + Σ_i α_i · ⟨s_i_bc_msg, sl_i⟩,
		//    and per-mask μ_i' = sl_{o,i} · s_i_bc_msg (sent separately so
		//    the verifier can do the per-mask local target check that binds
		//    the carry-in μ_i = mc.target).
		let mu_prime_main: Goldilocks4 = g_msg.iter().zip(coefficients).map(|(g, c)| *g * *c).sum();
		let mu_prime_per_mask: Vec<Goldilocks4> = s_bc_states
			.iter()
			.zip(&mask_stack.constraints)
			.map(|(s, mc)| mc.evaluate_sl(&s.msg))
			.collect();
		let mu_prime_masks: Goldilocks4 = mask_stack
			.constraints
			.iter()
			.zip(&mu_prime_per_mask)
			.map(|(mc, mu_i)| mc.alpha * *mu_i)
			.sum();
		transcript.prover_message(&(mu_prime_main + mu_prime_masks));
		for mu_i_prime in &mu_prime_per_mask {
			transcript.prover_message(mu_i_prime);
		}

		// 4. Read γ_bc.
		let gamma_bc: Goldilocks4 = transcript.verifier_message();

		// 5. Send f* = g + γ_bc·f (length input_msg_len).
		let f_star: Vec<Goldilocks4> = g_msg
			.iter()
			.zip(f_msg)
			.map(|(g, f)| *g + gamma_bc * *f)
			.collect();
		for el in &f_star {
			transcript.prover_message(el);
		}

		// 6. Per mask: send (ξ_i*_msg, ξ_i*_r) combined, length M_ZK = 64.
		for (s_bc, mask) in s_bc_states.iter().zip(&mask_stack.oracles) {
			let carry_msg = mask.message();
			let carry_r = mask.randomness();
			assert_eq!(s_bc.msg.len(), carry_msg.len());
			assert_eq!(s_bc.r.len(), carry_r.len());
			for (s, c) in s_bc.msg.iter().zip(carry_msg) {
				transcript.prover_message(&(*s + gamma_bc * *c));
			}
			for (s, c) in s_bc.r.iter().zip(carry_r) {
				transcript.prover_message(&(*s + gamma_bc * *c));
			}
		}

		// 7. Sample f spot positions; open f and g.
		let positions = sample_positions_prover(transcript, self.queries, input.codeword_len());
		let input_opening = input.open(&positions);
		let g_opening = g_vc.open(&g_vc_state, &positions);
		write_opening(transcript, &input_opening);
		write_opening(transcript, &g_opening);

		// 8. Sample shared mask spot positions, then per mask open ξ_i and s_i_bc.
		if !mask_stack.is_empty() {
			let mask_positions =
				sample_positions_prover(transcript, self.mask_queries, zk_enc.codeword_len);
			for (s_bc, mask) in s_bc_states.iter().zip(&mask_stack.oracles) {
				let mask_opening = mask.open(&mask_positions);
				let s_bc_opening = s_bc.vc.open(&s_bc.vc_state, &mask_positions);
				write_opening(transcript, &mask_opening);
				write_opening(transcript, &s_bc_opening);
			}
		}
	}
}

/// Verifier side of Construction 7.2.
pub(crate) fn verify_base_case<EC>(
	transcript: &mut VerifierState,
	queries: usize,
	mask_queries: usize,
	folded_commitment: FoldedCodeCommitmentHandle<EC, MerkleVc>,
	constraint: LinearConstraint<FoldedFormHandle<Goldilocks4>>,
	mask_stack_view: &[super::mask_stack::MaskOracleHandle],
	mask_constraints: &[super::mask_stack::MaskConstraint],
) -> VerificationResult<()>
where
	EC: super::code::LinearCode<Alphabet = Goldilocks4>,
	ReedSolomon<Goldilocks4>:
		AdditiveCode<InputAlphabet = Goldilocks4, OutputAlphabet = Goldilocks4>,
{
	assert_eq!(mask_stack_view.len(), mask_constraints.len());
	let input_msg_len = folded_commitment.msg_len();
	let l_zk_inner = crate::params::Params::M_ZK - crate::params::Params::T_ZK;
	let t_zk = crate::params::Params::T_ZK;
	let zk_enc = ZkEncoding::new(l_zk_inner, t_zk);

	// 1. Read g root.
	let g_root: [u8; 32] = transcript.prover_message()?;

	// 2. Read s_i_bc roots, one per mask.
	let mut s_bc_roots: Vec<[u8; 32]> = Vec::with_capacity(mask_stack_view.len());
	for _ in mask_stack_view {
		s_bc_roots.push(transcript.prover_message()?);
	}

	// 3. Read joint μ' and per-mask μ_i'.
	let mu_prime: Goldilocks4 = transcript.prover_message()?;
	let mut mu_i_primes: Vec<Goldilocks4> = Vec::with_capacity(mask_stack_view.len());
	for _ in mask_stack_view {
		mu_i_primes.push(transcript.prover_message()?);
	}

	// 4. γ_bc.
	let gamma_bc: Goldilocks4 = transcript.verifier_message();

	// 5. Read f* (length input_msg_len).
	let f_star = transcript.prover_messages_vec::<Goldilocks4>(input_msg_len)?;

	// 6. Read each ξ_i* = (msg portion of length L_ZK_INNER, randomness
	//    portion of length T_ZK), total M_ZK per mask.
	let mut xi_star_msgs: Vec<Vec<Goldilocks4>> = Vec::with_capacity(mask_stack_view.len());
	let mut xi_star_rs: Vec<Vec<Goldilocks4>> = Vec::with_capacity(mask_stack_view.len());
	for _ in mask_stack_view {
		xi_star_msgs.push(transcript.prover_messages_vec::<Goldilocks4>(l_zk_inner)?);
		xi_star_rs.push(transcript.prover_messages_vec::<Goldilocks4>(t_zk)?);
	}

	// 7a. Per-mask local target check:
	//     sl_{o,i} · ξ_i*_msg = μ_i' + γ_bc · μ_i_carry_in (= mc.target).
	for ((xi_star_msg, mc), mu_i_prime) in
		xi_star_msgs.iter().zip(mask_constraints).zip(&mu_i_primes)
	{
		if mc.evaluate_sl(xi_star_msg) != *mu_i_prime + gamma_bc * mc.target {
			return Err(VerificationError);
		}
	}

	// 7b. Joint target check:
	//     ⟨f*, coefficients⟩ + Σ_i α_i · ⟨ξ_i*_msg, sl_i⟩ = μ' + γ_bc · joint_value.
	let coefficients = constraint.linear_form_handle.folded_form(&[]);
	if coefficients.len() != f_star.len() {
		return Err(VerificationError);
	}
	let main_dot: Goldilocks4 = coefficients.iter().zip(&f_star).map(|(a, b)| *a * *b).sum();
	let mask_dot: Goldilocks4 = xi_star_msgs
		.iter()
		.zip(mask_constraints)
		.map(|(xi_star_msg, mc)| mc.alpha * mc.evaluate_sl(xi_star_msg))
		.sum();
	if main_dot + mask_dot != mu_prime + gamma_bc * constraint.value {
		return Err(VerificationError);
	}

	// 8. Main-code spot checks.
	let positions =
		sample_positions_verifier(transcript, queries, folded_commitment.codeword_len());
	let path_len = folded_commitment
		.codeword_len()
		.next_power_of_two()
		.trailing_zeros() as usize;
	const INTERLEAVING: usize = 4;
	// BCS multiproof bytes count from sorted-unique positions (shared by
	// the main code's input opening and the g mask opening — both indexed
	// by the same `positions`).
	let mut main_sorted_unique = positions.clone();
	main_sorted_unique.sort_unstable();
	main_sorted_unique.dedup();
	let main_multiproof_bytes = crate::merkle::multiproof_size(&main_sorted_unique, path_len);
	let input_opening = read_opening(transcript, queries, INTERLEAVING, main_multiproof_bytes)?;
	let g_opening = read_opening(transcript, queries, G_LEAF_WIDTH, main_multiproof_bytes)?;

	let input_folded_values = folded_commitment.verify_openings(&positions, &input_opening)?;
	let g_vc = MerkleVc::new(folded_commitment.codeword_len());
	if !g_vc.verify(&g_root, &positions, &g_opening) {
		return Err(VerificationError);
	}
	let g_values: Vec<Goldilocks4> = g_opening.openings.iter().map(|o| o[0]).collect();

	let inner_code = ReedSolomon::<Goldilocks4>::new(input_msg_len);
	let encoded_f_star = inner_code.encode(&f_star);
	for (i, &pos) in positions.iter().enumerate() {
		let expected = g_values[i] + gamma_bc * input_folded_values[i];
		match encoded_f_star.get(pos) {
			Some(actual) if *actual == expected => {}
			_ => return Err(VerificationError),
		}
	}

	// 9. Per-mask spot checks (shared positions across all masks).
	if !mask_stack_view.is_empty() {
		let mask_path_len = zk_enc.codeword_len.next_power_of_two().trailing_zeros() as usize;

		// Read all per-mask openings BEFORE sampling shared positions (matches
		// the prover's write order: openings written after sampling positions).
		// Actually the prover wrote openings AFTER positions, so the verifier
		// must sample positions FIRST, then read.
		let mask_positions =
			sample_positions_verifier(transcript, mask_queries, zk_enc.codeword_len);

		// BCS multiproof bytes for the shared mask spotcheck positions.
		// All per-mask trees in the stack share the same codeword length
		// (m_zk) and therefore the same path depth, so a single size suffices.
		let mut mask_sorted_unique = mask_positions.clone();
		mask_sorted_unique.sort_unstable();
		mask_sorted_unique.dedup();
		let s_bc_multiproof_bytes =
			crate::merkle::multiproof_size(&mask_sorted_unique, mask_path_len);

		for (((s_bc_root, mask), xi_star_msg), xi_star_r) in s_bc_roots
			.iter()
			.zip(mask_stack_view)
			.zip(&xi_star_msgs)
			.zip(&xi_star_rs)
		{
			// Carry-in mask oracle's tree depth equals mask.path_len() (which
			// equals mask_path_len for C_zk-shape oracles — that's the only
			// oracle shape in the stack at base case).
			let mask_multiproof_bytes =
				crate::merkle::multiproof_size(&mask_sorted_unique, mask.path_len());
			let mask_opening = read_opening(transcript, mask_queries, 1, mask_multiproof_bytes)?;
			let s_bc_opening = read_opening(transcript, mask_queries, 1, s_bc_multiproof_bytes)?;

			let carry_values = mask.verify_openings(&mask_positions, &mask_opening)?;
			let s_bc_vc = MerkleVc::new(zk_enc.codeword_len);
			if !s_bc_vc.verify(s_bc_root, &mask_positions, &s_bc_opening) {
				return Err(VerificationError);
			}
			let s_bc_values: Vec<Goldilocks4> =
				s_bc_opening.openings.iter().map(|o| o[0]).collect();

			// Codeword consistency: Enc_{C_zk}(ξ_i*_msg, ξ_i*_r)[pos] should
			// equal s_i_bc_codeword[pos] + γ_bc · ξ_i_codeword[pos].
			let xi_star_codeword = zk_enc.encode_with(xi_star_msg, xi_star_r);
			for (j, &pos) in mask_positions.iter().enumerate() {
				let expected = s_bc_values[j] + gamma_bc * carry_values[j];
				match xi_star_codeword.get(pos) {
					Some(actual) if *actual == expected => {}
					_ => return Err(VerificationError),
				}
			}
		}
	}

	Ok(())
}

/// Per-mask prover state produced when committing the companion `s_i_bc`
/// oracle. Holds both the message portion and the encoding randomness so
/// the prover can later send `(s_i_bc_msg + γ_bc·ξ_i_msg, s_i_bc_r +
/// γ_bc·ξ_i_r)` and open the codeword at spot positions.
struct SOracleProverState {
	msg: Vec<Goldilocks4>,
	r: Vec<Goldilocks4>,
	vc: MerkleVc,
	vc_state: <MerkleVc as VectorCommitment>::CommitState,
}

/// Derive `count` `Goldilocks4` elements deterministically from
/// `(mask_seed, purpose)` via the `JV-OPRD` SHAKE256 stream with per-limb
/// rejection sampling.
///
/// All per-signature WHIR-prover randomness — sumcheck round-polynomial
/// masks (Construction 6.3), code-switching padding masks (Construction
/// 9.7), and base-case mask companions (Construction 7.2) — flows through
/// this function with `mask_seed = ρ` set by
/// [`crate::sign::derive_prover_randomness_seed`]. Using `JV-OPRD` rather
/// than `JV-RZK` keeps the spec's seven-tag domain separation intact
/// (`JV-RZK` is reserved for `KeyGen`'s encoding randomness).
pub(crate) fn derive_field_vec(
	mask_seed: &[u8; 32],
	purpose: &[u8],
	count: usize,
) -> Vec<Goldilocks4> {
	crate::hash::shake_field_elements(crate::hash::JV_OPRD, &[mask_seed, purpose], count)
}

/// Derive `count` `Goldilocks4` elements deterministically from
/// `(mask_seed, purpose, i)`. Used to give each mask oracle a distinct stream.
pub(crate) fn derive_field_vec_indexed(
	mask_seed: &[u8; 32],
	purpose: &[u8],
	i: usize,
	count: usize,
) -> Vec<Goldilocks4> {
	let mut salt = purpose.to_vec();
	salt.extend_from_slice(b"::idx::");
	salt.extend_from_slice(&(i as u64).to_le_bytes());
	derive_field_vec(mask_seed, &salt, count)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn derive_field_vec_is_deterministic() {
		let seed = [42u8; 32];
		let a = derive_field_vec(&seed, b"test", 8);
		let b = derive_field_vec(&seed, b"test", 8);
		assert_eq!(a, b);
		assert_eq!(a.len(), 8);
	}

	#[test]
	fn derive_field_vec_indexed_distinct_by_index() {
		let seed = [42u8; 32];
		let a = derive_field_vec_indexed(&seed, b"x", 0, 4);
		let b = derive_field_vec_indexed(&seed, b"x", 1, 4);
		assert_ne!(a, b);
	}

	#[test]
	fn derive_field_vec_distinct_by_purpose() {
		let seed = [42u8; 32];
		let a = derive_field_vec(&seed, b"alpha", 4);
		let b = derive_field_vec(&seed, b"beta", 4);
		assert_ne!(a, b);
	}
}
