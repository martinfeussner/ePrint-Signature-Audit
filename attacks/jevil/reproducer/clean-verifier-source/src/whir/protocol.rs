//! Runtime-sized WHIR protocol specialised to Jevil's fixed parameter set.
//!
//! ## Fixed instantiation
//!
//! - Field: [`Goldilocks4`].
//! - Inner code: [`ReedSolomon`] (rate `1/4`) wrapped in
//!   [`InterleavedCode`] (factor 4 — i.e. 4 inner codewords per outer symbol).
//! - Vector commitment: [`MerkleVc`] (Poseidon2-Goldilocks Merkle tree).
//! - Zero evader: DEEP-FRI [`OodEvader`].
//! - Fold cap: keep folding by `κ = 4` while the inner message length exceeds
//!   `threshold = 64`. For even `ν'` this halts exactly at 64; for odd `ν'`
//!   (e.g. the reference `n* = 1023`, `ν' = 17`) the `κ = 4` schedule cannot
//!   land on `2⁶` and halts one step lower, at 32. Prover and verifier share
//!   this schedule, so signatures verify and per-round soundness is unchanged;
//!   this is a deviation from the paper's stated `2⁶` floor that should be
//!   reconciled in the paper text.
//! - `C_zk` (sumcheck / code-switching masks): `M_ZK = 64` at rate `1/16`, so
//!   the mask evaluation domain is the length-1024 codeword (`m_zk = 1024`).
//!
//! ## Length-`M` API (paper `def:whir`)
//!
//! All entry points take **length-`M` messages and linear forms**; the
//! Prop. 3.19 encoding randomness that drives ZK lives entirely inside
//! this module and is never named by callers.
//!
//! - [`ConcreteWhirProtocol::build`] — prover setup for
//!   `(msg_len, hvzk_budget, queries, threshold)`.
//! - [`ConcreteWhirProtocol::commit`] — `WHIR.Commit(c, σ) → (root, st)`;
//!   derives the Prop. 3.19 encoding randomness from `σ` via the `JV-RZK`
//!   tag of `src/hash.rs`.
//! - [`ConcreteWhirProtocol::prove`] — `WHIR.Open(st, α_msg, v) → π`,
//!   written into the Fiat–Shamir transcript.
//! - [`ConcreteWhirVerifier::build`] / [`ConcreteWhirVerifier::verify`] —
//!   verifier counterparts; the verifier supplies a length-`M`
//!   [`LinearFormHandle`] which is wrapped in [`MessageEmbeddedHandle`]
//!   before driving the inner sumcheck.
//!
//! Both halves must be built with the *same* `(msg_len, hvzk_budget,
//! queries, threshold)`; mismatched parameters break interoperability
//! silently.

use std::sync::Arc;

use spongefish::{ProverState, VerificationError, VerificationResult, VerifierState};

use super::base_case::{BaseCase, verify_base_case};
use super::code::{Field, InterleavedCode, ReedSolomon};
use super::codeswitch::CodeswitchHandle;
use super::commitment::{
	CodeCommitment, CodeCommitmentHandle, CodeCommitmentProverHandle, ExplicitCodeCommitmentHandle,
	FoldedCodeCommitmentHandle, FoldedCodeCommitmentProverState,
};
use super::evader::{ETA, OodEvader, OodEvaderHandle};
use super::linear_form::{
	FoldedFormHandle, LinearCombinationForm, LinearConstraint, LinearForm, LinearFormHandle,
};
use super::mask_stack::MaskStack;
use super::transcript_io::{
	read_opening, sample_positions_prover, sample_positions_verifier, write_opening,
};
use super::vc::MerkleVc;
use crate::field::Goldilocks4;
use crate::hash::JV_RZK;

// ---------------------------------------------------------------------------
// Constants matching the reference WHIR parameter set (paper §3.5, Table 4)
// ---------------------------------------------------------------------------

/// Interleaving factor for the outer code (groups of `INTERLEAVING` inner
/// codewords share one outer alphabet symbol).
const INTERLEAVING: usize = 4;

/// Reciprocal of the Reed–Solomon rate (`codeword_len = RATE_INV · msg_len`).
const RATE_INV: usize = 4;

// ---------------------------------------------------------------------------
// Concrete type aliases
// ---------------------------------------------------------------------------

type ProverFolded = FoldedCodeCommitmentProverState<ReedSolomon<Goldilocks4>, MerkleVc>;
type ProverCommit = CodeCommitment<InterleavedCode<ReedSolomon<Goldilocks4>>, MerkleVc>;

type VerifierFolded = FoldedCodeCommitmentHandle<ReedSolomon<Goldilocks4>, MerkleVc>;
type VerifierExplicit =
	ExplicitCodeCommitmentHandle<InterleavedCode<ReedSolomon<Goldilocks4>>, MerkleVc>;

// ===========================================================================
// PROVER
// ===========================================================================

/// One codeswitch round on the prover side.
pub(crate) struct ProverCodeswitch {
	ood_ze: OodEvader,
	queries: usize,
	output_commitment: ProverCommit,
}

impl ProverCodeswitch {
	/// Drive one codeswitch round + embedded HVZK sumcheck.
	///
	/// The `mask_seed`, `salt`, and `mask_stack` let `prove_sumcheck_zk`
	/// commit fresh sumcheck masks and push them onto the stack with
	/// their `(α, sl, target)`.
	fn prove(
		&self,
		transcript: &mut ProverState,
		input: ProverFolded,
		mut constraint: LinearForm<Goldilocks4>,
		mask_seed: &[u8; 32],
		salt: &[u8],
		mask_stack: &mut super::mask_stack::MaskStack,
	) -> (LinearForm<Goldilocks4>, ProverFolded) {
		let output = self
			.output_commitment
			.commit(transcript, input.msg().to_vec());

		// Construction 9.7 (privacy padding for OOD). Commit a fresh
		// C_zk-encoded padding mask whose first ETA entries (= r') will be
		// added to the ETA OOD answers to make them statistically
		// independent of the witness. The verifier reads the root,
		// reconstructs the OOD answers' sl_o contribution at the
		// joint-target check, and verifies codeword consistency at the
		// base case.
		let l_zk_inner = crate::params::Params::M_ZK - crate::params::Params::T_ZK;
		let t_zk = crate::params::Params::T_ZK;
		let zk_enc = super::encoding::ZkEncoding::new(l_zk_inner, t_zk);
		let padding_msg = super::base_case::derive_field_vec(
			mask_seed,
			&codeswitch_pad_msg_salt(salt),
			l_zk_inner,
		);
		let padding_r =
			super::base_case::derive_field_vec(mask_seed, &codeswitch_pad_r_salt(salt), t_zk);
		let padding_codeword = zk_enc.encode_with(&padding_msg, &padding_r);
		let padding_slab = super::code::CodewordSlab::new(padding_codeword, 1);
		let padding_vc = super::vc::MerkleVc::new(padding_slab.positions());
		let (padding_root, padding_vc_state) = padding_vc.commit_slab(padding_slab);
		transcript.prover_message(&padding_root);

		// Spec §3.5 fixes η = 2: draw two independent OOD seeds, then return
		// two evaluations and two corresponding linear-form constraints.
		let ood_seeds: Vec<Goldilocks4> = (0..ETA).map(|_| transcript.verifier_message()).collect();
		// Privacy-padded OOD: y_i = ze(ρ_i)·folded_msg + padding_msg[i] for
		// i ∈ [ETA]. The first ETA entries of padding_msg are the fresh r'.
		let mut ood_answers = self.ood_ze.apply(&output.msg, &ood_seeds);
		for (i, y) in ood_answers.iter_mut().enumerate() {
			*y += padding_msg[i];
		}
		transcript.prover_message(&ood_answers);

		let positions = sample_positions_prover(transcript, self.queries, input.codeword_len());
		let openings = input.open(&positions);

		write_opening(transcript, &openings);

		let batch_rand = transcript.verifier_messages_vec(ood_answers.len() + self.queries);

		// Fold the OOD constraints (the ze part only) into the accumulator.
		// The privacy-padding part (r') is absorbed by the padding mask
		// oracle pushed below; this keeps main_constraint k-dimensional.
		for (i, ze_constraint) in self
			.ood_ze
			.expanded_constraint(&ood_seeds)
			.into_iter()
			.enumerate()
		{
			constraint += LinearForm::new(ze_constraint) * batch_rand[i];
		}

		// Build the selector vector (one weight per opened position) and
		// pull its image under the transpose of the encoding map.
		//
		// IMPORTANT: use `+=` so duplicate positions accumulate both weights
		// (a plain `=` would overwrite the earlier weight and silently break
		// soundness, since the verifier's `LinearCombinationForm` adds both
		// contributions).
		use super::codeswitch::TransposeCode;
		let mut selector = vec![Goldilocks4::ZERO; input.codeword_len()];
		for (i, &pos) in positions.iter().enumerate() {
			selector[pos] += batch_rand[ood_answers.len() + i];
		}
		constraint += LinearForm::new(input.code().apply_transpose(&selector));

		// Build the padding mask's sl_o and target. sl_o has batch_rand[0..ETA]
		// in its first ETA slots and zeros elsewhere — this picks out the
		// r' = padding_msg[..ETA] entries when evaluated against the mask.
		let mut padding_sl_o = vec![Goldilocks4::ZERO; l_zk_inner];
		padding_sl_o[..ETA].copy_from_slice(&batch_rand[..ETA]);
		let padding_target: Goldilocks4 = padding_sl_o
			.iter()
			.zip(&padding_msg)
			.map(|(a, b)| *a * *b)
			.sum();
		transcript.prover_message(&padding_target);

		// Push the padding mask onto the stack with (α=1, sl_o, target=μ).
		let padding_handle = super::mask_stack::MaskOracleHandle::new_prover(
			padding_msg,
			padding_r,
			padding_vc,
			padding_vc_state,
		);
		mask_stack.push_padding_mask(padding_handle, Goldilocks4::ONE, padding_sl_o);
		// `push_padding_mask` leaves target=ZERO; patch it.
		if let Some(last_mc) = mask_stack.constraints.last_mut() {
			last_mc.target = padding_target;
		}

		// HVZK sumcheck. Carry-in handling: the prover's running sum for the
		// sumcheck is ⟨a, b⟩, which equals the verifier's claim MINUS the
		// carry-in mask contribution mask_carry_in_pre. The verifier
		// subtracts mask_carry_in_pre from its claim before its own HVZK
		// init step; both sides then run prove_sumcheck / verify_sumcheck
		// in sync. After the sumcheck, the verifier adds back ε · carry-in
		// to restore the joint claim. The prover doesn't track claim
		// explicitly; downstream IORs read coefficients/mask_stack.
		let (folded_state, folded_constraint, mask_handles, gammas, epsilon, mask_targets) =
			super::sumcheck::prove_sumcheck_zk(transcript, output, constraint, mask_seed, salt);
		mask_stack.scale_alphas(epsilon);
		mask_stack.push_sumcheck_masks(mask_handles, gammas, mask_targets);
		let folded_constraint = folded_constraint * epsilon;
		(folded_constraint, folded_state)
	}
}

/// Salt builders for the per-codeswitch padding mask derivations.
fn codeswitch_pad_msg_salt(salt: &[u8]) -> Vec<u8> {
	let mut s = salt.to_vec();
	s.extend_from_slice(b"::cs::pad_msg");
	s
}

fn codeswitch_pad_r_salt(salt: &[u8]) -> Vec<u8> {
	let mut s = salt.to_vec();
	s.extend_from_slice(b"::cs::pad_r");
	s
}

/// Runtime-sized WHIR prover specialised to (Goldilocks4 + RS + MerkleVc +
/// OOD).
pub(crate) struct ConcreteWhirProtocol {
	initial_commitment: ProverCommit,
	rounds: Vec<ProverCodeswitch>,
	final_base_case: BaseCase,
	msg_len: usize,
	internal_len: usize,
}

impl ConcreteWhirProtocol {
	/// Build the protocol for a deployment with message length `msg_len`
	/// and HVZK budget `hvzk_budget`. The WHIR-internal Prop. 3.19
	/// ZK-encoded message length is
	/// `internal_len = next_pow2(msg_len + hvzk_budget)`.
	///
	/// Folds by `INTERLEAVING = 4` each round until the inner message length
	/// reaches `threshold` (Jevil uses 64). `queries` is the number of
	/// in-domain Merkle queries per round.
	pub(crate) fn build(
		msg_len: usize,
		hvzk_budget: usize,
		queries: usize,
		threshold: usize,
	) -> Self {
		assert!(msg_len.is_power_of_two(), "msg_len must be a power of two");
		let internal_len = (msg_len + hvzk_budget).next_power_of_two();
		let initial_inner_msg_len = internal_len / INTERLEAVING;
		let initial_commitment = make_commitment(initial_inner_msg_len);

		let mut rounds = Vec::new();
		let mut current_inner_msg_len = initial_inner_msg_len;
		while current_inner_msg_len > threshold {
			let next_inner_msg_len = current_inner_msg_len / INTERLEAVING;
			rounds.push(ProverCodeswitch {
				ood_ze: OodEvader::new(current_inner_msg_len),
				queries,
				output_commitment: make_commitment(next_inner_msg_len),
			});
			current_inner_msg_len = next_inner_msg_len;
		}

		Self {
			initial_commitment,
			rounds,
			final_base_case: BaseCase::new(queries, crate::params::Params::T_ZK),
			msg_len,
			internal_len,
		}
	}

	/// `WHIR.Commit(c, σ) → (root, signer-state)`. Derives the Prop. 3.19
	/// encoding randomness `r_zk ∈ F^{N − M}` from `σ` via the `JV-RZK`
	/// SHAKE256 stream, runs the inner commit-only path, and returns the
	/// 32-byte root and a signer state that the caller caches for fast
	/// signing.
	pub(crate) fn commit(
		&self,
		c: &[Goldilocks4],
		sigma: &[u8; 32],
	) -> ([u8; 32], WhirSignerState) {
		assert_eq!(c.len(), self.msg_len);
		let r_zk = derive_r_zk(sigma, self.internal_len - self.msg_len);
		let mut internal = Vec::with_capacity(self.internal_len);
		internal.extend_from_slice(c);
		internal.extend(r_zk);

		let (root, state) = self.initial_commitment.commit_only(internal.clone());
		(
			root,
			WhirSignerState {
				internal,
				initial_state: Some(state),
			},
		)
	}

	/// `WHIR.Open(st, α_message, v) → π`, with the proof written into the
	/// supplied Fiat–Shamir transcript. `alpha_message` is length-`M`;
	/// this routine embeds it into the WHIR-internal length-`N` wire
	/// format (zero-padding over the encoding-randomness slots — invisible
	/// to the caller).
	///
	/// `mask_seed` is fresh per-signature randomness used to derive the
	/// HVZK masking polynomials (Constructions 6.3 and 7.2 of
	/// eprint 2026/391). Must be unique per signature for HVZK.
	pub(crate) fn prove(
		&self,
		transcript: &mut ProverState,
		state: &WhirSignerState,
		alpha_message: Vec<Goldilocks4>,
		mask_seed: &[u8; 32],
	) {
		assert_eq!(alpha_message.len(), self.msg_len);
		assert_eq!(state.internal.len(), self.internal_len);
		let mut alpha_full = alpha_message;
		alpha_full.resize(self.internal_len, Goldilocks4::ZERO);
		let initial_constraint = LinearForm::new(alpha_full);

		// Each sumcheck commits k mask oracles, runs the HVZK round-poly
		// math, and pushes k masks onto a per-signature mask_stack. Each
		// codeswitch commits its Construction 9.7 padding mask and pushes
		// that onto the stack too. The base case consumes the full stack
		// via the joint Construction 7.2 target check.
		//
		// Initial commit: reuse the cached prover state populated by
		// `WhirSignerState::commit` at keygen time — write the root to the
		// transcript and clone the cached state for this signature's
		// sumcheck. Skips the initial Merkle tree rebuild entirely.
		let cached_initial = state
			.initial_state
			.as_ref()
			.expect("WhirSignerState::initial_state missing; keygen must populate it");
		cached_initial.write_root_to(transcript);
		let initial_state = cached_initial.clone();
		let mut mask_stack = MaskStack::new();

		let (mut folded_state, mut constraint, mask_handles, gammas, epsilon, mask_targets) =
			super::sumcheck::prove_sumcheck_zk(
				transcript,
				initial_state,
				initial_constraint,
				mask_seed,
				b"sumcheck::initial",
			);
		// scale_alphas is a no-op on the empty stack (no carry-in masks).
		mask_stack.scale_alphas(epsilon);
		mask_stack.push_sumcheck_masks(mask_handles, gammas, mask_targets);
		constraint = constraint * epsilon;

		for (round_idx, round) in self.rounds.iter().enumerate() {
			let salt = format!("sumcheck::post-codeswitch-{round_idx}");
			let (next_constraint, next_folded) = round.prove(
				transcript,
				folded_state,
				constraint,
				mask_seed,
				salt.as_bytes(),
				&mut mask_stack,
			);
			folded_state = next_folded;
			constraint = next_constraint;
		}

		// HVZK base case (Construction 7.2). The mask stack contains every
		// sumcheck mask pushed across all sumchecks; the BaseCase consumes
		// them via the joint target check + per-mask local check + codeword
		// consistency.
		let coefficients: Vec<Goldilocks4> = constraint.coefficients().to_vec();
		self.final_base_case.prove(
			transcript,
			folded_state,
			&coefficients,
			&mask_stack,
			mask_seed,
		);
	}
}

// ===========================================================================
// VERIFIER
// ===========================================================================

/// One codeswitch round on the verifier side.
pub(crate) struct VerifierCodeswitch {
	ood_ze: OodEvaderHandle,
	queries: usize,
	output_commitment: VerifierExplicit,
}

impl VerifierCodeswitch {
	/// Verify one codeswitch round + embedded HVZK sumcheck. Subtracts the
	/// carry-in mask contribution from constraint.value before calling
	/// verify_sumcheck (so the sumcheck's HVZK init scales just the main
	/// part by ε), then adds back ε · carry_in to restore the joint claim.
	fn verify(
		&self,
		transcript: &mut VerifierState,
		input: &VerifierFolded,
		constraint: LinearConstraint<FoldedFormHandle<Goldilocks4>>,
		mask_stack: &mut super::mask_stack::MaskStack,
	) -> VerificationResult<(
		LinearConstraint<FoldedFormHandle<Goldilocks4>>,
		VerifierFolded,
	)> {
		let output = ExplicitCodeCommitmentHandle {
			code: self.output_commitment.code.clone(),
			vc: self.output_commitment.vc.clone(),
			commitment: transcript.prover_message()?,
		};

		// Construction 9.7 padding mask root.
		let padding_root: [u8; 32] = transcript.prover_message()?;

		let ood_seeds: Vec<Goldilocks4> = (0..ETA).map(|_| transcript.verifier_message()).collect();
		let ze_constraints = self.ood_ze.zero_evader_handles(&ood_seeds);
		let ood_answers = transcript.prover_messages_vec::<Goldilocks4>(ze_constraints.len())?;
		let positions = sample_positions_verifier(transcript, self.queries, input.codeword_len());

		// In a codeswitch round the queried commitment is the *previous* round's
		// folded interleaved code, so each opening is a length-`INTERLEAVING`
		// vector. The Merkle proof is a BCS multiproof over the sorted-unique
		// queried indices; both sides compute its size from the same indices.
		let path_len_per_opening =
			input.codeword_len().next_power_of_two().trailing_zeros() as usize;
		let mut sorted_unique = positions.clone();
		sorted_unique.sort_unstable();
		sorted_unique.dedup();
		let multiproof_bytes = crate::merkle::multiproof_size(&sorted_unique, path_len_per_opening);
		let openings = read_opening(transcript, self.queries, INTERLEAVING, multiproof_bytes)?;
		let opened = input.verify_openings(&positions, &openings)?;

		let ood_len = ood_answers.len();
		let batch_rand: Vec<Goldilocks4> = (0..ood_len + self.queries)
			.map(|_| transcript.verifier_message())
			.collect();

		let mut value = constraint.value;
		let mut forms: Vec<Box<dyn LinearFormHandle<Alphabet = Goldilocks4>>> =
			vec![Box::new(constraint.linear_form_handle)];
		let mut coeffs = vec![<Goldilocks4 as crate::field::SumcheckField>::ONE];

		for (i, (answer, ze_constraint)) in ood_answers.into_iter().zip(ze_constraints).enumerate()
		{
			value += answer * batch_rand[i];
			forms.push(Box::new(ze_constraint));
			coeffs.push(batch_rand[i]);
		}

		for (i, (&pos, opening)) in positions.iter().zip(opened).enumerate() {
			value += opening * batch_rand[ood_len + i];
			forms.push(Box::new(input.code().apply_transpose_handle(pos)));
			coeffs.push(batch_rand[ood_len + i]);
		}

		// Construction 9.7 padding mask: read its sent target and push onto
		// the mask stack with sl_o = (batch_rand[0..ETA], 0, ..., 0). This
		// captures the OOD answers' privacy-padding contribution into the
		// joint mask formulation so subsequent base case checks balance.
		let padding_target: Goldilocks4 = transcript.prover_message()?;
		let l_zk_inner = crate::params::Params::M_ZK - crate::params::Params::T_ZK;
		let mut padding_sl_o = vec![Goldilocks4::ZERO; l_zk_inner];
		padding_sl_o[..ETA].copy_from_slice(&batch_rand[..ETA]);
		let padding_mask_handle =
			super::mask_stack::MaskOracleHandle::verifier_root_only(padding_root);
		mask_stack.push_padding_mask(
			padding_mask_handle,
			<Goldilocks4 as crate::field::SumcheckField>::ONE,
			padding_sl_o,
		);
		if let Some(last_mc) = mask_stack.constraints.last_mut() {
			last_mc.target = padding_target;
		}

		// Wrap in FoldedFormHandle so the type matches what verify_sumcheck_zk
		// expects (its scale field defaults to ONE here — no additional
		// scaling beyond the LinearCombinationForm batching).
		let mask_carry_in_pre = mask_stack.joint_mask_value();
		let batched_constraint = LinearConstraint {
			linear_form_handle: FoldedFormHandle {
				linear_form_handle: Box::new(LinearCombinationForm {
					linear_form_handles: forms,
					combination_rand: coeffs,
				}),
				rand: Vec::new(),
				scale: <Goldilocks4 as crate::field::SumcheckField>::ONE,
			},
			value: value - mask_carry_in_pre,
		};

		// HVZK sumcheck (Construction 6.3).
		let (folded_output, mut folded_constraint, mask_handles, gammas, epsilon, mask_targets) =
			super::sumcheck::verify_sumcheck_zk(transcript, output, batched_constraint)?;
		// Restore joint claim: add back ε · carry_in_pre. The mask stack
		// alphas then scale by ε so Σ α_i · μ_i (post-scale) = ε · carry_in_pre.
		folded_constraint.value += epsilon * mask_carry_in_pre;
		mask_stack.scale_alphas(epsilon);
		mask_stack.push_sumcheck_masks(mask_handles, gammas, mask_targets);
		Ok((folded_constraint, folded_output))
	}
}

/// Runtime-sized WHIR verifier specialised to (Goldilocks4 + RS + MerkleVc +
/// OOD).
pub(crate) struct ConcreteWhirVerifier {
	initial_commitment: VerifierExplicit,
	rounds: Vec<VerifierCodeswitch>,
	final_base_case: BaseCase,
	msg_len: usize,
	internal_len: usize,
}

impl ConcreteWhirVerifier {
	/// Build the verifier. Parameters must match what
	/// [`ConcreteWhirProtocol::build`] was called with.
	pub(crate) fn build(
		msg_len: usize,
		hvzk_budget: usize,
		queries: usize,
		threshold: usize,
	) -> Self {
		assert!(msg_len.is_power_of_two(), "msg_len must be a power of two");
		let internal_len = (msg_len + hvzk_budget).next_power_of_two();
		let initial_inner_msg_len = internal_len / INTERLEAVING;
		let initial_commitment = make_explicit_handle(initial_inner_msg_len);

		let mut rounds = Vec::new();
		let mut current_inner_msg_len = initial_inner_msg_len;
		while current_inner_msg_len > threshold {
			let next_inner_msg_len = current_inner_msg_len / INTERLEAVING;
			rounds.push(VerifierCodeswitch {
				ood_ze: OodEvaderHandle::new(current_inner_msg_len),
				queries,
				output_commitment: make_explicit_handle(next_inner_msg_len),
			});
			current_inner_msg_len = next_inner_msg_len;
		}

		Self {
			initial_commitment,
			rounds,
			final_base_case: BaseCase::new(queries, crate::params::Params::T_ZK),
			msg_len,
			internal_len,
		}
	}

	/// `WHIR.Verify(root, α_message, v, π)` reading from the supplied
	/// Fiat–Shamir verifier transcript. `alpha_handle` is a length-`M`
	/// [`LinearFormHandle`]; this routine wraps it in a
	/// [`MessageEmbeddedHandle`] that exposes the length-`N` form the
	/// inner sumcheck expects.
	///
	/// `expected_root` is the public-key commitment digest the caller wants
	/// the proof to open against (paper §3.5 Def. 5: WHIR.Verify takes
	/// `root` as an input). The first prover message of the WHIR proof
	/// carries the commit root that was committed under at signing time;
	/// we read it, absorb it into the Fiat–Shamir sponge (so the
	/// downstream challenges depend on it), and only THEN compare it to
	/// `expected_root`. Mismatch → `VerificationError`. Without this
	/// check a malicious signer can commit to an arbitrary polynomial
	/// f' (e.g., satisfying only f'(z) = pk.w) under a self-chosen root
	/// and open it against the verifier, since the Merkle opening
	/// verification at the base case uses the prover-supplied root.
	pub(crate) fn verify<LFH>(
		&self,
		transcript: &mut VerifierState,
		expected_root: [u8; 32],
		alpha_handle: LFH,
		value: Goldilocks4,
	) -> VerificationResult<()>
	where
		LFH: LinearFormHandle<Alphabet = Goldilocks4> + 'static,
	{
		assert_eq!(alpha_handle.form_size(), self.msg_len);
		let nu = self.msg_len.trailing_zeros();
		let nu_prime = self.internal_len.trailing_zeros();
		let embedded = MessageEmbeddedHandle {
			inner: Box::new(alpha_handle),
			nu,
			nu_prime,
		};

		// Read the initial commitment root from the proof, absorb it into
		// the FS sponge via `prover_message`, then bind it to the
		// caller-supplied `expected_root`. The absorption must happen
		// before the equality check so a rejected proof costs the
		// adversary one extra sponge state advancement — not a security
		// requirement but keeps the failure path indistinguishable to
		// reduce reasoning about partial leakage.
		let initial_commitment_root: [u8; 32] = transcript.prover_message()?;
		if initial_commitment_root != expected_root {
			return Err(VerificationError);
		}
		let initial_commitment = ExplicitCodeCommitmentHandle {
			code: self.initial_commitment.code.clone(),
			vc: self.initial_commitment.vc.clone(),
			commitment: initial_commitment_root,
		};

		// Wrap embedded handle in FoldedFormHandle (scale=ONE, empty rand)
		// so verify_sumcheck_zk's input type matches. Initial mask stack
		// is empty → mask_carry_in_pre = 0 → no subtraction.
		let wrapped_initial = LinearConstraint {
			linear_form_handle: FoldedFormHandle {
				linear_form_handle: Box::new(embedded),
				rand: Vec::new(),
				scale: <Goldilocks4 as crate::field::SumcheckField>::ONE,
			},
			value,
		};

		let mut mask_stack = super::mask_stack::MaskStack::new();
		let (mut folded_commitment, mut constraint, mask_handles, gammas, epsilon, mask_targets) =
			super::sumcheck::verify_sumcheck_zk(transcript, initial_commitment, wrapped_initial)?;
		mask_stack.scale_alphas(epsilon); // no-op (empty)
		mask_stack.push_sumcheck_masks(mask_handles, gammas, mask_targets);

		for round in &self.rounds {
			let (next_constraint, next_folded) =
				round.verify(transcript, &folded_commitment, constraint, &mut mask_stack)?;
			constraint = next_constraint;
			folded_commitment = next_folded;
		}

		// HVZK base case (Construction 7.2 with non-empty mask stack).
		verify_base_case(
			transcript,
			self.final_base_case.queries,
			self.final_base_case.mask_queries,
			folded_commitment,
			constraint,
			&mask_stack.oracles,
			&mask_stack.constraints,
		)
	}
}

// ---------------------------------------------------------------------------
// Constructor helpers
// ---------------------------------------------------------------------------

fn make_commitment(inner_msg_len: usize) -> ProverCommit {
	let rs = ReedSolomon::<Goldilocks4>::new(inner_msg_len);
	let code = Arc::new(InterleavedCode::new(rs, INTERLEAVING));
	let vc = Arc::new(MerkleVc::new(inner_msg_len * RATE_INV));
	CodeCommitment::new(code, vc)
}

fn make_explicit_handle(inner_msg_len: usize) -> VerifierExplicit {
	let rs = ReedSolomon::<Goldilocks4>::new(inner_msg_len);
	let code = Arc::new(InterleavedCode::new(rs, INTERLEAVING));
	let vc = Arc::new(MerkleVc::new(inner_msg_len * RATE_INV));
	ExplicitCodeCommitmentHandle::new(code, vc, <[u8; 32]>::default())
}

// ===========================================================================
// Length-M API support types
// ===========================================================================

/// Concrete prover state held by [`WhirSignerState::initial_state`]:
/// the encoded codeword + initial Merkle tree at the WHIR-internal length.
pub(crate) type ProverCommitState = super::commitment::CodeCommitmentProverState<
	super::code::InterleavedCode<super::code::ReedSolomon<Goldilocks4>>,
	super::vc::MerkleVc,
>;

/// Cached signer state returned by [`ConcreteWhirProtocol::commit`].
///
/// Holds the WHIR-internal length-`N` data vector (`internal`, retained
/// for the `SignerCache::from_secret` rebuild path) plus the cached
/// initial prover state (`initial_state` — encoded codeword + initial
/// Merkle tree). Caching `initial_state` lets `sign` skip rebuilding
/// the largest Merkle tree of the protocol on every signature; the tree
/// contents are public-derivable from the published `root`, so caching
/// is sound. Treat as opaque from outside this module.
pub(crate) struct WhirSignerState {
	pub(crate) internal: Vec<Goldilocks4>,
	pub(crate) initial_state: Option<ProverCommitState>,
}

/// Embed a length-`M` [`LinearFormHandle`] into the WHIR primitive's
/// length-`N` wire format. The MLE of the embedded vector
/// `(u_0, …, u_{M-1}, 0, …, 0) ∈ F^N` factors as the inner length-`M`
/// MLE times `∏_{j=ν+1}^{ν'}(1 − r_j)` (the trailing-pad product). Under
/// WHIR's MSB-first fold convention, the first `ν' − ν` folds bind the
/// trailing-pad variables and contribute the pad scalar; any further
/// folds delegate to the inner handle.
pub(crate) struct MessageEmbeddedHandle<F: Field> {
	inner: Box<dyn LinearFormHandle<Alphabet = F>>,
	nu: u32,
	nu_prime: u32,
}

impl<F: Field> LinearFormHandle for MessageEmbeddedHandle<F> {
	type Alphabet = F;

	fn form_size(&self) -> usize {
		1usize << self.nu_prime
	}

	fn folded_form(&self, rand: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
		let r = rand.len();
		let pad_total = (self.nu_prime - self.nu) as usize;
		let pad_rounds_bound = r.min(pad_total);

		// First `pad_rounds_bound` entries of `rand` (MSB-first) bind the
		// pad-region variables; each contributes a `(1 - r_i)` factor.
		let mut pad_scalar = F::ONE;
		for &r_i in &rand[..pad_rounds_bound] {
			pad_scalar *= F::ONE - r_i;
		}
		let inner_rand = &rand[pad_rounds_bound..];
		let inner_folded = self.inner.folded_form(inner_rand);

		if pad_rounds_bound < pad_total {
			// Pad-region not fully bound. Output has leading 2^ν entries
			// = inner * pad_scalar, trailing entries = 0.
			let output_len = 1usize << (self.nu_prime as usize - r);
			let mut out = vec![F::ZERO; output_len];
			for (i, &x) in inner_folded.iter().enumerate() {
				out[i] = pad_scalar * x;
			}
			out
		} else {
			// All pad rounds bound; scale inner by pad_scalar.
			inner_folded.iter().map(|&x| pad_scalar * x).collect()
		}
	}
}

/// Derive `count` uniform `Goldilocks4` entries from
/// `SHAKE256(JV-RZK ‖ σ)` with per-limb rejection sampling. This is the
/// Prop. 3.19 encoding randomness that [`ConcreteWhirProtocol::commit`]
/// samples internally.
fn derive_r_zk(sigma: &[u8; 32], count: usize) -> Vec<Goldilocks4> {
	crate::hash::shake_field_elements(JV_RZK, &[sigma], count)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::alpha::BatchedAlpha;
	use crate::field::Goldilocks;
	use crate::lift::MonomialLift;

	fn g(n: u64) -> Goldilocks4 {
		Goldilocks4::new([
			Goldilocks::new(n),
			Goldilocks::new(0),
			Goldilocks::new(0),
			Goldilocks::new(0),
		])
	}

	fn manual_fold(mut v: Vec<Goldilocks4>, rand: &[Goldilocks4]) -> Vec<Goldilocks4> {
		for &w in rand {
			let half = v.len() / 2;
			let mut new = Vec::with_capacity(half);
			for k in 0..half {
				new.push(v[k] + (v[k + half] - v[k]) * w);
			}
			v = new;
		}
		v
	}

	#[test]
	fn embedded_handle_matches_zero_padded_explicit_fold() {
		for (nu, nu_prime) in [(2u32, 4), (3, 5), (4, 6), (4, 9), (5, 7)] {
			for k in [1usize, 2, 4] {
				let xs: Vec<Goldilocks4> = (0..k).map(|i| g(7 + i as u64)).collect();
				let betas: Vec<Goldilocks4> = (0..k).map(|i| g(101 + i as u64)).collect();
				let alpha = BatchedAlpha::new(&xs, betas.clone(), nu);
				let embedded = MessageEmbeddedHandle {
					inner: Box::new(alpha),
					nu,
					nu_prime,
				};

				let n = 1usize << nu_prime;
				let m = 1usize << nu;
				let mut explicit = vec![Goldilocks4::ZERO; n];
				for (x, &beta) in xs.iter().zip(betas.iter()) {
					let lift = MonomialLift::new(*x, nu);
					let u = lift.materialize();
					assert_eq!(u.len(), m);
					for (a, &uk) in explicit.iter_mut().take(m).zip(u.iter()) {
						*a += beta * uk;
					}
				}

				for r in 0..=nu_prime {
					let rand: Vec<Goldilocks4> = (0..r).map(|i| g(2000 + i as u64)).collect();
					let symbolic = embedded.folded_form(&rand);
					let ref_fold = manual_fold(explicit.clone(), &rand);
					assert_eq!(symbolic, ref_fold, "ν={nu} ν'={nu_prime} K={k} R={r}");
				}
			}
		}
	}

	#[test]
	fn derive_r_zk_is_deterministic() {
		let sigma = [9u8; 32];
		let a = derive_r_zk(&sigma, 100);
		let b = derive_r_zk(&sigma, 100);
		assert_eq!(a, b);
		assert_eq!(a.len(), 100);
	}

	#[test]
	fn derive_r_zk_distinct_seeds_diverge() {
		let a = derive_r_zk(&[0u8; 32], 10);
		let b = derive_r_zk(&[1u8; 32], 10);
		assert_ne!(a, b);
	}
}
