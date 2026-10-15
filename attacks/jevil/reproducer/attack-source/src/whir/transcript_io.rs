//! Inline (de)serialisation of `Opening<MerkleVc>` against a spongefish
//! transcript, plus position-sampling helpers shared between sumcheck rounds.
//!
//! The opening data is written *inline* into the transcript NARG string
//! between the query-position sample and the batching-randomness draw. The
//! verifier reads it back from the same offset.

use spongefish::{ProverState, VerificationError, VerificationResult, VerifierState};

use super::vc::{MerkleVc, Opening};
use crate::field::Goldilocks4;

// ---------------------------------------------------------------------------
// Opening (de)serialisation
// ---------------------------------------------------------------------------

/// Write an `Opening<MerkleVc>` into the prover transcript. Layout:
///
/// ```text
/// n_vals : u32 LE      -- number of opened positions
/// n_sym  : u32 LE      -- symbols per position (interleaving factor)
/// symbols: n_vals · n_sym · 32 bytes (each Goldilocks4 to_bytes)
/// path_len : u32 LE    -- total length of the Merkle-path concatenation
/// path   : path_len · 32 bytes
/// ```
pub(crate) fn write_opening(transcript: &mut ProverState, opening: &Opening<MerkleVc>) {
	let n_vals = opening.openings.len() as u32;
	transcript.prover_message(&n_vals.to_le_bytes());

	let n_sym: u32 = if opening.openings.is_empty() {
		0
	} else {
		opening.openings[0].len() as u32
	};
	transcript.prover_message(&n_sym.to_le_bytes());

	for symbols in &opening.openings {
		for sym in symbols {
			transcript.prover_message(&sym.to_bytes());
		}
	}

	let path_len = opening.vc_proof.len() as u32;
	transcript.prover_message(&path_len.to_le_bytes());
	for h in &opening.vc_proof {
		transcript.prover_message(h);
	}
}

/// Read an `Opening<MerkleVc>` back from the verifier transcript.
///
/// Mirrors [`write_opening`] exactly. The verifier passes the protocol-known
/// `expected_n_vals` (= number of queried positions), `expected_n_sym`
/// (= interleaving factor of the VC alphabet), and `expected_path_len`
/// (= `n_vals · log₂(codeword_len_padded)`) so that adversary-controlled
/// header values can't drive runaway allocations: any mismatch short-circuits
/// to `VerificationError` *before* any `Vec::with_capacity`.
pub(crate) fn read_opening(
	transcript: &mut VerifierState,
	expected_n_vals: usize,
	expected_n_sym: usize,
	expected_path_len: usize,
) -> VerificationResult<Opening<MerkleVc>> {
	let n_vals_bytes: [u8; 4] = transcript.prover_message()?;
	let n_vals = u32::from_le_bytes(n_vals_bytes) as usize;
	if n_vals != expected_n_vals {
		return Err(VerificationError);
	}

	let n_sym_bytes: [u8; 4] = transcript.prover_message()?;
	let n_sym = u32::from_le_bytes(n_sym_bytes) as usize;
	if n_sym != expected_n_sym {
		return Err(VerificationError);
	}

	let mut openings: Vec<Vec<Goldilocks4>> = Vec::with_capacity(n_vals);
	for _ in 0..n_vals {
		let mut symbols: Vec<Goldilocks4> = Vec::with_capacity(n_sym);
		for _ in 0..n_sym {
			let bytes: [u8; 32] = transcript.prover_message()?;
			let sym = Goldilocks4::from_bytes(&bytes).ok_or(VerificationError)?;
			symbols.push(sym);
		}
		openings.push(symbols);
	}

	let path_len_bytes: [u8; 4] = transcript.prover_message()?;
	let path_len = u32::from_le_bytes(path_len_bytes) as usize;
	if path_len != expected_path_len {
		return Err(VerificationError);
	}

	let mut vc_proof: Vec<[u8; 32]> = Vec::with_capacity(path_len);
	for _ in 0..path_len {
		let h: [u8; 32] = transcript.prover_message()?;
		vc_proof.push(h);
	}

	Ok(Opening { openings, vc_proof })
}

// ---------------------------------------------------------------------------
// Position sampling
// ---------------------------------------------------------------------------

/// Sample `count` uniformly random positions in `[0, domain_size)` from the
/// prover transcript by drawing `u64` challenges and reducing modulo
/// `domain_size`.
pub(crate) fn sample_positions_prover(
	transcript: &mut ProverState,
	count: usize,
	domain_size: usize,
) -> Vec<usize> {
	transcript
		.verifier_messages_vec(count)
		.into_iter()
		.map(|i: u64| (i % domain_size as u64) as usize)
		.collect()
}

/// Verifier counterpart of [`sample_positions_prover`].
pub(crate) fn sample_positions_verifier(
	transcript: &mut VerifierState,
	count: usize,
	domain_size: usize,
) -> Vec<usize> {
	(0..count)
		.map(|_| {
			let position: u64 = transcript.verifier_message();
			(position % domain_size as u64) as usize
		})
		.collect()
}
