//! Domain-tagged hashing.
//!
//! Jevil uses three random-oracle-modelled primitives, paper §3.4:
//!
//! - [`hash_vc_leaf`] / [`hash_vc_node`]: **H_VC**, a Poseidon2-Goldilocks-12
//!   compression function with leaf-vs-node IV separation. Used *only* inside
//!   zk-WHIR as the binary Merkle tree's leaf and internal-node hash.
//! - [`hash`] (the only family below, SHAKE256): **H_xof**. Used for seed
//!   expansion, position derivation, Fiat–Shamir batching, the per-signature
//!   prover-randomness derivation, and the OOD binding-point derivation.
//! - A third primitive, **H_fs** (SHAKE128 via spongefish), is used inside
//!   zk-WHIR for its own Fiat–Shamir transcript. It has no jevil-side
//!   callsites and is therefore not exposed by this module.
//!
//! Every [`hash`] invocation is prefixed by an 8-byte ASCII *domain tag*
//! selecting one of seven disjoint H_xof domains (paper §3.4). The tags
//! are exposed as module-level constants below. An eighth label
//! [`JV_WHIR`] is reserved as the H_VC capacity-IV constituent and never
//! addresses H_xof.
//!
//! ## Serialisation format
//!
//! `hash(family, tag, [x₁, x₂, …, xₖ]; L)` returns the first `L` output bytes
//! of `family` applied to
//!
//! ```text
//! tag ‖ len_8(x₁) ‖ x₁ ‖ len_8(x₂) ‖ x₂ ‖ … ‖ len_8(xₖ) ‖ xₖ
//! ```
//!
//! where `len_8(x)` is the byte length of `x` encoded as an 8-byte
//! little-endian unsigned integer. The length prefix is what makes the
//! framing *injective*: concatenating two inputs of different lengths can
//! never produce the same serialised buffer as concatenating two of any other
//! lengths.

use std::sync::OnceLock;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_12};
use p3_symmetric::Permutation;
use shake::{ExtendableOutput, Shake256, Update, XofReader};

// ---------------------------------------------------------------------------
// Domain tags (paper §3.4, Table 3)
// ---------------------------------------------------------------------------

/// Domain tag for the seed-derived polynomial coefficients (XOF).
pub(crate) const JV_SEED: [u8; 8] = *b"JV-SEED ";
/// Domain tag for the seed-derived ZK encoding randomness (Prop. 3.19 of
/// eprint 2026/391). Used **only** at `KeyGen` to extend the committed
/// message from `M` to `N` before NTT encoding so that any subset of
/// ≤ `N − M` codeword positions reveals nothing about the honest
/// coefficients. Per-signature prover-side randomness uses [`JV_OPRD`].
pub(crate) const JV_RZK: [u8; 8] = *b"JV-RZK  ";
/// Domain tag for per-message position derivation (XOF).
pub(crate) const JV_POSN: [u8; 8] = *b"JV-POSN ";
/// Domain tag for the Fiat–Shamir batching challenges (XOF).
pub(crate) const JV_FSCH: [u8; 8] = *b"JV-FSCH ";
/// Domain tag for WHIR's internal vector commitment (Poseidon2).
pub(crate) const JV_WHIR: [u8; 8] = *b"JV-WHIR ";
/// Domain tag for the WHIR transcript's instance-bytes prefix
/// ([`crate::transcript::prefix_bytes`]). Not used as input to a hash
/// invocation — consumed only by the Fiat–Shamir layer as the leading
/// 8 bytes of the binding prefix per paper §4.2 step 4 / §4.3 step 3.
pub(crate) const JV_OPEN: [u8; 8] = *b"JV-OPEN ";
/// Domain tag for the per-signature prover-randomness derivation (XOF).
/// Used by [`crate::sign`] to derive a deterministic seed from
/// `(s, root, msg, y_1, …, y_K)` per paper §3.4 / §4.3 Construction 2 step 7; the resulting
/// seed feeds **all** internal randomness consumed by `WHIR.Open` — sumcheck
/// round-polynomial masks (Construction 6.3), code-switching mask oracles
/// (Construction 9.7), and OOD answers (Lemma 9.3) — so that `Sign` is a
/// pure function of `(sk, pk, msg)` rather than a sampler. The trailing two
/// `0x20` bytes pad the seven-character `JV-OPRD` ASCII tag out to the
/// fixed 8-byte slot.
pub(crate) const JV_OPRD: [u8; 8] = *b"JV-OPRD ";
/// Domain tag for the OOD binding point derivation (XOF). Used by
/// [`crate::keygen`] to derive the out-of-domain point `z ∈ F` from
/// `mathsf{root}` and by [`crate::verify`] to re-derive the same `z`
/// (the signer never transmits it). Bound by the OOD value `w = f(z)`
/// stored in the public key, this collapses an outsider's cap-binding
/// extraction from "needs ≥ ⌈M/K⌉ accepting signatures" to "one accepting
/// signature suffices" (paper §6.1, Theorem 3). The trailing three
/// `0x20` bytes pad the five-character `JV-OOD` ASCII tag out to the
/// fixed 8-byte slot.
pub(crate) const JV_OOD: [u8; 8] = *b"JV-OOD  ";

// ---------------------------------------------------------------------------
// H_VC capacity-IV constituent (paper §3.4)
// ---------------------------------------------------------------------------

/// `JV-WHIR ` ASCII bytes interpreted as a little-endian `u64`. Derived
/// from the spec's [`JV_WHIR`] tag bytes; below the Goldilocks modulus
/// `q_0`, so `Goldilocks::from_u64` is the identity reduction.
const G_WHIR_U64: u64 = u64::from_le_bytes(JV_WHIR);

const _: () = assert!(
	G_WHIR_U64 < Goldilocks::ORDER_U64,
	"JV-WHIR tag bytes as u64-LE must fit canonically in Goldilocks"
);

/// Cached `(IV_leaf, IV_node)` per spec §3.4. The capacity portion of H_VC's
/// state (slots 8..12) is set to one of these two IVs at the start of every
/// invocation; the `0` vs `1` in slot 9 is the leaf-versus-internal-node
/// domain separator.
fn h_vc_ivs() -> &'static ([Goldilocks; 4], [Goldilocks; 4]) {
	use std::sync::OnceLock;
	static CELL: OnceLock<([Goldilocks; 4], [Goldilocks; 4])> = OnceLock::new();
	CELL.get_or_init(|| {
		let g = Goldilocks::from_u64(G_WHIR_U64);
		let z = Goldilocks::ZERO;
		let leaf = [g, z, z, z];
		let node = [g, Goldilocks::from_u64(1), z, z];
		(leaf, node)
	})
}

// ---------------------------------------------------------------------------
// Length-prefixed domain-tagged hash (SHAKE256)
// ---------------------------------------------------------------------------

/// Hash a sequence of byte-string inputs with SHAKE256, prefixing the
/// canonical 8-byte domain `tag` and the length-prefix framing described
/// in the module docs. Returns exactly `out_len` output bytes.
pub(crate) fn hash(tag: [u8; 8], inputs: &[&[u8]], out_len: usize) -> Vec<u8> {
	let mut reader = shake256_xof(tag, inputs);
	let mut out = vec![0u8; out_len];
	reader.read(&mut out);
	out
}

/// Pull `count` uniform `Goldilocks4` elements from the SHAKE256 XOF
/// stream `SHAKE256(tag ‖ len_8(x_1) ‖ x_1 ‖ … )` with per-limb rejection
/// sampling. Realises paper §3.2/§4.1 step 2's "from H_xof(tag, …; ∞)"
/// language literally: a single open-ended SHAKE squeeze fed by the
/// canonical framing, with 32-byte chunks parsed as four little-endian
/// Goldilocks limbs and rejected if any limb is `≥ q_0`.
pub(crate) fn shake_field_elements(
	tag: [u8; 8],
	inputs: &[&[u8]],
	count: usize,
) -> Vec<crate::field::Goldilocks4> {
	if count == 0 {
		return Vec::new();
	}
	let mut reader = shake256_xof(tag, inputs);
	let mut out = Vec::with_capacity(count);
	let mut chunk = [0u8; 32];
	while out.len() < count {
		reader.read(&mut chunk);
		if let Some(g) = crate::field::Goldilocks4::from_bytes(&chunk) {
			out.push(g);
		}
	}
	out
}

/// Initialise a SHAKE256 XOF reader over `tag ‖ len_8(x_1) ‖ x_1 ‖ …`.
/// The caller can squeeze any number of bytes; the framing matches
/// [`hash`] exactly so single-shot and streamed callers agree on the
/// first N bytes for every N.
///
/// The `use<>` capture clause is explicit: the returned reader owns its
/// state and does NOT borrow from `inputs`, so callers can pass
/// short-lived `&[&[u8]]` slices like `&[root, msg]` without lifetime
/// gymnastics.
pub(crate) fn shake256_xof(tag: [u8; 8], inputs: &[&[u8]]) -> impl XofReader + use<> {
	let mut hasher = Shake256::default();
	hasher.update(&tag);
	for input in inputs {
		hasher.update(&(input.len() as u64).to_le_bytes());
		hasher.update(input);
	}
	hasher.finalize_xof()
}

// ---------------------------------------------------------------------------
// Poseidon2-Goldilocks-12 — state-width / rate constants shared by H_VC
// ---------------------------------------------------------------------------

/// Permutation state width (field elements).
const POSEIDON2_WIDTH: usize = 12;
/// Rate in field elements (8 → 64 bytes per absorb).
const POSEIDON2_RATE: usize = 8;

/// The shared Poseidon2-Goldilocks-12 permutation, constructed once on first
/// use and reused for every H_VC invocation.
///
/// `default_goldilocks_poseidon2_12()` allocates and copies the full round-
/// constant tables on every call (six heap allocations on aarch64's fused
/// path). H_VC runs once per Merkle leaf **and** once per internal node, i.e.
/// `≈ 2·N` times per `WHIR.Commit` (up to `≈ 2^22` at the largest deployment),
/// so rebuilding the permutation per call dominated commit time. The
/// permutation is immutable (`permute_mut` takes `&self`) and `Sync`, so a
/// process-wide singleton is safe.
fn poseidon2_perm() -> &'static Poseidon2Goldilocks<12> {
	static CELL: OnceLock<Poseidon2Goldilocks<12>> = OnceLock::new();
	CELL.get_or_init(default_goldilocks_poseidon2_12)
}

/// Deserialise 8 little-endian bytes into a canonical `Goldilocks` element.
#[inline]
fn bytes_to_goldilocks(chunk: &[u8]) -> Goldilocks {
	let raw = u64::from_le_bytes(chunk.try_into().unwrap());
	let v = if raw >= Goldilocks::ORDER_U64 {
		raw - Goldilocks::ORDER_U64
	} else {
		raw
	};
	Goldilocks::from_u64(v)
}

// ---------------------------------------------------------------------------
// H_VC: Poseidon2-Goldilocks-12 compression function (paper §3.4)
// ---------------------------------------------------------------------------

/// H_VC^leaf per paper §3.4. Absorbs `symbols` as a flat sequence of
/// base-field limbs (in `Goldilocks4.c` order, canonical little-endian),
/// rate-8 chunks, zero-pad to a multiple of the rate, capacity IV =
/// `IV_leaf`. Output is the first 4 state limbs as 32 bytes little-endian.
pub(crate) fn hash_vc_leaf(symbols: &[crate::field::Goldilocks4]) -> [u8; 32] {
	let perm = poseidon2_perm();
	let (iv_leaf, _) = h_vc_ivs();

	let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
	state[POSEIDON2_RATE..].copy_from_slice(iv_leaf.as_slice());

	// Stream limbs in canonical order: symbols[0].c[0..4], symbols[1].c[0..4], …
	let total_limbs = symbols.len() * 4;
	let padded_limbs = total_limbs.div_ceil(POSEIDON2_RATE) * POSEIDON2_RATE;
	let mut flat: Vec<Goldilocks> = Vec::with_capacity(padded_limbs);
	for s in symbols {
		flat.extend_from_slice(&s.c);
	}
	flat.resize(padded_limbs, Goldilocks::ZERO);

	for chunk in flat.chunks_exact(POSEIDON2_RATE) {
		for (i, &elem) in chunk.iter().enumerate() {
			state[i] += elem;
		}
		perm.permute_mut(&mut state);
	}

	let mut out = [0u8; 32];
	for (i, elem) in state[..4].iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&elem.as_canonical_u64().to_le_bytes());
	}
	out
}

/// H_VC^node per paper §3.4. One-permutation compression of two 32-byte
/// child digests. Capacity IV = `IV_node`.
pub(crate) fn hash_vc_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	let perm = poseidon2_perm();
	let (_, iv_node) = h_vc_ivs();

	let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
	for (i, chunk) in left.chunks_exact(8).enumerate() {
		state[i] = bytes_to_goldilocks(chunk);
	}
	for (i, chunk) in right.chunks_exact(8).enumerate() {
		state[4 + i] = bytes_to_goldilocks(chunk);
	}
	state[POSEIDON2_RATE..].copy_from_slice(iv_node.as_slice());

	perm.permute_mut(&mut state);

	let mut out = [0u8; 32];
	for (i, elem) in state[..4].iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&elem.as_canonical_u64().to_le_bytes());
	}
	out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn xof_is_deterministic() {
		let a = hash(JV_POSN, &[b"hello"], 32);
		let b = hash(JV_POSN, &[b"hello"], 32);
		assert_eq!(a, b);
	}

	#[test]
	fn domain_tags_separate() {
		let a = hash(JV_SEED, &[b"x"], 32);
		let b = hash(JV_POSN, &[b"x"], 32);
		assert_ne!(a, b);
	}

	#[test]
	fn variable_output_length() {
		let a = hash(JV_POSN, &[b"x"], 16);
		let b = hash(JV_POSN, &[b"x"], 64);
		assert_eq!(a.len(), 16);
		assert_eq!(b.len(), 64);
		assert_eq!(&a[..], &b[..16]);
	}

	#[test]
	fn length_prefix_is_injective_under_concat() {
		// Without a length prefix, ("abcd", "ef") and ("abc", "def") would
		// collide. With our framing they cannot.
		let a = hash(JV_POSN, &[b"abcd", b"ef"], 32);
		let b = hash(JV_POSN, &[b"abc", b"def"], 32);
		assert_ne!(a, b);
	}

	#[test]
	fn spec_tags_are_present() {
		// Per paper §3.4: 8-byte ASCII strings right-padded with 0x20 (space).
		assert_eq!(&JV_SEED, b"JV-SEED ");
		assert_eq!(&JV_RZK, b"JV-RZK  ");
		assert_eq!(&JV_POSN, b"JV-POSN ");
		assert_eq!(&JV_FSCH, b"JV-FSCH ");
		assert_eq!(&JV_WHIR, b"JV-WHIR ");
		assert_eq!(&JV_OPEN, b"JV-OPEN ");
		assert_eq!(&JV_OPRD, b"JV-OPRD ");
		assert_eq!(&JV_OOD, b"JV-OOD  ");
		// Pairwise distinct as 8-byte strings.
		let tags: [&[u8; 8]; 8] = [
			&JV_SEED, &JV_RZK, &JV_POSN, &JV_FSCH, &JV_WHIR, &JV_OPEN, &JV_OPRD, &JV_OOD,
		];
		for i in 0..tags.len() {
			for j in (i + 1)..tags.len() {
				assert_ne!(tags[i], tags[j]);
			}
		}
	}

	#[test]
	fn hash_vc_leaf_is_deterministic() {
		use crate::field::Goldilocks4;
		let leaf = vec![
			Goldilocks4::new([
				Goldilocks::new(1),
				Goldilocks::new(2),
				Goldilocks::new(3),
				Goldilocks::new(4),
			]),
			Goldilocks4::new([
				Goldilocks::new(5),
				Goldilocks::new(6),
				Goldilocks::new(7),
				Goldilocks::new(8),
			]),
		];
		let a = hash_vc_leaf(&leaf);
		let b = hash_vc_leaf(&leaf);
		assert_eq!(a, b);
	}

	#[test]
	fn hash_vc_leaf_distinguishes_inputs() {
		use crate::field::Goldilocks4;
		let a = vec![Goldilocks4::new([Goldilocks::new(1); 4])];
		let b = vec![Goldilocks4::new([Goldilocks::new(2); 4])];
		assert_ne!(hash_vc_leaf(&a), hash_vc_leaf(&b));
	}

	#[test]
	fn hash_vc_node_is_deterministic_and_input_sensitive() {
		let l = [7u8; 32];
		let r = [9u8; 32];
		assert_eq!(hash_vc_node(&l, &r), hash_vc_node(&l, &r));
		assert_ne!(hash_vc_node(&l, &r), hash_vc_node(&r, &l));
	}

	#[test]
	fn hash_vc_leaf_and_node_are_domain_separated() {
		// A 2-G4 leaf has 8 base-field limbs of input, same total absorbed
		// width as an internal node's 8 limbs. The IV separator (capacity
		// slot 9: 0 for leaf, 1 for node) must produce different outputs
		// even if the input limb sequence matches.
		use crate::field::Goldilocks4;
		let leaf_symbols = vec![
			Goldilocks4::new([
				Goldilocks::new(1),
				Goldilocks::new(2),
				Goldilocks::new(3),
				Goldilocks::new(4),
			]),
			Goldilocks4::new([
				Goldilocks::new(5),
				Goldilocks::new(6),
				Goldilocks::new(7),
				Goldilocks::new(8),
			]),
		];
		let leaf_out = hash_vc_leaf(&leaf_symbols);

		let mut left = [0u8; 32];
		let mut right = [0u8; 32];
		for (i, v) in (1u64..=4).enumerate() {
			left[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
		}
		for (i, v) in (5u64..=8).enumerate() {
			right[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
		}
		let node_out = hash_vc_node(&left, &right);

		assert_ne!(leaf_out, node_out, "IV domain separation failed");
	}
}
