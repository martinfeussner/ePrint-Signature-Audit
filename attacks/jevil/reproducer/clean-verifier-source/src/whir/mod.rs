//! WHIR — Reed–Solomon-proximity-test IOP used as Jevil's polynomial
//! commitment.
//!
//! This module is **crate-private**: external callers should never depend on
//! its types. The only Jevil-relevant operations on WHIR are
//!
//! 1. *commit* to a length-`M` coefficient vector (run during [`crate::keygen`]),
//! 2. *open* a linear-form claim `⟨c, α⟩ = v` (run during [`crate::sign`]),
//! 3. *verify* that opening against a public commitment root (run during
//!    [`crate::verify`]).
//!
//! See the paper §3.5 (`def:whir`) for the full WHIR API contract. The
//! API exposed here matches it byte-for-byte: callers pass length-`M`
//! vectors and a 32-byte seed; the Prop. 3.19 encoding randomness lives
//! entirely inside this module and never appears at the boundary. The
//! implementation is hard-specialised to the Jevil setting:
//!
//! - field: [`crate::field::Goldilocks4`];
//! - inner code: rate-1/4 [`code::ReedSolomon`] wrapped in
//!   [`code::InterleavedCode`] (factor 4);
//! - vector commitment: Poseidon2-Goldilocks Merkle tree
//!   ([`vc::MerkleVc`]);
//! - zero evader: DEEP-FRI out-of-domain (`OodEvader`);
//! - sumcheck: degree-2 inner-product, MSB half-split fold;
//! - fold cap: stop folding at inner message length `2⁶ = 64`;
//! - in-domain queries per round: 64 (configurable through
//!   [`protocol::ConcreteWhirProtocol::build`]).

pub(crate) mod base_case;
pub(crate) mod code;
pub(crate) mod codeswitch;
pub(crate) mod commitment;
pub(crate) mod encoding;
pub(crate) mod evader;
pub(crate) mod linear_form;
pub(crate) mod mask_stack;
pub(crate) mod protocol;
pub(crate) mod sumcheck;
pub(crate) mod transcript_io;
pub(crate) mod vc;

pub(crate) use linear_form::LinearFormHandle;
pub(crate) use protocol::{ConcreteWhirProtocol, ConcreteWhirVerifier, WhirSignerState};
