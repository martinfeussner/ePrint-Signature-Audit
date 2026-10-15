//! Errors returned by Jevil signature operations.

/// The error type returned by [`crate::verify`] and the byte parsers.
///
/// `Error` is intentionally coarse-grained. Verification failure produces a
/// single [`Error::VerificationFailed`] variant regardless of *which* check
/// failed — this is by design, so that a verifier cannot reveal partial
/// information about why a forged signature was rejected. Parser-only errors
/// (length mismatch, non-canonical field element) carry their own variants so
/// honest callers can distinguish bad I/O from cryptographic failure.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
	/// The `Params` supplied to [`crate::verify`] disagree with the public key
	/// — typically because the verifier was given the wrong `n_star`.
	#[error("verifier params do not match the public key's n_star")]
	ParamsMismatch,

	/// A serialised signature did not contain the leading `K · 32` y-bytes,
	/// or [`crate::verify`] was handed a [`crate::Signature`] whose
	/// `y_values.len()` differs from `Params::K`. (The 36-byte public key
	/// parser cannot fail with this — its input is a fixed-size array.)
	#[error("serialised input has the wrong length")]
	InvalidLength,

	/// A 32-byte chunk of `Signature::y_values` did not decode to a canonical
	/// Goldilocks-extension element (some 8-byte limb was ≥ the prime).
	#[error("non-canonical field element in signature")]
	NonCanonicalField,

	/// The signature failed verification. This is the catch-all cryptographic
	/// failure mode: it covers tampered y-values, malformed proofs, wrong
	/// messages, and any internal WHIR-level check that rejected.
	#[error("signature verification failed")]
	VerificationFailed,
}
