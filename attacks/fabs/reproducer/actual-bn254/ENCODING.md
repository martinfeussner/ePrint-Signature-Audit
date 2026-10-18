# Declared oracle encodings

## H0

H0 uses SHA-256 with domain bytes
`FABS-2026-022/H0/ARK-BN254/v1\0`.  The domain is followed by a big-endian
32-bit tuple arity (7), then the ordered fields A, B, C, Y, Z, W, and message.
Each field is encoded as a one-byte positional/type tag, a big-endian 64-bit
byte length, and its payload.  Tags 01/02/06 are compressed canonical
Arkworks G1 affine encodings, tag 03 is compressed canonical G2 affine, tags
04/05 are compressed canonical PairingOutput encodings, and tag 07 is the
message byte string.  The SHA-256 digest is interpreted big endian and reduced
modulo the BN254 scalar modulus.

## H1

H1 is a deterministic public try-and-increment map to BN254 G1.  For counter
`j=0,1,...`, SHA-256 hashes domain
`FABS-2026-022/H1/ARK-BN254/v1\0`, the big-endian 64-bit attribute length, the
attribute bytes, and big-endian 32-bit `j`.  The digest is interpreted big
endian modulo the BN254 base-field modulus as x.  If `x^3+3` is a square, its
root with parity equal to the low digest bit is selected; otherwise the
counter advances.  BN254 G1 has cofactor one; the implementation nevertheless
asserts on-curve and prime-subgroup membership and rejects identity.

This deterministic map is local test plumbing, not a claim of Charm/PBC,
author codec, RFC hash-to-curve, or byte-level conformance.  The attack does
not use or know discrete logarithms of H1 outputs.
