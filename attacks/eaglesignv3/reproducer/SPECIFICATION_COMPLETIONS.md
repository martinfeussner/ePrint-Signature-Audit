# Paper-level specification completions

EagleSignV3 ePrint 2024/1234 does not provide an exact V3 implementation or
known-answer vectors, and several byte lengths conflict across the main
algorithms and Appendix A.4. This reproducer fixes the following choices while
preserving the Ring-L2 equations and printed distributions:

- `r` is 64 bytes, following Section 3.3's printed 512-bit range for `G`.
- `lambda` is 48 bytes, following Appendix A.4's `y` sampler.
- `rho` is 32 bytes, following `GenRandoms` and Appendix A.4.
- `tr` is 32 bytes and `mu` is 48 bytes, following Appendix A.4.
- Small-polynomial samplers consume the complete 32-byte derived seed and a
  two-byte nonce. Ternary coefficients are uniform in `{-1,0,1}`.
- The `y` sampler is uniform on the complete inclusive interval
  `[-16384,16384]` by rejection sampling 16-bit words above 32768.
- Public `T` coefficients are canonical little-endian 16-bit residues.
- High bits in `{-1,0,1}` are encoded as bytes in `{0,1,2}` before hashing.
- `A` is expanded as one uniform ring element in coefficient form; the NTT is
  an explicit bijection used for multiplication.

These are explicit paper-level completions. They do not establish
compatibility with an author implementation or a canonical EagleSignV3 wire
format.

