# Source and license notice

This package targets Jevil from IACR ePrint 2026/1103, revision 4. The pinned
implementation is from <https://github.com/symbolicsoft/jevil> at commit
`905466fbe3be99d90fd41e461e0c68271d09104b` and tree
`f4a7366dac1a1f079186d87a2aca79c9918ee79e`. Its frozen source-archive
SHA-256 is
`b8817b85a5f90dd4045c8e635dad806e3973b26dbb36c01d7d2a37fcdff0270e`.

The upstream Jevil source is distributed under `MIT OR Apache-2.0`. Its
license texts are retained at the package root and in both source trees. The
reproducer additions in `attack-source/src/independent.rs`, the three
reproducer examples, the root scripts, and the compatibility wrappers are
also made available under the same `MIT OR Apache-2.0` terms.

The clean verifier tree differs from the pinned upstream source only by the
external `examples/exp002_clean_verify.rs` driver. The attack tree has three
new implementation files and two instrumented integration points. Run
`./scripts/check-pins.sh` for the exact file-set and byte-hash checks.

