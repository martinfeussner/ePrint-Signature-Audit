# Jevil width-four state-recovery reproducer

This package reproduces a full-parameter fresh-message forgery against Jevil
(IACR ePrint 2026/1103, revision 4) at the exact source-backed profile
`n_star=1023` and Poseidon2 capacity `c=4`. It asks an ordinary signing oracle
for 650 signatures, recovers an equivalent signing state from public
signature openings, signs an unqueried message, and submits the result to a
second copy of the unchanged ordinary verifier.

The run never requests the advertised 1,024th signature. Its zero-based query
indices are `0..649`; index `1023`, which would produce response 1,024, is
excluded.

## Commands

Rust and Cargo 1.88.0 are required and pinned by `rust-toolchain.toml`. The
dependency graph is pinned by the byte-identical `Cargo.lock` in both source
trees.

Run the source-integrity checks and a small synthetic four-row interpolation
test. This is a structural smoke test and does not reproduce the forgery:

```sh
./reproduce.sh --smoke
```

Run the complete 650-query attack with a fresh local key:

```sh
./reproduce.sh --full
```

The equivalent Make targets are `make smoke`, `make full`, and
`make check-pins`. Set `JEVIL_OFFLINE=1` to pass Cargo's `--offline` flag when
the locked crates are already in `CARGO_HOME`. `CARGO` and `RUSTC` may name
the exact 1.88.0 binaries.

Both modes use one Cargo build job and one Rayon worker. The smoke mode is the
appropriate CI path. A cold Rust build can still take several minutes; the
synthetic test itself takes less than a second after compilation. The full
run takes roughly 18 minutes after compilation on the recorded AMD EPYC
host. Allow 1 GiB of free disk for the temporary transcript, build products,
and retained result artifacts. The measured peak was below 520 MiB RSS for
compilation and below 151 MiB RSS for attack execution. No process needs more
than one CPU worker or 1 GiB RAM.

Each successful mode ends with one of these banners:

```text
JEVIL STRUCTURE SMOKE: PASS
JEVIL FULL ATTACK REPRODUCTION: PASS
```

## What the full run does

The signing-oracle executable generates a fresh exact-profile key from 32
bytes read locally from `/dev/urandom`. It writes only the public key, 650
distinct query messages, 650 ordinary serialized signatures, and an
accounting record. The seed and the secret signing state remain on the oracle
side.

Every valid signature authenticates 64 initial Merkle leaves, and every leaf
contains four extension-field symbols. Those leaves are positions in four
length-131,072 Reed--Solomon rows of degree below 32,768. The public recovery
executable ordinary-verifies every signature, collects the authenticated
width-four openings, and requires at least 32,768 distinct positions. It then
interpolates all four rows, re-encodes them across the complete domain, and
checks every observed opening.

The recovered rows reconstruct the exact public Merkle root and the public
out-of-domain evaluation. They therefore form an equivalent signing state.
The recovery process signs a message absent from the 650-query set using new
local prover randomness. It requires acceptance by the ordinary verifier and
rejection after changing the message, public root, or signature. It also
requires a corrupted recovered row to fail the root or public-evaluation
check.

Finally, `clean-verifier-source` parses the generated public key, message, and
signature and repeats ordinary acceptance plus the changed-message,
changed-root, and altered-signature controls. Apart from its external example
driver, this second source tree is the untouched pinned upstream source.

## Process and file boundary

The oracle producer and public recovery consumer are different processes.
Before recovery, the public transcript is made read-only, the seed directory
is made unreadable, the environment is cleared except for `PATH` and
`RAYON_NUM_THREADS=1`, and the consumer starts in an empty working directory.
The consumer receives only a public-transcript path and an empty result path.

The raw signature corpus is about 220 MB. It exists only below a temporary
directory during a full run and is deleted on success or failure. The private
seed is also deleted and is never copied into the output directory. Generated
build products live in `build/`, and generated results live in `output/`;
both are ignored by the package manifest.

A successful full run retains these public outputs below `output/full/`:

- `summary.json`, using schema
  `org.eprint-signature-audit.jevil-reproducer-run/v1`;
- `artifacts/result.json`, the recovery's detailed machine-readable result;
- `artifacts/clean-verifier-result.json`, the untouched-verifier result;
- the four recovered rows, authenticated-opening transcript, public key,
  fresh message, and fresh signature;
- per-stage GNU-time records, commands, environment, and logs; and
- `MANIFEST.sha256`, covering all retained output files.

The smoke result uses `mode=structural_smoke` and
`full_attack_reproduced=false`. The JSON schema and field names are stable
across runs. Hashes and timings change because every full run generates a new
key and fresh prover randomness.

## Source pins and modifications

Target pins:

- paper: ePrint 2026/1103 revision 4;
- paper PDF SHA-256:
  `c0da79bdf8b2d2c9667d6167d6ab008b8eeaf838b463a40eb64f2abe123c01c5`;
- source commit: `905466fbe3be99d90fd41e461e0c68271d09104b`;
- source tree: `f4a7366dac1a1f079186d87a2aca79c9918ee79e`;
- frozen source archive SHA-256:
  `b8817b85a5f90dd4045c8e635dad806e3973b26dbb36c01d7d2a37fcdff0270e`;
- locked dependency file SHA-256:
  `a13a82ddbe35d97e7cd9f0056af036695d0c6bab0202cb9b6bd351ec09b65d77`.

The ordinary signing and verification entry points are byte-identical to the
pinned source in both trees:

- `src/sign.rs` SHA-256:
  `34a61da541e7239402e2e49fedee76aaa50fc4c328c49cc9a307dca3bac2fb74`;
- `src/verify.rs` SHA-256:
  `d84341b99aa3b76413c20118f7fb0a78886754e1d9c7c0f952c7f930037e569b`.

The clean upstream `src/whir/protocol.rs` SHA-256 is
`5cdd14362c35ca71e085a2e85a45f9a55663c0ffea9a2a196e3548ccc0bcb20e`.
The attack tree changes only `src/lib.rs` and `src/whir/protocol.rs` among
common files, and adds `src/independent.rs` plus the oracle and recovery
examples. The protocol hook records first-round openings after their Merkle
authentication; the ordinary `verify` entry point still executes its complete
proof and end-of-transcript checks before the observer returns them.

`SOURCE-PINS.sha256` covers every file in both source trees. `SHA256SUMS`
covers the complete sanitized package except itself. The pin checker also
rejects extra source files, target directories, oracle-private directories,
and retained public-transcript directories.

## Recorded scope and limitations

The independently written implementation on which this package is based
passed one prior 650-query fresh-key reproduction. This package replay is a
separate publication-package validation; it is not described as an
independent verification of itself. Neither run estimates the minimum query
count or an all-key success probability.

The new package replay authenticated 35,704 distinct positions and passed the
full endpoint. Oracle collection took 821.48 seconds at 131,552 KiB peak RSS;
public recovery took 254.28 seconds at 150,488 KiB; and the clean verifier took
0.89 seconds at 91,840 KiB. The three attack stages totaled 1,076.65 seconds.
The initial runner then exposed a post-result cleanup-order bug after its
output manifest had passed. The final script restores traversal on the
mode-`000` private directory before recursive cleanup, and that exact cleanup
sequence passed a focused test. The attack was not rerun after this cleanup-
only change. `validation/full-replay-20261015.json` records this boundary;
`validation/structural-smoke-20261015.json` records the post-lint smoke run.

The target is the frozen source-backed row. The pinned source commit predates
the final revision-4 PDF by about 19 hours and 47 minutes. The package therefore
demonstrates the attack against that exact source-backed implementation and
parameter profile; it does not claim byte-format coverage beyond the pinned
source. A mount-namespace sandbox is not required for use of the reproducer;
the recorded isolation rests on separate processes, a narrow file API,
read-only public input, an unreadable private directory, and a scrubbed
consumer environment.

See `NOTICE.md`, `LICENSE-MIT`, and `LICENSE-APACHE` for source provenance and
license terms.

