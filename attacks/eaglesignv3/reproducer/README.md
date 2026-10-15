# EagleSignV3 paper-level Ring-L2 reproducer (publication draft)

This proposed public reproducer implements the exact Ring-L2 mathematical row
from EagleSignV3, IACR ePrint 2024/1234, revised 6 August 2024. No exact V3
author source or known-answer vector was located, so this package makes a
paper-level claim only. Its byte-level choices are listed in
[`SPECIFICATION_COMPLETIONS.md`](SPECIFICATION_COMPLETIONS.md).

The full mode generates a fresh key, retains every one of 40,000 outputs
returned by the printed signing algorithm, decodes centered-modulus wrap labels
from public `r`, solves the resulting ternary inequalities for `D`, derives
`G = T^-1(A+D)` when public `T` is a unit, and signs a message absent from the
query set. Separate executables implement key generation, the signing oracle,
public recovery, ordinary verification, and the final post-hoc ground-truth
comparison.

## Requirements

- a C++20 compiler;
- OpenSSL 3 development headers and `libcrypto`;
- Python 3 with NumPy 2.5.3 and SciPy 1.18.1;
- `taskset` for one-CPU solver affinity;
- GNU `time`; and
- a POSIX shell with `sha256sum`.

The sealed independent environment used `g++` 13.3.0, OpenSSL 3.0.13,
NumPy 2.5.3, and SciPy 1.18.1 with bundled HiGHS 1.12.0. Compilation and every
attack stage use one worker. The solver wrapper uses SciPy
`optimize.milp`, integral bounds `[-1,1]`, a 21,600-second time limit, and
affinity to the first CPU allowed by the current process. The scripts apply a
4 GiB virtual-memory ceiling. Allow about 120 MiB of temporary storage for the
complete transcript and integer program. The sealed independent run completed
the public attack pipeline in 296.09 seconds, including 124.51 seconds for
oracle collection and 144.56 seconds for the SciPy/HiGHS command, with
221,272 KiB peak RSS. Fresh-key timing may differ.

## Commands

Build and run the structural arithmetic checks:

```sh
./reproduce.sh --smoke
```

Run the complete attack on one fresh unit-`T` key:

```sh
./reproduce.sh --full
```

Equivalent Make targets are `make smoke` and `make full`. A successful full
run ends with:

```text
EAGLESIGNV3 FULL ATTACK REPRODUCTION: PASS
```

Generated files are written below `output/full/`. Secret key material and the
large raw transcript remain in a temporary directory and are removed after the
post-hoc comparison. Run `make clean` before repeating full mode.

## What the full run checks

The recovery executable receives only the public key and printed signer
outputs. It requires a unique public hash match for every edge-label set.
`solve_milp.py` parses the generated LP into a sparse matrix and invokes
SciPy/HiGHS with 1,024 integral variables bounded to `{-1,0,1}`; it independently
checks every inequality before writing the candidate. Recovery then derives a
ternary and invertible `G` and verifies `T*G=A+D` before creating a fresh
signature. The separate verifier then requires:

- the fresh message to be absent from the 40,000 query messages;
- acceptance by the ordinary paper-level verifier;
- rejection after changing the message; and
- rejection after changing one bit of `r` while retaining `z`.

Only after those checks pass does a separate executable compare recovered
`D,G` with the hidden generated key.

## Scope

The direct `G` derivation is conditional on public `T` being a unit, estimated
for about 98.29% of Ring-L2 keys under the paper-level distribution. Key
generation records every attempt and selects the first unit-`T` key. One full
run is one key-recovery demonstration, not a success-rate estimate.

The attack consumes every output returned after Algorithm 4's two printed
rejection tests. In the primary run, about 4.4% of those outputs failed
ordinary verification because of the same modulus-boundary defect. Adding an
extra self-verification-and-resampling loop changes the signer and is outside
this claim. The fixed count of 40,000 is a demonstrated working point, not a
minimum-query estimate.

This public code was adapted from the separately written implementation used in
the prospectively sealed independent reproduction. That run used the same
64-byte-`r` main-text completion, SciPy 1.18.1/HiGHS 1.12.0 solver path,
40,000-output working point, one-worker limit, and 4 GiB virtual-memory
ceiling. The public adaptation changes domain-separation labels and removes a
stale solver-format compatibility label; it does not change the mathematical
path. Final exact-target history and independent Publication Review passed.

