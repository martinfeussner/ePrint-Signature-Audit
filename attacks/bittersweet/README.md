# Bittersweet accepted-transcript key recovery

> **Status: `VERIFIED_ATTACK`.** The full-parameter attack was independently
> reproduced by a separate AI agent and passed the technical, adversarial,
> history, and publication-review gates.

[Bittersweet, IACR ePrint 2026/397 v1](https://eprint.iacr.org/2026/397)
([SCN 2026 version](https://doi.org/10.1007/978-3-032-36264-3_6)) exposes an oriented comparison with a
fixed 90-bit buffer of each secret LWR product in every accepted optimized
protocol repetition. Sixteen ordinary Level-I signatures provide 416 strict
comparisons for each of 747 public rows. Intersecting those comparisons gives
modular product intervals narrow enough for a conventional weighted CVP
embedding, plain LLL, and Babai nearest-plane recovery of the complete
1056-bit signing key.

The frozen procedure first succeeded on the untouched run-003 key. A separate
fresh-context run, run-005, then generated one new OS-random key, collected 16
complete signatures on distinct messages, and repeated the full public-only
recovery exactly once. Its candidate passed 747/747 intervals and 747/747
rounded public outputs before truth access, matched 11/11 key words through a
sealed comparator, and signed a distinct seventeenth message. The ordinary
strict verifier accepted all 26 repetitions and all 747 rows per repetition;
all ten final controls rejected. A public-only adversarial review independently
replayed the 310,752 comparisons, solver constraints, candidate constraints,
and fresh verifier.

## Verification status

| Check | Status |
|---|---|
| Full claimed parameter execution | Passed on run-003 and independent run-005 |
| Public-only candidate freeze before truth | Passed on both final runs |
| Exact secret-key match | Passed: 11/11 words on each final run |
| Fresh signing and ordinary verification | Passed on both final runs |
| Adversarial result review | Passed |
| Fresh-context independent reproduction | **Passed: run-005, one trial** |
| Final exact-scheme attack-history recheck | **Passed, dated 2026-10-07** |
| Public reproducer | Quick replay, independent all-row replay, and full fresh-key mode |
| Verified classification | **Passed** |

## Result at a glance

| Field | Result |
|---|---|
| Scheme | Bittersweet |
| Paper | [IACR ePrint 2026/397 v1](https://eprint.iacr.org/2026/397); [SCN 2026 DOI](https://doi.org/10.1007/978-3-032-36264-3_6) |
| Authors | Brieuc Balon, Gianluca Brian, Sebastian Faust, Carmit Hazay, Elena Micheli, and François-Xavier Standaert |
| Family | LWR-based MPC-in-the-head signature with Fiat--Shamir with aborts |
| Result | Full Level-I secret-key recovery and fresh signing on two separate final S16 keys: untouched run-003 and fresh-context run-005 |
| Technique | Turn accepted carry/error bits into strict product-buffer comparisons; intersect intervals; solve a weighted modular CVP with LLL and Babai |
| Affected row demonstrated | Level I, `d=32`: `(q,p',alpha,p,n,m,d,t)=(96,3,90,93,11,747,32,26)` |
| Signing queries | 16 accepted signatures on 16 distinct messages per attack execution |
| Public comparisons | 416 per row; 310,752 total per execution |
| Recovery rows | 160 narrowest of 747 |
| Run-003 public pipeline | 320.47 s wall; 236,792 KiB peak RSS; one worker |
| Run-005 public pipeline | 313.95 s wall; 236,760 KiB peak RSS; one worker |
| Run-005 complete stage sum | 379.82 s; peak 236,760 KiB |
| Sanitized quick replay | 65.98 s internal wall; 81,680 KiB peak RSS; one worker |
| Independent all-row replay | 65.27 s external wall; 82,996 KiB peak RSS; one worker |
| Exact-final-source full reproducer | 184.47 s internal wall; 83,336 KiB peak RSS; one worker |
| Public constraint checks | 747/747 intervals and 747/747 rounded outputs on each final run |
| Exact truth check | 11/11 96-bit words on each final run |
| Fresh signing consequence | One new-message signature accepted per final run; ten final controls rejected |
| Design level | Paper-level design attack under the frozen canonical realization |
| Independent reproduction | Passed on one fresh key in run-005 |
| Verification basis | Independent fresh-context execution plus passed technical, adversarial, history, and publication reviews |
| Final history search | Passed; no prior exact-scheme attack located as of 2026-10-07 |

Run-005 used Python 3.12.14 and Singular 4.4.1 on one CPU under a 4 GiB
limit. Its seven timed stages were 2.60 seconds for main precommit, 2.82 for
seed/commitment generation, 42.80 for key generation and 16 accepted
signatures, 313.95 for the public pipeline, 0.20 for truth comparison, 2.25
for fresh signing, and 15.20 for verification and controls. The sum is 379.82
seconds and the maximum RSS is 236,760 KiB (about 231.2 MiB).

Run-003 and run-005 use the same 16-query attack configuration but remain
separate records. Run-003 recorded 171/171 query-signature mutation controls;
run-005 recorded 169/169. Each fresh signature separately rejected ten final
controls.

## Why accepted signatures leak intervals

For public row `X_r`, secret key `k`, and

```text
u_r = <X_r,k> mod 2^96,
u_r = y_r*2^93 + 8*B_r + ell_r,
```

`y_r` is the public three-bit LWR output, `B_r` is a fixed 90-bit buffer, and
`0 <= ell_r < 8`. In one optimized protocol repetition, the response lets the
verifier reconstruct the opened key-share aggregate and therefore

```text
A_r = (S_r >> 3) mod 2^90.
```

The transmitted reconstruction-error bit orients the comparison. With the
Figure 3 modular verification rule and the honest abort condition:

```text
e_r = 0  =>  A_r < B_r  =>  B_r >= A_r + 1,
e_r = 1  =>  A_r > B_r  =>  B_r <= A_r - 1.
```

Equality never appears in an accepted honest transcript. Intersecting all 416
comparisons for row `r` gives `[L_r,U_r]`, hence

```text
y_r*2^93 + 8*L_r
    <= <X_r,k> mod 2^96
    <= y_r*2^93 + 8*(U_r+1) - 1.
```

The attack selects the 160 narrowest intervals, weights them by inverse
relative width, applies plain LLL, and uses Babai nearest plane. The candidate
must satisfy all 160 selected intervals, all 747 intervals, and all 747 public
rounded products before the comparator can read generated truth.

## Recorded empirical history

| Evidence class | Key accounting | Solver/trial accounting | Outcome and role |
|---|---:|---:|---|
| Original deterministic projected development | 1 tuned/training key | 2 documented successful configurations: S4/r120 and independently frozen S8; earlier tuning attempts are not exhaustively enumerated | Adaptive development only; recovery and fresh signing |
| Fresh adaptive S8 development | 1 key | 2 configurations: r112 failed, then adaptive r160 succeeded | Development only; the success produced fresh signing |
| Run-002 first driver stop | 0 new keys | 0 solver trials; stopped at environment import before LLL/Babai | Infrastructure only; corrected rerun is the immutable row below |
| Run-002 quarantined cross-agent retry | 0 new keys | Nonzero execution; no candidate; excluded from substantive trials | Preserved non-result |
| Untouched run-002 S8 | 1 held-out key | 1 frozen cryptanalytic trial | 0 recoveries; immutable campaign negative |
| Robust Family B development | 6 shared development keys | 6 trials, 6 successes | Selected S16 configuration; four projected-marginal and two complete-signature keys |
| Robust Family A development | Same 6 keys as Family B | 6 separate trials, 6 successes; BKZ-24 required on 2 | Development only; executed after Family-B truth opened, so not blind evidence |
| Robust benchmark environment stops | 0 new keys | 2 launches stopped before solving; 0 substantive trials | Inactive NGCC environment; successful reruns are already in Family B |
| Robust Families C and D | 0 keys | 0 trials | Not run under the predeclared selection rule |
| Untouched run-003 final S16 | 1 key | 1 fixed cryptanalytic trial | 1 exact recovery and fresh signing; qualifying campaign result |
| Run-004 infrastructure | 0 keys | 0 cryptanalytic trials | One terminal preseed attempt |
| Run-005 initial source VETO | 0 keys | 0 cryptanalytic trials | Preseed source review only |
| Run-005 final S16 | 1 OS-random key | 1 fixed cryptanalytic trial | 1 exact recovery and fresh signing; qualifying campaign result |
| Earlier public-package harness | 1 local key | 0 cryptanalytic trials and 0 solver attempts | Stopped in changed-message controls before lattice recovery; contemporaneous record only |
| Corrected public full-mode validation | 5 local keys | 5 fixed cryptanalytic trials | 5 exact recoveries and fresh signing; separate package validation |

Run-002 remains immutable: `NO_RECOVERY`, 0/160 selected intervals, 1/747
total intervals, and 214/747 public outputs fit; its truth remains sealed.
Run-004 timed out while probing `Singular --version` with inherited standard
input. It created no seed or key and made no signing, verifier, solver, truth,
or fresh-signing call. The corrected run-005 rev2 probe used closed standard
input, captured output, and a finite timeout. The initial run-005 source was
VETOed before entropy because its implementation did not exactly match the
declared first-nonempty-line parser; rev2 fixed the mismatch and passed before
the fresh run began.

The robust benchmark subtotal is six unique keys, twelve substantive Family-A
and Family-B solver trials, twelve development successes, and two pre-solver
environment stops. Family A and Family B reuse the same six keys; their rows
must not be read as twelve unique keys. Earlier S8 work was adaptive and its
full tuning history was not exhaustively enumerated. None of these development
rows is pooled with campaign evidence.

The final campaign S16 procedure has succeeded in 2/2 new or untouched final
executions, run-003 and run-005. This small pair does not support a population
success-rate estimate. Run-004 is one infrastructure attempt and zero
cryptanalytic trials. The attack's demonstrated query complexity is 16
signatures per campaign trial, not an aggregate of the two executions.

Public-package testing is accounted separately. An earlier harness attempt
generated one local key and signature set, then stopped in changed-message
control code before any lattice/public-recovery attempt; it contributes zero
cryptanalytic trials. After the harness fix, five full invocations each
generated one new key and performed exactly one fixed attack trial; all five
recovered the generated key and completed fresh signing, with zero signing
aborts and no solver retry or cryptanalytic retuning. These package-validation
runs add zero campaign trials or successes. Quick, all-row, and determinism
checks reuse the sanitized run-005 public interval instance and generate zero
keys and zero local or campaign cryptanalytic trials.

The five corrected tests shared the same fixed cryptanalytic configuration,
while noncryptanalytic harness and reporting code changed between validation
snapshots. The early stop is reported conservatively because no failed result
or time log survived.

The exact-final-source full run used 16 distinct complete signatures
with zero signing aborts, derived 310,752 comparisons, recovered 11/11 words
after the candidate commitment, accepted the fresh signature, and rejected
25/25 applicable query controls plus 10/10 applicable fresh-signature controls.

## Install and run

The hash lock is tested for CPython 3.12 on Linux x86_64 with glibc 2.17 or
newer. It permits only the official binary wheels for fpylll 0.6.4 and
cysignals 1.12.6 whose SHA-256 values are embedded in
`reproducer/requirements.txt`. Source builds and other Python/platform
combinations are unverified.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r reproducer/requirements.txt
.venv/bin/python -B reproduce.py
.venv/bin/python -B reproduce-all-rows.py
# Optional fresh-key execution:
.venv/bin/python -B reproduce.py --full
```

The locked install was tested in a fresh CPython 3.12.3 virtual environment;
imports and an LLL smoke test passed. The cryptanalytic replay and full-mode
measurements below used CPython 3.12.14. Exact wheel filenames, official PyPI
URLs, and hashes are recorded in `reproducer/UPSTREAM-SOURCES.json`.

The prebuilt paper uses pdfTeX 3.141592653-2.6-1.40.25 from TeX Live
2023/Debian with kpathsea 6.3.5. Its recorded SHA-256 is authoritative; other
TeX distributions may render the source but are outside the byte-identical PDF
claim.

## Reproduction outline

The public interface uses `reproduce.py` for a public-only quick replay,
`reproduce-all-rows.py` for an independent replay of the sole affected row,
and `reproduce.py --full` for a fresh local execution. The full mode:

1. generate a fresh Level-I key while keeping truth outside attacker inputs;
2. produce 16 complete optimized signatures on distinct messages;
3. verify them normally and run transcript mutation controls;
4. derive 310,752 comparisons only from verifier-visible data;
5. intersect them into 747 public product intervals;
6. select the 160 narrowest rows and execute the frozen LLL/Babai schedule;
7. freeze and validate the candidate against every interval and rounded output
   before comparing with generated truth;
8. sign a seventeenth, previously unsigned message with the recovered key;
9. verify it normally and reject the specified controls; and
10. report versions, commands, hashes, wall time, peak RSS, local
    trial/recovery counts, campaign increment, and public replay counts.

The package does not embed a stored recovered key as its proof of recovery.
Canonical results are in `reference-output.json` and
`all-rows-reference-output.json`.

## Scope and limitations

- The target is exact ePrint 2026/397 v1 and only its Level-I `d=32,t=26` row.
- The paper publishes no author implementation, normative byte encoding,
  domain separators, test vectors, or XOF-to-matrix specification. The
  experiment uses a frozen canonical SHAKE/SHA3 realization of the exact
  arithmetic, optimized GGM response structure, abort condition, and
  Fiat--Shamir binding.
- The leakage is at the design level and does not depend on a parser defect.
  Byte compatibility with a nonexistent author implementation is not claimed.
- Exact matches are accepted through hash-pinned comparators. Public-only
  reviewers and this documentation pass did not reopen private state.
- The verified classification rests on the recorded technical, adversarial,
  independent-reproduction, history, and publication-review gates.

## Method attribution and history

The Bittersweet paper identifies accepted-transcript carry leakage and notes
that successful signatures exclude buffer values. This result uses the
verifier-visible opened aggregate and error bit as oriented strict
inequalities, combines them as intervals, and applies established lattice
reduction and nearest-plane tools. No originality is claimed for LLL, Babai,
generic modular CVP embeddings, power-of-two LWR cryptanalysis, or carry
leakage.

The final dated recheck found that ePrint 2026/250 by Jules Baudrin, Rachelle
Heim Boissier, and François-Xavier Standaert is relevant generic prior work on
power-of-two LWR, but not a public attack on Bittersweet at its exact
parameters. The conservative finding is: **No prior public attack against
Bittersweet Signatures was located in the searches performed as of
2026-10-07.** This is not an absolute first-attack claim.

## AI provenance

Target selection, history searching, reconstruction, cryptanalysis,
implementation, execution, review, independent reproduction, and drafting
were AI-assisted. Separate AI agents reviewed run-003 and independently ran
and reviewed run-005. A clean-context AI Publication Reviewer conditionally
passed the frozen package. The result is classified `VERIFIED_ATTACK` under
the project's recorded review gates.

## Evidence boundary

The independent run-005 handoff has SHA-256
`b498f60bf6f5e821bba4f94c5d8c7de5268986fd095755d11998d96afd670b01`;
its public summary has SHA-256
`7818701b1b0b78ee51505943885e0deeb0783f408ebce99b8a1c4321f001ae08`;
and its public-only result review has SHA-256
`21d8d33dadd43f47b00fb4ed2cd94b3cbf52e8cebd2b81b47727cc6d4a9bc28b`.
The final history handoff has SHA-256
`1c0b648b3fe6d97edfcc51974ace70bee5c98b7df2220d786a46df5880453358`.

The immutable S8/run-002 ledger is bound by adversarial review
`00cb524125348ff860e347bac184e8b54eb61638330103d319a8d3b07bd4f7b1`.
The robust development primary handoff and adversarial review have SHA-256
`9046156582f336a8ba108f405c1c2bed7f231e3344700d2f32170e2ba4bbb302`
and `8f0d6915f76c6ca4059fe100231606c20c0572e65102dd3b765ba8e4fb4261fd`.
Run-003's public adversarial review has SHA-256
`b78fee81ec01e92f367f2d0dc91071ed41feb6dd300168f77e9d11fee1c27fdd`.
The public quick and independent scripts have SHA-256
`ea4f2fb18a4cfd71a1dd8bd94c8d52e1ef40b21f6bb25a5c74e6567a7cc483d9`
and `5dd764977e8e118731d57c6886789713315bb381e5fd549827aca5003ebb4183`.
Their canonical reference outputs have SHA-256
`977f1d9d604346291013126bcbceaa0edc0f5146e08bb4cb5796039fac33ad15`
and `fbbc3e32ed31974a685fa7ce92dae3d847654b873405aba9b9e7bdbdb6050226`.

Raw seeds, private generation state, raw key words, and private campaign files
are absent from the public package.
