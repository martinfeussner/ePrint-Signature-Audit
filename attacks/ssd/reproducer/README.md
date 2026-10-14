# SSD1760 full-parameter public reproducer

This standard-library Python implementation reconstructs a valid structured
standard-mode SSD1760 key from the equations in IACR ePrint 2022/1698, checks
an honest signing relation, and then performs a public-only fresh-message
forgery against the ordinary Algorithm-4 verifier.

Run with fresh operating-system seeds:

```sh
./reproducer/reproduce.sh --quick
```

Run the affected-row wrapper (SSD1760 is the only row claimed here):

```sh
./reproducer/reproduce.sh --all-rows
```

Successful output is JSON containing:

```json
{
  "banner": "ATTACK REPRODUCTION: PASS",
  "parameter_set": "SSD1760 standard mode",
  "status": "PASS",
  "workers": 1
}
```

The committed reference fixtures use disclosed seeds:

```sh
./reproducer/reproduce.sh --reference-quick > reference-output.json
./reproducer/reproduce.sh --reference-all-rows > all-rows-reference-output.json
```

## Attack implemented

The ordinary verifier accepts a binary vector `s` exactly when

```text
473 <= weight(s) <= 513
H*s = Y*hbar,
```

where `hbar` is the xor of four 440-bit blocks of the 1760-bit message hash.
For a valid SSD1760 key, `H` has 242 independent rows. Public row reduction
therefore gives 242 pivot coordinates and 1518 free coordinates.

The forger fixes 363 free coordinates to one. For each distinct candidate
message, it computes the public target `Y*hbar` and uniquely completes the
242 pivot coordinates. In the paper's random-oracle model, `Y*hbar` is
uniform in 242 bits, so the pivot weight is distributed as
`Binomial(242,1/2)`. The ordinary verifier accepts exactly when that pivot
weight lies from 110 through 150. Thus:

```text
success probability per distinct message = 0.9303737782253141
expected public message-hash queries      = 1.0748368273
signing queries                           = 0
```

This is a zero-signing-query existential fresh-message forgery through public
message search. It is not a universal forgery or a guarantee for every fixed,
preselected message.

## What the run checks

The implementation uses complete advertised dimensions and:

- reconstructs the standard Gen1/Gen2 algebra with the paper's consecutive
  odd signing exponents;
- requires `rank(H)=rank(Y)=242`;
- accepts a separate honest signature through the ordinary verifier;
- tracks the complete RREF transform and separately inverts the original
  242-by-242 pivot-column matrix, requiring both completion paths to agree;
- uses only public `H`, `Y`, parameters, and candidate-message hashes in the
  attack stage;
- counts distinct candidate messages and signing queries;
- rejects a changed message, an in-range one-bit response change, the
  response under an independently generated structured wrong key, and the
  zero vector; and
- constructs equation-valid vectors at weights 472, 473, 513, and 514,
  requiring reject, accept, accept, and reject respectively.

It also checks the separate Gen1 issue at the allowed `alpha_0=r=15`: the
candidate rank is at most 198 and cannot provide the 242 independent rows
Gen2 requests. The forgery does not use this key-generation defect and is
claimed only for valid full-rank keys.

## Hash and source boundary

The paper specifies a random oracle with a 1760-bit output but no concrete
hash function or message serialization. This reproducer uses SHAKE256 on
explicit byte strings. The exact probability calculation belongs to the
paper's random-oracle model; the executable SHAKE256 success is a concrete
check, not a theorem about every fixed SHAKE256 message.

No author implementation was available. This is an independent paper-level
reconstruction derived from the printed equations and checked against sealed
primary and adversarial evidence. It does not claim wire-format conformance.

## Timing boundary

The attack stage begins immediately before public row reduction and ends when
the first candidate passes ordinary verification. The complete process also
includes structured key generation, honest conformance, an independent wrong
key, and endpoint diagnostics. The committed JSON omits wall-clock values so
it is reproducible; use an external timer around the command and report which
of these scopes is measured.

The sealed adversarial run measured 0.19 CPU seconds for the attack stage from
before row reduction. Its complete two-key and control process took 1.29
seconds wall time and 23,552 KiB peak RSS. A primary result field named
`seconds_including_rref` is mislabeled: its 0.000544-second timer starts after
row reduction and measures only candidate-message completion. It must not be
cited as the full attack time.

Python 3.10 or newer is required. No third-party package is used, and every
run is sequential with one worker.

