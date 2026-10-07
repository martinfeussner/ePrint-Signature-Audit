# ePrint Signature Audit

An AI-assisted campaign to identify and practically audit digital signature schemes
published on the IACR Cryptology ePrint Archive for which no prior public attack
against the scheme was located.

The project counts only practical, full-parameter, design-level signing compromises:
secret-key recovery with fresh signing, equivalent signing-key or witness recovery
with fresh signing, or efficient fresh-message forgery. Known cryptanalytic methods
are welcome when their application to the target scheme appears previously
unreported.

## Dashboard

| Metric | Count |
|---|---:|
| Schemes identified | 2 |
| Known attacks excluded | 1 |
| Schemes audited | 1 |
| No practical attack found | 1 |
| Verified practical design attacks | 0 |
| Independently reproduced attacks | 0 |

## Verified attacks

No attack has passed the publication gate yet.

The first catalog record is ATLAS (ePrint 2026/2323), excluded because it is
the published form of MORNING-ATLAS/NGCC sign-15 and a practical ATLAS-128
equivalent-key recovery with fresh-message forgery is already public.

ECLIPSE (ePrint 2026/2312) received a scoped paper-level audit after a
scheme-specific search, including its unnamed Section 5 PRISM identity, located
no prior public attack as of 2026-10-07. Tests of its structured-primality,
scalar-verifier, canonical-encoding, derived-key, and deterministic-stream
surfaces found no practical full-parameter signing compromise. The exact
implementation remains private, so source-specific decoder and serializer
checks are reserved for a release-time recheck.

See [methodology](METHODOLOGY.md), [attack-history methodology](docs/attack-history-methodology.md), [publication policy](docs/publication-policy.md), [reproducibility](REPRODUCIBILITY.md), and [AI disclosure](AI_DISCLOSURE.md).
