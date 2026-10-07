# Methodology

Targets are discovered from the IACR Cryptology ePrint Archive and screened for
active overlap with other audits. Each candidate receives a scheme-specific public
attack-history search before significant cryptanalysis begins. Eligible targets are
reconstructed from an exact paper version and, when available, pinned source code.

Specialists then test distinct algebraic, lattice, statistical, protocol, coding,
hash-based, number-theoretic, and cross-family hypotheses as appropriate. Promising
leads must progress from a derivation through controlled experiments to a claimed
full parameter set and a fresh-message signing demonstration using the ordinary
verifier.

An apparent success is challenged by an adversarial reviewer and reproduced in a
fresh context. A final scheme-specific attack-history search and publication review
are required before it enters `attacks/`.

Toy attacks, proof gaps, distinguishers without signing consequences, implementation
bugs, side channels, fault attacks, and attacks requiring unrealistic conditions do
not count as project successes.
