#!/usr/bin/env python3
"""Public-only Yagisawa forger.

The only input accepted by this process is the serialized public coefficient
representation.  It has no signing-oracle interface and records zero signing
queries in both returned signatures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import List, Sequence, Tuple


Exp = Tuple[int, int, int, int]


def coefficient_sha256(coefficients: Sequence[Sequence[int]], q: int) -> str:
    width = (q.bit_length() + 7) // 8
    h = hashlib.sha256()
    for component in coefficients:
        for c in component:
            h.update(int(c).to_bytes(width, "little"))
    return h.hexdigest()


def compose_left_i(coefficients: Sequence[Sequence[int]],
                   monomials: Sequence[Exp], q: int) -> List[List[int]]:
    """Return coefficients of F(iX) by a signed monomial permutation.

    For X=(x0,x1,x2,x3), left multiplication gives
    iX=(-x1,x0,-x3,x2). Hence
    e=(e0,e1,e2,e3) maps to (e1,e0,e3,e2), with sign
    (-1)^(e0+e2).
    """
    index = {e: position for position, e in enumerate(monomials)}
    out = [[0] * len(monomials) for _ in range(4)]
    for component in range(4):
        for source_index, e in enumerate(monomials):
            target: Exp = (e[1], e[0], e[3], e[2])
            value = coefficients[component][source_index]
            if (e[0] + e[2]) & 1:
                value = -value
            target_index = index[target]
            out[component][target_index] = (
                out[component][target_index] + value
            ) % q
    return out


def add_monomial(coefficients: Sequence[Sequence[int]],
                 monomials: Sequence[Exp], q: int, exponent: Exp,
                 component: int = 0, delta: int = 1) -> List[List[int]]:
    out = [list(row) for row in coefficients]
    index = {e: position for position, e in enumerate(monomials)}
    out[component][index[exponent]] = (
        out[component][index[exponent]] + delta
    ) % q
    return out


def write_forgery(path: Path, public_doc: dict,
                  coefficients: Sequence[Sequence[int]], kind: str,
                  r_value: Sequence[int], e_value: Sequence[int],
                  construction: str) -> None:
    q = public_doc["parameters"]["q"]
    doc = {
        "kind": kind,
        "parameters": public_doc["parameters"],
        "ordering": public_doc["ordering"],
        "monomials": public_doc["monomials"],
        "coefficients": coefficients,
        "canonical_coefficient_sha256": coefficient_sha256(coefficients, q),
        "R": list(r_value),
        "E": list(e_value),
        "signing_queries": 0,
        "forger_interface": {
            "inputs": ["serialized public coefficient representation F"],
            "signing_oracle_available": False,
            "secret_material_available": False,
        },
        "construction": construction,
    }
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--primary-output", type=Path, required=True)
    parser.add_argument("--secondary-output", type=Path, required=True)
    args = parser.parse_args()

    public_doc = json.loads(args.public_key.read_text())
    q = int(public_doc["parameters"]["q"])
    s = int(public_doc["parameters"]["s"])
    monomials = [tuple(e) for e in public_doc["monomials"]]
    coefficients = public_doc["coefficients"]
    if len(coefficients) != 4 or len(monomials) != 560 or s != 13:
        raise ValueError("unexpected public full-row dimensions")
    if any(len(row) != len(monomials) for row in coefficients):
        raise ValueError("malformed public coefficient array")

    # Primary g=2 forgery: T*(X)=F(iX)+(x2^13,0,0,0).
    primary = compose_left_i(coefficients, monomials, q)
    primary = add_monomial(primary, monomials, q, (0, 0, s, 0))
    write_forgery(
        args.primary_output,
        public_doc,
        primary,
        "zero-query-primary-g2-forgery-T",
        (0, 1, 0, 0),
        (0, 0, 0, 2),
        "public signed monomial permutation F(iX), plus scalar-output x2^13",
    )

    # Retained secondary regression: g=1, T*(X)=F(X)+x2^13.
    secondary = add_monomial(coefficients, monomials, q, (0, 0, s, 0))
    write_forgery(
        args.secondary_output,
        public_doc,
        secondary,
        "zero-query-secondary-g1-regression-T",
        (0, 1, 0, 0),
        (0, 0, 0, 1),
        "public F(X), plus scalar-output x2^13",
    )

    print(json.dumps({
        "forger": "PUBLIC_ONLY_ISOLATED_PROCESS",
        "signing_queries": 0,
        "primary_coefficient_sha256": coefficient_sha256(primary, q),
        "secondary_coefficient_sha256": coefficient_sha256(secondary, q),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
