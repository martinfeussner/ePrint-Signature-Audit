#!/usr/bin/env python3
"""Export the sanitized q5/128 public-key JSON for the public Magma attack.

This exporter deliberately rebuilds the three public pencil matrices from the
JSON coefficient arrays.  It does not read a checkpoint, recovered basis, key
generation record, or secret-derived validation fixture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


class DuplicateKeyError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_secret_metadata(value: object, path: str = "$") -> None:
    forbidden = ("seed", "secret", "private", "validation_fixture")
    if isinstance(value, dict):
        for key, child in value.items():
            folded = str(key).casefold()
            if any(token in folded for token in forbidden):
                raise ValueError(f"secret-reproducible metadata key at {path}.{key}")
            reject_secret_metadata(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_metadata(child, f"{path}[{index}]")


def mlist(values: list[int]) -> str:
    return "[" + ",".join(str(int(x)) for x in values) + "]"


def matrix_literal(name: str, rows: list[list[int]], q: int) -> str:
    if not rows or not rows[0]:
        raise ValueError(f"empty matrix {name}")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise ValueError(f"ragged matrix {name}")
    flat = [int(x) % q for row in rows for x in row]
    return f"{name} := Matrix(F,{len(rows)},{width},{mlist(flat)});"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path("full-q5-128-public-key.json")
    )
    parser.add_argument(
        "output", nargs="?", type=Path, default=Path("work/public-data.m")
    )
    args = parser.parse_args()

    raw = args.input.read_bytes()
    obj = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    reject_secret_metadata(obj)
    q = int(obj["q"])
    n = int(obj["extension_degree"])
    m = int(obj["code_length"])
    ny = int(obj["public_code_dimension_observed"])
    kappa = int(obj["parent_code_dimension_over_extension"])
    matrices = obj["matrices"]
    aa = obj["aa_upper_triangular_vectors"]
    fixed = obj["fixed_rhs_test"]

    assert obj["schema"] == "djames-public-dragon-code-v1"
    assert obj["parameter"] == "d-james-128-q5"
    assert obj["upstream_commit"] == "4328ab366c066554094033297eb1ef3ec8b21c6f"
    assert (q, n, m, ny, kappa) == (5, 94, 73, 111, 2)
    assert obj["public_code_dimension_declared"] == ny
    assert len(matrices) == ny
    assert all(len(row) == n * m for row in matrices)
    assert len(aa) == n * (n + 1) // 2
    assert all(len(row) == m for row in aa)
    assert fixed["target"] == [1] * m
    assert fixed["salt_count"] == 256
    assert len(fixed["messages"]) == 2
    assert all(len(item["hashes"]) == fixed["salt_count"] for item in fixed["messages"])
    assert all(
        len(y) == ny
        for item in fixed["messages"]
        for y in item["hashes"]
    )
    messages = {item["label"]: item for item in fixed["messages"]}
    assert set(messages) == {"fresh", "changed"}
    for item in messages.values():
        assert re.fullmatch(r"(?:[0-9a-f]{2})+", item["message_hex"])

    # Matrix s is an n-by-m transposed public Y-slice in row-major order.
    # Aj[s,i] is public coefficient (signature coordinate i, output j).
    pencil = [
        [[int(matrices[s][i * m + j]) % q for i in range(n)] for s in range(ny)]
        for j in range(3)
    ]

    lines = [
        'ExportSchema := "djames-q5-128-root-public-json-v1";',
        f'InputSHA256 := "{hashlib.sha256(raw).hexdigest()}";',
        f'q := {q}; extension_degree := {n}; code_length := {m};',
        f'public_dimension := {ny}; parent_dimension := {kappa};',
        f'parameter_name := "{obj["parameter"]}";',
        'F := GF(q);',
    ]
    lines.extend(matrix_literal(f"A{j}", rows, q) for j, rows in enumerate(pencil))
    lines.append("PublicFlat := [")
    lines.extend(
        "  " + mlist([int(x) % q for x in row]) + ("," if s + 1 < ny else "")
        for s, row in enumerate(matrices)
    )
    lines.append("];\nAAUpper := [")
    lines.extend(
        "  " + mlist([int(x) % q for x in row]) + ("," if i + 1 < len(aa) else "")
        for i, row in enumerate(aa)
    )
    lines.extend(
        [
            "];",
            f"FixedTarget := {mlist(fixed['target'])};",
            f'SaltCount := {int(fixed["salt_count"])};',
            f'FreshMessageHex := "{messages["fresh"]["message_hex"]}";',
            f'ChangedMessageHex := "{messages["changed"]["message_hex"]}";',
            "FreshHashes := [",
        ]
    )
    fresh = messages["fresh"]["hashes"]
    lines.extend("  " + mlist(row) + ("," if i + 1 < len(fresh) else "") for i, row in enumerate(fresh))
    lines.append("];\nChangedHashes := [")
    changed = messages["changed"]["hashes"]
    lines.extend("  " + mlist(row) + ("," if i + 1 < len(changed) else "") for i, row in enumerate(changed))
    lines.append("];\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(
        f"exported {args.output} input_sha256={hashlib.sha256(raw).hexdigest()} "
        f"A_shapes=3x{ny}x{n} public_slices={ny}x{n}x{m} aa={len(aa)}x{m}"
    )


if __name__ == "__main__":
    main()
