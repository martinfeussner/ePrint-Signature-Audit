#!/usr/bin/env python3
"""Quick public-only verification of the D-James q5/128 forgery.

This script recomputes the pinned SHAKE256 message hashes and evaluates the
ordinary public equations from the sanitized coefficient JSON.  It does not
load a field basis, recovery checkpoint, key-generation seed, or secret key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path
from typing import Callable


DOM_MSG = b"D-James/v1/msg"


class DuplicateKeyError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def xof(*parts: bytes, length: int) -> bytes:
    state = hashlib.shake_256()
    for part in parts:
        state.update(len(part).to_bytes(4, "little"))
        state.update(part)
    return state.digest(length)


def hash_to_fq(message: bytes, salt: int, count: int, q: int) -> list[int]:
    parts = (
        DOM_MSG,
        message,
        salt.to_bytes(8, "little"),
        q.to_bytes(4, "little"),
        count.to_bytes(4, "little"),
    )
    size = max(64, count * 2)
    while True:
        stream = xof(*parts, length=size)
        accepted = [byte % q for byte in stream if byte < (256 // q) * q]
        if len(accepted) >= count:
            return accepted[:count]
        size *= 2


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


def compile_public_map(public: dict, signature: list[int]) -> Callable[[list[int]], list[int]]:
    q = int(public["q"])
    n = int(public["extension_degree"])
    m = int(public["code_length"])
    ny = int(public["public_code_dimension_declared"])
    aa = public["aa_upper_triangular_vectors"]
    cross = public["matrices"]
    if len(signature) != n or len(aa) != n * (n + 1) // 2 or len(cross) != ny:
        raise ValueError("public or signature dimension mismatch")

    quadratic = [0] * m
    at = 0
    for i in range(n):
        for j in range(i, n):
            scale = signature[i] * signature[j] % q
            if scale:
                for k, coeff in enumerate(aa[at]):
                    quadratic[k] = (quadratic[k] + scale * int(coeff)) % q
            at += 1

    cross_columns: list[list[int]] = []
    for flat in cross:
        if len(flat) != n * m:
            raise ValueError("bad public cross-slice length")
        column = [0] * m
        for i, ai in enumerate(signature):
            if ai:
                start = i * m
                for k in range(m):
                    column[k] = (column[k] + ai * int(flat[start + k])) % q
        cross_columns.append(column)

    def evaluate(y: list[int]) -> list[int]:
        if len(y) != ny:
            raise ValueError("public hash dimension mismatch")
        out = quadratic[:]
        for ys, column in zip(y, cross_columns):
            if ys:
                for k in range(m):
                    out[k] = (out[k] + int(ys) * column[k]) % q
        return out

    return evaluate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", default="full-q5-128-public-key.json")
    parser.add_argument("--forgery", default="full-q5-128-forgery.json")
    parser.add_argument("--output", default="result.json")
    args = parser.parse_args()

    started = time.monotonic()
    public_path = Path(args.public_key)
    forgery_path = Path(args.forgery)
    public = load_json(public_path)
    forgery = load_json(forgery_path)
    reject_secret_metadata(public)
    reject_secret_metadata(forgery)

    public_digest = sha256(public_path)
    if public_digest != forgery["public_artifact_sha256"]:
        raise SystemExit("public artifact digest mismatch")
    if forgery.get("public_artifact") != public_path.name:
        raise SystemExit("public artifact filename mismatch")
    if public["parameter"] != forgery["parameter"] or public["parameter"] != "d-james-128-q5":
        raise SystemExit("parameter mismatch")
    if (public["q"], public["extension_degree"], public["code_length"],
            public["public_code_dimension_declared"]) != (5, 94, 73, 111):
        raise SystemExit("advertised q5/128 dimensions mismatch")

    fixed = public["fixed_rhs_test"]
    if fixed["salt_count"] != 256 or fixed["target"] != [1] * 73:
        raise SystemExit("public target or salt-domain mismatch")
    messages = {record["label"]: record for record in fixed["messages"]}
    if set(messages) != {"fresh", "changed"}:
        raise SystemExit("message controls mismatch")

    hashes_match = True
    hashes: dict[str, list[list[int]]] = {}
    for label, record in messages.items():
        message = bytes.fromhex(record["message_hex"])
        computed = [hash_to_fq(message, salt, 111, 5) for salt in range(256)]
        hashes[label] = computed
        hashes_match &= computed == record["hashes"]

    signature = [int(x) for x in forgery["signature_fq"]]
    salt = int(forgery["salt"])
    if (
        forgery.get("message_label") != "fresh"
        or forgery.get("message_hex") != messages["fresh"]["message_hex"]
        or not 0 <= salt < fixed["salt_count"]
        or any(not 0 <= x < public["q"] for x in signature)
    ):
        raise SystemExit("forgery witness metadata mismatch")
    evaluate = compile_public_map(public, signature)
    fresh_value = evaluate(hashes["fresh"][salt])
    changed_accepting = [
        candidate
        for candidate, digest in enumerate(hashes["changed"])
        if evaluate(digest) == fixed["target"]
    ]
    checks = {
        "advertised_parameter_row": True,
        "changed_message_rejects_all_256_salts": changed_accepting == [],
        "fresh_signature_satisfies_all_73_public_equations": fresh_value == fixed["target"],
        "public_input_contains_no_secret_metadata": True,
        "signature_is_nonzero_and_has_94_symbols": len(signature) == 94 and any(signature),
        "stored_hash_vectors_match_recomputed_shake256": hashes_match,
    }
    result = {
        "attack": {
            "fresh_message_hex": messages["fresh"]["message_hex"],
            "fresh_salt": salt,
            "parameter_row": "D-James q5/128",
            "signing_queries": 0,
        },
        "checks": checks,
        "digests": {
            "forgery_sha256": sha256(forgery_path),
            "public_key_sha256": public_digest,
        },
        "environment": {
            "machine": platform.machine(),
            "python": platform.python_version(),
            "workers": 1,
        },
        "metrics": {
            "changed_message_accepting_salts": changed_accepting,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "public_equations_checked": 73,
            "salts_checked": 512,
        },
        "result": "PASS" if all(checks.values()) else "FAIL",
        "schema": "djames-q5-128-public-verification-v1",
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    if result["result"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
