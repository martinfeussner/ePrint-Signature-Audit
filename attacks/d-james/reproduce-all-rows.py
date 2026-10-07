#!/usr/bin/env python3
"""Independent direct evaluator for every parameter row claimed here.

The public report claims one advertised row, q5/128.  This implementation is
deliberately separate from reproduce.py and evaluates each public term for
each digest without partial evaluation.  It is slower but provides a simple
cross-check of the claimed signature and negative control.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path


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


def shake_hash(message: bytes, salt: int, count: int = 111, q: int = 5) -> list[int]:
    pieces = (
        DOM_MSG,
        message,
        salt.to_bytes(8, "little"),
        q.to_bytes(4, "little"),
        count.to_bytes(4, "little"),
    )
    size = max(64, count * 2)
    while True:
        h = hashlib.shake_256()
        for piece in pieces:
            h.update(len(piece).to_bytes(4, "little"))
            h.update(piece)
        stream = h.digest(size)
        values = [octet % q for octet in stream if octet < (256 // q) * q]
        if len(values) >= count:
            return values[:count]
        size *= 2


def evaluate(public: dict, signature: list[int], digest: list[int]) -> list[int]:
    q, n, m, ny = 5, 94, 73, 111
    out = [0] * m
    index = 0
    for i in range(n):
        for j in range(i, n):
            scale = signature[i] * signature[j] % q
            if scale:
                coeff = public["aa_upper_triangular_vectors"][index]
                for k in range(m):
                    out[k] = (out[k] + scale * int(coeff[k])) % q
            index += 1
    for s in range(ny):
        ys = digest[s]
        if not ys:
            continue
        flat = public["matrices"][s]
        for i in range(n):
            scale = ys * signature[i] % q
            if scale:
                base = i * m
                for k in range(m):
                    out[k] = (out[k] + scale * int(flat[base + k])) % q
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", default="full-q5-128-public-key.json")
    parser.add_argument("--forgery", default="full-q5-128-forgery.json")
    parser.add_argument("--output", default="all-rows-result.json")
    args = parser.parse_args()
    started = time.monotonic()
    public_path, forgery_path = Path(args.public_key), Path(args.forgery)
    public = load_json(public_path)
    forgery = load_json(forgery_path)
    reject_secret_metadata(public)
    reject_secret_metadata(forgery)
    public_hash = hashlib.sha256(public_path.read_bytes()).hexdigest()
    if public_hash != forgery.get("public_artifact_sha256"):
        raise SystemExit("public artifact digest mismatch")
    if forgery.get("public_artifact") != public_path.name:
        raise SystemExit("public artifact filename mismatch")
    if public.get("parameter") != forgery.get("parameter") or public.get("parameter") != "d-james-128-q5":
        raise SystemExit("parameter mismatch")
    if (public["q"], public["extension_degree"], public["code_length"],
            public["public_code_dimension_declared"]) != (5, 94, 73, 111):
        raise SystemExit("advertised q5/128 dimensions mismatch")
    fixed = public["fixed_rhs_test"]
    if fixed.get("salt_count") != 256 or fixed.get("target") != [1] * 73:
        raise SystemExit("public target or salt-domain mismatch")
    records = {x["label"]: x for x in fixed["messages"]}
    if set(records) != {"fresh", "changed"}:
        raise SystemExit("message controls mismatch")
    target = fixed["target"]
    sig = [int(x) for x in forgery["signature_fq"]]
    salt = int(forgery["salt"])
    if (
        forgery.get("message_label") != "fresh"
        or forgery.get("message_hex") != records["fresh"]["message_hex"]
        or not 0 <= salt < fixed["salt_count"]
        or len(sig) != 94
        or any(not 0 <= x < 5 for x in sig)
    ):
        raise SystemExit("forgery witness metadata mismatch")
    fresh_message = bytes.fromhex(records["fresh"]["message_hex"])
    changed_message = bytes.fromhex(records["changed"]["message_hex"])
    fresh_hashes = [shake_hash(fresh_message, candidate) for candidate in range(256)]
    stored_fresh_hashes_match = fresh_hashes == records["fresh"]["hashes"]
    fresh_digest = fresh_hashes[salt]
    fresh_accepts = evaluate(public, sig, fresh_digest) == target
    changed_accepting = []
    stored_changed_hashes_match = True
    for candidate in range(256):
        digest = shake_hash(changed_message, candidate)
        stored_changed_hashes_match &= digest == records["changed"]["hashes"][candidate]
        if evaluate(public, sig, digest) == target:
            changed_accepting.append(candidate)
    expected = (
        stored_fresh_hashes_match
        and stored_changed_hashes_match
        and fresh_accepts
        and not changed_accepting
        and len(sig) == 94
        and any(sig)
    )
    result = {
        "all_rows_pass": expected,
        "environment": {
            "machine": platform.machine(),
            "python": platform.python_version(),
            "workers": 1,
        },
        "results": [
            {
                "all_expected_checks_pass": expected,
                "changed_message_accepting_salts": changed_accepting,
                "fresh_accepts": fresh_accepts,
                "parameter_row": "D-James q5/128",
                "public_key_sha256": public_hash,
                "signature_nonzero": any(sig),
                "stored_hash_vectors_match": (
                    stored_fresh_hashes_match and stored_changed_hashes_match
                ),
            }
        ],
        "runtime_seconds": round(time.monotonic() - started, 6),
        "schema": "djames-claimed-rows-independent-verification-v1",
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    if not expected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
