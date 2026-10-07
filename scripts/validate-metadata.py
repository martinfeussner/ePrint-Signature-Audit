#!/usr/bin/env python3
"""Perform dependency-free structural checks on public JSON metadata."""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EPRINT = re.compile(r"^[0-9]{4}/[0-9]+$")
STATES = {
    "VERIFIED_ATTACK",
    "AI_REPRODUCED_HUMAN_PENDING",
    "AUDITED_NO_PRACTICAL_ATTACK",
    "QUEUED",
    "KNOWN_ATTACK_EXCLUDED",
    "IMPRACTICAL",
    "DUPLICATE_ACTIVE_AUDIT",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def main() -> int:
    errors = 0
    catalog_path = ROOT / "catalog" / "schemes.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{catalog_path}: {exc}")
        return 1
    if not isinstance(catalog, list):
        fail("catalog/schemes.json must contain a JSON array")
        return 1
    seen: set[str] = set()
    for index, item in enumerate(catalog):
        label = f"catalog entry {index}"
        if not isinstance(item, dict):
            fail(f"{label} is not an object")
            errors += 1
            continue
        for field in ("scheme", "eprint_id", "eprint_version", "family", "status", "url"):
            if not item.get(field):
                fail(f"{label} lacks {field}")
                errors += 1
        eprint_id = item.get("eprint_id", "")
        if not EPRINT.fullmatch(eprint_id):
            fail(f"{label} has invalid eprint_id {eprint_id!r}")
            errors += 1
        if eprint_id in seen:
            fail(f"duplicate eprint_id {eprint_id}")
            errors += 1
        seen.add(eprint_id)
        if item.get("status") not in STATES:
            fail(f"{label} has unknown status {item.get('status')!r}")
            errors += 1

    for path in sorted((ROOT / "attacks").glob("*/metadata.json")):
        try:
            attack = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"{path}: {exc}")
            errors += 1
            continue
        required = {
            "scheme", "eprint_id", "eprint_version", "attack_history_checked_at",
            "prior_public_attack_located", "attack_result", "attack_technique",
            "layer", "affected_parameters", "full_scale", "runtime_seconds",
            "peak_ram_mb", "workers", "independent_reproduction", "human_verification",
        }
        missing = sorted(required - attack.keys())
        if missing:
            fail(f"{path}: missing {', '.join(missing)}")
            errors += 1
        if attack.get("prior_public_attack_located") is not False:
            fail(f"{path}: prior_public_attack_located must be false")
            errors += 1
        if attack.get("layer") != "design" or attack.get("full_scale") is not True:
            fail(f"{path}: attack must be design-level and full-scale")
            errors += 1
        if attack.get("independent_reproduction") is not True:
            fail(f"{path}: independent reproduction is required")
            errors += 1

    if errors:
        print(f"Metadata validation failed with {errors} error(s).", file=sys.stderr)
        return 1
    print(f"Metadata validation passed: {len(catalog)} catalog entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
