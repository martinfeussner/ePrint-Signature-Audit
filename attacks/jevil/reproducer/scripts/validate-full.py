#!/usr/bin/env python3
"""Validate full-run outputs and emit the stable public summary schema."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


if len(sys.argv) != 6:
    raise SystemExit(
        "usage: validate-full.py COMPLETE RECOVERY_JSON VERIFIER_JSON SUMMARY_JSON TIME_DIR"
    )

completion_path, recovery_path, verifier_path, summary_path, time_dir = map(
    Path, sys.argv[1:]
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"full-result validation failed: {message}")


def wall_seconds(value: str) -> float:
    parts = value.split(":")
    require(len(parts) in (2, 3), f"GNU-time wall value {value!r}")
    numbers = [float(part) for part in parts]
    if len(numbers) == 2:
        return 60 * numbers[0] + numbers[1]
    return 3600 * numbers[0] + 60 * numbers[1] + numbers[2]


def time_record(path: Path) -> dict[str, float | int]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "Elapsed (wall clock) time" in line:
            values["wall"] = line.rsplit(": ", 1)[1]
        elif "Maximum resident set size (kbytes)" in line:
            values["rss"] = line.rsplit(": ", 1)[1]
        elif "Exit status" in line:
            values["exit"] = line.rsplit(": ", 1)[1]
    require(values.get("exit") == "0", f"nonzero/missing time record: {path.name}")
    require("wall" in values and "rss" in values, f"incomplete time record: {path.name}")
    return {
        "wall_seconds": wall_seconds(values["wall"]),
        "peak_rss_kib": int(values["rss"]),
    }


completion: dict[str, str] = {}
for line in completion_path.read_text(encoding="utf-8").splitlines():
    key, separator, value = line.partition("=")
    require(bool(separator) and key not in completion, f"bad COMPLETE line: {line!r}")
    completion[key] = value

recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
verifier = json.loads(verifier_path.read_text(encoding="utf-8"))

require(completion.get("experiment") == "JEVIL-EXP-002", "oracle experiment")
require(completion.get("n_star") == "1023", "oracle n_star")
require(completion.get("poseidon_capacity") == "4", "oracle capacity")
require(completion.get("query_count") == "650", "oracle query count")
require(completion.get("first_zero_based_query_index") == "0", "first index")
require(completion.get("last_zero_based_query_index") == "649", "last index")
require(completion.get("excluded_zero_based_query_index") == "1023", "excluded index")
require(completion.get("ordinary_self_verification") == "PASS", "oracle verification")

require(
    recovery.get("schema")
    == "org.eprint-signature-audit.jevil-width-four-result/v1",
    "recovery schema",
)
require(recovery.get("mode") == "full", "recovery mode")
require(recovery.get("verdict") == "PASS", "recovery verdict")
require(recovery.get("n_star") == 1023, "recovery n_star")
require(recovery.get("query_count") == 650, "recovery query count")
require(recovery.get("maximum_zero_based_query_index") == 649, "recovery index")
require(recovery.get("authenticated_openings") == 41_600, "opening count")
require(recovery.get("distinct_positions", 0) >= 32_768, "interpolation threshold")
require(len(recovery.get("row_sha256", [])) == 4, "four recovered rows")
for field in (
    "excluded_1024th_signature_unused",
    "root_reconstructed",
    "public_evaluation_reconstructed",
    "fresh_message_unqueried",
    "unchanged_verifier_accepts_forgery",
    "changed_message_rejected",
    "changed_root_rejected",
    "altered_signature_rejected",
    "corrupted_row_rejected",
    "public_inputs_only",
):
    require(recovery.get(field) is True, f"recovery flag {field}")

require(
    verifier.get("schema")
    == "org.eprint-signature-audit.jevil-clean-verifier-result/v1",
    "clean-verifier schema",
)
require(verifier.get("n_star") == 1023, "clean-verifier n_star")
for field in (
    "ordinary_verifier_accepts_forgery",
    "changed_message_rejected",
    "changed_root_rejected",
    "altered_signature_rejected",
):
    require(verifier.get(field) is True, f"clean-verifier flag {field}")

require(
    completion["public_key_sha256"] == recovery["public_key_sha256"],
    "oracle/recovery public-key hash",
)
require(
    int(completion["signature_bytes_total"]) == recovery["signature_bytes_total"],
    "oracle/recovery signature-byte total",
)

result_dir = recovery_path.parent
artifact_names = (
    "authenticated-openings.bin",
    "fresh-message.bin",
    "fresh-signature.bin",
    "public-key.bin",
    "recovered-row-0.bin",
    "recovered-row-1.bin",
    "recovered-row-2.bin",
    "recovered-row-3.bin",
)
artifact_hashes = {name: sha256(result_dir / name) for name in artifact_names}
require(
    artifact_hashes["public-key.bin"] == recovery["public_key_sha256"],
    "retained public key",
)
require(
    artifact_hashes["fresh-message.bin"] == recovery["fresh_message_sha256"],
    "retained fresh message",
)
require(
    artifact_hashes["fresh-signature.bin"] == recovery["fresh_signature_sha256"],
    "retained fresh signature",
)
require(
    [artifact_hashes[f"recovered-row-{index}.bin"] for index in range(4)]
    == recovery["row_sha256"],
    "retained recovered rows",
)

stage_files = {
    "build_attack": "build-attack.time.txt",
    "build_clean_verifier": "build-clean-verifier.time.txt",
    "oracle": "oracle.time.txt",
    "recovery": "recovery.time.txt",
    "clean_verifier": "clean-verifier.time.txt",
}
stages = {name: time_record(time_dir / filename) for name, filename in stage_files.items()}
attack_stage_names = ("oracle", "recovery", "clean_verifier")
attack_wall = sum(stages[name]["wall_seconds"] for name in attack_stage_names)
attack_peak = max(stages[name]["peak_rss_kib"] for name in attack_stage_names)
total_wall = sum(stage["wall_seconds"] for stage in stages.values())
overall_peak = max(stage["peak_rss_kib"] for stage in stages.values())

summary = {
    "schema": "org.eprint-signature-audit.jevil-reproducer-run/v1",
    "mode": "full",
    "verdict": "PASS",
    "parameters": {
        "n_star": 1023,
        "poseidon_capacity": 4,
        "codeword_length": 131_072,
        "row_count": 4,
        "row_dimension": 32_768,
    },
    "oracle": {
        "query_count": 650,
        "first_zero_based_query_index": 0,
        "last_zero_based_query_index": 649,
        "excluded_zero_based_query_index": 1023,
        "public_key_sha256": completion["public_key_sha256"],
        "corpus_sha256": completion["corpus_sha256"],
        "signature_bytes_total": int(completion["signature_bytes_total"]),
    },
    "recovery": recovery,
    "clean_verifier": verifier,
    "retained_artifact_sha256": artifact_hashes,
    "execution": {
        "workers": 1,
        "fresh_local_key_per_run": True,
        "private_seed_retained": False,
        "raw_oracle_corpus_retained": False,
    },
    "resources": {
        "attack_stages_wall_seconds": round(attack_wall, 2),
        "attack_stages_peak_rss_kib": attack_peak,
        "build_and_attack_wall_seconds": round(total_wall, 2),
        "build_and_attack_peak_rss_kib": overall_peak,
        "stages": stages,
    },
}
summary_path.write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print("FULL_RESULT_SCHEMA=PASS")

