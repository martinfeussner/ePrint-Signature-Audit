#!/usr/bin/env python3
"""Create the machine-readable report for a completed public full run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def peak_rss(path: Path) -> int:
    for line in path.read_text(encoding="utf-8").splitlines():
        if "Maximum resident set size" in line:
            return int(line.rsplit(":", 1)[1].strip())
    raise ValueError(f"peak RSS missing from {path}")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: report.py OUTPUT_DIRECTORY")
    root = Path(sys.argv[1]).resolve()
    required = (
        "oracle-summary.txt",
        "constraint-report.txt",
        "solver-report.json",
        "recovery-report.txt",
        "verification-report.txt",
        "ground-truth-comparison.txt",
        "MANIFEST.sha256",
        "milp.time",
    )
    for name in required:
        if not (root / name).is_file():
            raise SystemExit(f"FULL REPORT: FAIL: missing {name}")

    oracle = key_values(root / "oracle-summary.txt")
    constraints = key_values(root / "constraint-report.txt")
    recovery = key_values(root / "recovery-report.txt")
    verification = key_values(root / "verification-report.txt")
    truth = key_values(root / "ground-truth-comparison.txt")
    solver = json.loads((root / "solver-report.json").read_text(encoding="utf-8"))
    checks = {
        "all_public_constraints_satisfied": recovery.get("all_constraints_satisfied") == "true",
        "altered_signature_rejected": verification.get("altered_signature_control") == "REJECTED",
        "changed_message_rejected": verification.get("changed_message_control") == "REJECTED",
        "fresh_message_unqueried": verification.get("fresh_message_absent_from_ordinary_queries") == "true",
        "ground_truth_delayed_until_after_public_gate": verification.get("ground_truth_consulted") == "false",
        "ordinary_verifier_accepts_forgery": verification.get("untouched_fresh_forgery") == "ACCEPTED",
        "public_relation_holds": recovery.get("public_TG_equals_A_plus_D") == "true",
        "recovered_D_ternary": recovery.get("recovered_D_ternary") == "true",
        "recovered_G_ternary": recovery.get("derived_G_ternary") == "true",
        "solver_passed": solver.get("status") == "PASS",
    }
    if not all(checks.values()):
        raise SystemExit(f"FULL REPORT: FAIL: {checks}")
    if truth.get("status") != "PASS" or oracle.get("status") != "PASS":
        raise SystemExit("FULL REPORT: FAIL: oracle or post-hoc comparison")

    result = {
        "all_rows_pass": True,
        "attack": {"signing_queries": int(oracle["algorithm4_returned_signatures"])},
        "digests": {
            "constraint_report_sha256": sha256(root / "constraint-report.txt"),
            "full_output_manifest_sha256": sha256(root / "MANIFEST.sha256"),
            "recovery_report_sha256": sha256(root / "recovery-report.txt"),
            "solver_report_sha256": sha256(root / "solver-report.json"),
            "verification_report_sha256": sha256(root / "verification-report.txt"),
        },
        "environment": {"workers": 1},
        "full_attack_reproduced": True,
        "resources": {
            "milp_peak_rss_kib": peak_rss(root / "milp.time"),
            "milp_wall_seconds": solver["wall_seconds"],
            "workers": 1,
        },
        "result": "FULL_FRESH_KEY_ATTACK_REPRODUCTION_PASS",
        "results": [
            {
                "all_expected_checks_pass": True,
                "checks": checks,
                "constraints": int(constraints["edge_constraints"]),
                "parameter_row": "paper-level Ring-L2 (n=1024,q=59393,tau=16,eta=1,gamma1=gamma2=16384)",
                "signing_queries": int(oracle["algorithm4_returned_signatures"]),
                "wraps": int(constraints["edge_flips"]),
            }
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

