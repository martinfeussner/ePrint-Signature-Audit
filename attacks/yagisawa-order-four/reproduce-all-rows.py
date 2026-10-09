#!/usr/bin/env python3
"""Run and summarize the independent full-parameter reproduction.

The paper publishes one concrete parameter row. This entry point retains the
repository's all-row convention while executing that row with separately
written quaternion, polynomial, signing, verification, and forger code.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(raw: dict, root: Path) -> dict:
    forgery = raw["primary_forgery_g2"]
    honest = raw["honest_same_message_signature_generated_after_forgery"]
    controls = raw["negative_controls"]
    checks = {
        "all_four_challenge_classes_accept": (
            forgery["p_residue_classes_checked"] == [0, 1, 2, 3]
            and all(item["equal"] for item in forgery["checks"])
        ),
        "equations_11_and_12_match_direct_evaluation": raw["independent_equation_conformance"]["all_match"],
        "forgery_accepted": forgery["accepted"],
        "forger_is_public_only_isolated_process": (
            forgery["isolated_process"]
            and not forgery["signing_oracle_available"]
            and not forgery["secret_material_available"]
        ),
        "fresh_same_message_honest_signature_accepts_after_forgery": (
            honest["generated_after_primary_forgery_accepted"]
            and honest["accepted"]
            and honest["E"] == forgery["E"]
        ),
        "hidden_domain_conditions_hold": all(raw["fixed_forgery_pair_validity"].values()),
        "negative_controls_rejected": all(not item["accepted"] for item in controls.values()),
        "public_coefficient_count_is_2240": raw["parameters"]["public_coefficients"] == 2240,
        "zero_signing_queries": forgery["signing_queries"] == 0,
    }
    return {
        "all_rows_pass": all(checks.values()),
        "digests": {
            "independent_core_sha256": sha256_file(root / "reproducer" / "independent.py"),
            "public_forger_core_sha256": sha256_file(root / "reproducer" / "public_forger.py"),
            "target_pdf_sha256": raw["target"]["pdf_sha256"],
        },
        "results": [
            {
                "all_expected_checks_pass": all(checks.values()),
                "checks": checks,
                "measurements": {
                    "elapsed_seconds": raw["timings"]["total_seconds"],
                    "parameter_row": "q=1048583, d=2, r=3, m=448, s=13",
                },
                "parameter_row": "claimed d=2, r=3, m=448 row over a conforming 21-bit prime",
                "signing_queries": forgery["signing_queries"],
            }
        ],
    }


def run() -> int:
    root = Path(__file__).resolve().parent
    core = root / "reproducer" / "independent.py"
    with tempfile.TemporaryDirectory(prefix="yagisawa-independent-") as tmp:
        output = Path(tmp)
        completed = subprocess.run(
            [sys.executable, "-B", str(core), "--output", str(output)],
            check=True,
            capture_output=True,
            text=True,
        )
        if completed.stderr:
            raise RuntimeError(completed.stderr)
        raw = json.loads((output / "results.json").read_text(encoding="utf-8"))
    summary = summarize(raw, root)
    if not summary["all_rows_pass"]:
        raise RuntimeError("one or more independent reproduction checks failed")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
