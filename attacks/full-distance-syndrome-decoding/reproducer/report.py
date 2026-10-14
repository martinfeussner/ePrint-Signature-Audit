"""Stable public reports for the fresh-key FDSD reproducer."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent
TARGET_PDF_SHA256 = (
    "394b7a3e4f8d935cfabffd90e17b4c8cdd5708267a14ede67b39c49ab9ead822"
)
PARAMETER_ROW = "n=1600,k=400,L=125,epsilon=5,theta=25,d=343"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run_once() -> tuple[dict[str, object], dict[str, object]]:
    with tempfile.TemporaryDirectory(prefix="fdsd-public-report-") as name:
        run_dir = Path(name) / "run"
        environment = dict(os.environ)
        environment.update(
            {
                "LC_ALL": "C",
                "TZ": "UTC",
                "PYTHONDONTWRITEBYTECODE": "1",
                "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1",
                "NUMEXPR_NUM_THREADS": "1",
            }
        )
        process = subprocess.run(
            [str(ROOT / "reproduce.sh"), "--output", str(run_dir)],
            check=True,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        if "ATTACK REPRODUCTION: PASS" not in process.stdout:
            raise RuntimeError("reproducer PASS banner missing")
        summary = json.loads((run_dir / "summary.json").read_text())
        generation = json.loads((run_dir / "public/generation-summary.json").read_text())
    return summary, generation


def stable_checks(
    summary: dict[str, object], generation: dict[str, object]
) -> dict[str, bool]:
    controls = summary["negative_controls"]
    recovery = summary["public_recovery"]
    search = summary["search"]
    checks = {
        "all_four_negative_controls_reject": set(controls.values())
        == {"REJECTED"}
        and len(controls) == 4,
        "exact_full_level_i_parameters": summary["profile"]
        == "Level I (1600,400,125,5,25,343)",
        "exact_weight_343": summary["forgery_weight"] == 343,
        "fresh_key_generated": generation["status"] == "PASS",
        "fresh_message_forgery_accepts": summary["fresh_message_forgery"]
        == "ACCEPTED",
        "one_ordinary_signing_query": summary["ordinary_signing_queries"] == 1,
        "ordinary_query_signature_accepts": summary["query_signature"]
        == "ACCEPTED",
        "public_attack_boundary": summary["attack_boundary"] == "PASS",
        "public_map_recovery": recovery["rank_R"] == 125
        and recovery["Hstar_columns_in_Col_R"] == 125
        and recovery["selected_column_rank"] == 125
        and recovery["recovered_U_columns"] == 125
        and recovery["all_Hstar_U_columns_equal_R"] is True,
        "search_bound_is_2_to_25": search["maximum_candidates"] == (1 << 25),
        "secret_material_not_persisted": generation["seed_persisted"] is False
        and generation["secret_key_persisted"] is False
        and generation["secret_coordinate_labels_persisted"] is False,
        "zero_target_message_queries": summary["target_message_queries"] == 0,
    }
    if not all(checks.values()):
        raise RuntimeError(f"one or more reproducer checks failed: {checks}")
    return checks


def quick_report() -> dict[str, object]:
    summary, generation = run_once()
    checks = stable_checks(summary, generation)
    return {
        "attack": {
            "fresh_message": True,
            "ordinary_signing_query": True,
            "public_inputs_only": True,
            "signing_queries": 1,
            "target_message_queries": 0,
        },
        "checks": checks,
        "controls_rejected": 4,
        "digests": {
            "public_attack_source_sha256": sha256_file(ROOT / "public_attack.py"),
            "reference_model_source_sha256": sha256_file(
                ROOT / "fdsd_reference.py"
            ),
            "target_pdf_sha256": TARGET_PDF_SHA256,
        },
        "environment": {"dependencies": "Python standard library", "workers": 1},
        "full_scale": True,
        "parameter_row": PARAMETER_ROW,
        "result": "ONE_QUERY_FRESH_MESSAGE_FORGERY",
        "scope": "independent paper-level mathematical reconstruction",
        "successes": 1,
        "trials": 1,
    }


def all_rows_report() -> dict[str, object]:
    summary, generation = run_once()
    checks = stable_checks(summary, generation)
    return {
        "all_rows_pass": True,
        "implementation_sha256": sha256_file(ROOT / "public_attack.py"),
        "results": [
            {
                "all_expected_checks_pass": True,
                "checks": checks,
                "controls_rejected": 4,
                "parameter_row": PARAMETER_ROW,
                "public_inputs_only": True,
                "signing_queries": 1,
                "successes": 1,
                "target_message_queries": 0,
                "trials": 1,
            }
        ],
    }
