"""Run and normalize the compiled GLYPH reproducer."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
EXPECTED = {
    "m": 2048,
    "n": 1024,
    "q": 59393,
    "B": 16383,
    "omega": 16,
    "K": 16367,
    "L": 16366,
    "D": 32735,
}
TARGET_PDF_SHA256 = (
    "ff0eeaea3a9fcb830197ea954472869a08adbf42e64e727470fa8e0038c6682a"
)
EXPECTED_TRIALS = {"quick": 8, "full": 64}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(mode: str) -> dict[str, Any]:
    if mode not in EXPECTED_TRIALS:
        raise ValueError(f"unsupported mode: {mode}")
    completed = subprocess.run(
        [str(HERE / "reproduce.sh"), f"--{mode}"],
        cwd=HERE,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, file=sys.stderr, end="")
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    if completed.returncode != 0:
        raise RuntimeError(
            f"compiled GLYPH reproduction failed with status "
            f"{completed.returncode}"
        )
    summary_path = HERE / "output" / mode / "summary.json"
    with summary_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    _validate_raw(raw, mode)
    return raw


def _validate_raw(raw: dict[str, Any], mode: str) -> None:
    trials = EXPECTED_TRIALS[mode]
    if raw.get("schema") != "glyph-public-reproducer-v1":
        raise RuntimeError("unexpected compiled-output schema")
    if raw.get("status") != "PASS" or raw.get("mode") != mode:
        raise RuntimeError("compiled reproduction did not report PASS")
    if raw.get("parameters") != EXPECTED:
        raise RuntimeError("compiled reproduction used the wrong parameter row")
    attack = raw.get("attack", {})
    if attack.get("signing_queries") != 0 or attack.get(
        "public_forger_secret_inputs"
    ) != 0:
        raise RuntimeError("public-only, zero-query boundary failed")
    observed_trials = raw.get("trials", {})
    if any(
        observed_trials.get(name) != trials
        for name in (
            "requested",
            "completed",
            "forgeries_accepted",
            "unique_public_keys",
            "unique_messages",
            "unique_signatures",
        )
    ):
        raise RuntimeError("fresh-trial accounting failed")
    controls = raw.get("controls", {})
    if controls.get("per_trial") != 8 or controls.get("total") != 8 * trials:
        raise RuntimeError("control accounting failed")
    if controls.get("rejected") != controls["total"]:
        raise RuntimeError("a negative control did not reject")
    checks = raw.get("checks", {})
    expected_checks = {
        "all_forgeries_accepted": True,
        "all_negative_controls_rejected": True,
        "all_selector_residues_passed": True,
        "strict_interior_responses": True,
        "ordinary_upstream_glp_verify": True,
        "public_only_forge_api": True,
        "secret_keys_retained": False,
        "zero_signing_queries": True,
    }
    if checks != expected_checks:
        raise RuntimeError("compiled reproduction checks were incomplete")
    exhaustion = raw.get("selector_exhaustion", {})
    if exhaustion.get("residues_tested") != 59393 or exhaustion.get(
        "selector_failures"
    ) != 0:
        raise RuntimeError("exhaustive selector check failed")
    manifest = HERE / "output" / mode / "MANIFEST.sha256"
    if not manifest.is_file() or not manifest.read_text(encoding="utf-8").strip():
        raise RuntimeError("run output was not sealed")


def _digests() -> dict[str, str]:
    upstream = json.loads(
        (HERE / "UPSTREAM-SOURCES.json").read_text(encoding="utf-8")
    )
    glp_hash = upstream["files"]["vendor/glyph/glp.c"]
    return {
        "public_forger_source_sha256": sha256_file(HERE / "src/public_forge.c"),
        "target_pdf_sha256": TARGET_PDF_SHA256,
        "upstream_glp_source_sha256": glp_hash,
        "upstream_source_manifest_sha256": sha256_file(
            HERE / "UPSTREAM-SOURCES.json"
        ),
    }


def _checks(raw: dict[str, Any]) -> dict[str, bool]:
    trials = int(raw["trials"]["requested"])
    return {
        "all_fresh_full_parameter_forgeries_accept": (
            raw["trials"]["forgeries_accepted"] == trials
        ),
        "all_negative_controls_reject": (
            raw["controls"]["rejected"] == raw["controls"]["total"]
        ),
        "byte_exact_upstream_verifier_source": True,
        "exhaustive_all_residue_selector_check": (
            raw["selector_exhaustion"]["residues_tested"] == 59393
            and raw["selector_exhaustion"]["selector_failures"] == 0
        ),
        "fresh_os_random_keys_and_messages": (
            raw["randomness"]["fresh_public_keys"]
            and raw["randomness"]["fresh_messages"]
            and raw["trials"]["unique_public_keys"] == trials
            and raw["trials"]["unique_messages"] == trials
        ),
        "ordinary_upstream_verifier_accepts": raw["checks"][
            "ordinary_upstream_glp_verify"
        ],
        "public_only_forging_api": raw["checks"]["public_only_forge_api"],
        "secret_keys_absent_from_retained_output": not raw["checks"][
            "secret_keys_retained"
        ],
        "strict_interior_response_bound": raw["checks"][
            "strict_interior_responses"
        ],
        "zero_signing_queries": raw["checks"]["zero_signing_queries"],
    }


def quick_report() -> dict[str, Any]:
    raw = _run("quick")
    checks = _checks(raw)
    if not all(checks.values()):
        raise RuntimeError("one or more normalized quick checks failed")
    return {
        "attack": {
            "message_scope": "fresh attacker-chosen message bytes",
            "parameter_row": "m=2048, n=1024, q=59393, B=16383, omega=16",
            "result": "public-key-only fresh-message forgery",
            "signing_queries": 0,
        },
        "checks": checks,
        "digests": _digests(),
        "environment": {
            "language": "GNU11 C with a Python 3 standard-library wrapper",
            "workers": 1,
        },
        "metrics": {
            "controls_rejected": raw["controls"]["rejected"],
            "controls_tested": raw["controls"]["total"],
            "forgeries_accepted": raw["trials"]["forgeries_accepted"],
            "residues_exhausted": raw["selector_exhaustion"][
                "residues_tested"
            ],
            "trials": raw["trials"]["requested"],
        },
        "result": "PASS: 8/8 fresh full-parameter forgeries accepted; 64/64 controls rejected",
        "scope": (
            "The numerical paper/source (z1,z2,c) and message/hash interface; "
            "the target specifies no portable external signature wire format."
        ),
    }


def full_report() -> dict[str, Any]:
    raw = _run("full")
    checks = _checks(raw)
    if not all(checks.values()):
        raise RuntimeError("one or more normalized full checks failed")
    row = {
        "all_expected_checks_pass": True,
        "checks": checks,
        "controls_rejected": raw["controls"]["rejected"],
        "controls_tested": raw["controls"]["total"],
        "forgeries_accepted": raw["trials"]["forgeries_accepted"],
        "forgery_trials": raw["trials"]["requested"],
        "parameter_row": "GLYPH recommended: m=2048, n=1024, q=59393, B=16383, omega=16",
        "residues_exhausted": raw["selector_exhaustion"]["residues_tested"],
    }
    return {
        "all_rows_pass": True,
        "attack": {
            "message_scope": "fresh attacker-chosen message bytes",
            "result": "public-key-only fresh-message forgery",
            "signing_queries": 0,
        },
        "digests": _digests(),
        "environment": {
            "language": "GNU11 C with a Python 3 standard-library wrapper",
            "workers": 1,
        },
        "result": "PASS: the complete advertised GLYPH row accepts 64/64 zero-query forgeries",
        "results": [row],
        "scope": (
            "The numerical paper/source (z1,z2,c) and message/hash interface; "
            "the target specifies no portable external signature wire format."
        ),
    }
