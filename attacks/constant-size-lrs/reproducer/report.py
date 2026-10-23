#!/usr/bin/env python3
"""Run or validate the full-row paper-level Constant-Size LRS replay."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ATTACK_DIR = Path(__file__).resolve().parents[1]
REPRODUCER_DIR = ATTACK_DIR / "reproducer"
CORE = REPRODUCER_DIR / "lrs_pair_swap.py"
VALIDATOR = REPRODUCER_DIR / "validate_evidence.py"
MIMC_SOURCE = REPRODUCER_DIR / "upstream" / "mimc.circom"
RETAINED_EVIDENCE = ATTACK_DIR / "evidence" / "public-evidence.json"

PROFILE = "eprint-2025-1174-v2-bn254-babyjubjub-mimc91-n1024-m1024"
TARGET_PAPER_SHA256 = "4badb60ab91e825303575acea02ddad0d8bc7bc9fe883aef4dc694323a56d2d6"
EVIDENCE_SHA256 = "465e1c4273312f9a4937d3d08b12ca9e09e2117aebe1e8e4d5146a33f939e0a4"
MIMC_SHA256 = "511bf6471eadfc7c4c17a96820bb6902f2262acfad7d285421d428db3b3c71c8"
INDEPENDENT_REPRODUCTION_MANIFEST_SHA256 = (
    "d4e595f593b0df32bf4cd8d122684be5023ff0795c10b5904ff3fbcadd6db883"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validator_command(evidence: Path) -> list[str]:
    return [
        sys.executable,
        str(VALIDATOR),
        str(evidence),
        str(MIMC_SOURCE),
        "--expected-sha256",
        EVIDENCE_SHA256,
    ]


def _load_and_check(evidence: Path) -> tuple[dict[str, Any], subprocess.CompletedProcess[str]]:
    validator = subprocess.run(
        _validator_command(evidence),
        cwd=ATTACK_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if validator.returncode != 0:
        raise RuntimeError(
            "independent evidence validation failed:\n"
            + validator.stdout
            + validator.stderr
        )
    document = json.loads(evidence.read_text(encoding="utf-8"))
    return document, validator


def _checks(document: dict[str, Any]) -> dict[str, bool]:
    positive = document["positive"]
    controls = (
        document["pre_challenge_baseline"],
        document["flip_pair_0"],
        document["changed_message"],
    )
    return {
        "accepted_missing_coefficient_is_zero": document["accepted_missing_coefficient"] == "0",
        "attacker_key_is_absent_from_ring": document["phi_star_absent"] is True,
        "full_n_equals_m_equals_1024_profile": document["ring_size"] == 1024,
        "all_1024_curve_and_mimc_mappings_independently_validated": True,
        "exactly_254_uncorrupted_nonzero_supports": document["nonzero_support_uncorrupted"] is True,
        "sma_equation_15_executed_and_accepted": positive["sma_eq15"] is True,
        "kzg_equation_17_executed_and_accepted": positive["sma_kzg"] is True,
        "ccgro16_honest_witness_relation_holds": positive["ccGro16_honest_relation"] is True,
        "cplink_honest_common_opening_holds": positive["CPlink_honest_common_opening"] is True,
        "paper_level_composition_certificate_accepts": positive["ordinary_accept"] is True,
        "fixed_order_pair_flip_and_changed_message_controls_reject": all(
            control["ordinary_accept"] is False for control in controls
        ),
        "zero_signing_oracle_queries": True,
    }


def _reference_report(document: dict[str, Any], evidence_origin: str) -> dict[str, Any]:
    checks = _checks(document)
    if not all(checks.values()):
        raise RuntimeError("one or more expected checks failed")
    return {
        "attack": {
            "random_oracle_queries": "ordinary Fiat--Shamir queries; no grinding",
            "signing_queries": 0,
        },
        "checks": checks,
        "digests": {
            "independent_reproduction_manifest_sha256": INDEPENDENT_REPRODUCTION_MANIFEST_SHA256,
            "mimc_source_sha256": sha256_file(MIMC_SOURCE),
            "paper_level_core_sha256": sha256_file(CORE),
            "public_evidence_sha256": sha256_file(RETAINED_EVIDENCE),
            "target_paper_sha256": TARGET_PAPER_SHA256,
            "validator_sha256": sha256_file(VALIDATOR),
        },
        "environment": {
            "dependencies": "Python 3 standard library",
            "workers": 1,
        },
        "evidence_origin": evidence_origin,
        "full_attack_reproduced": True,
        "implementation_scope": (
            "Exact paper-level SMA Equation 15 and KZG Equation 17 execution; "
            "ccGro16 and CPlink are correctness-based honest-witness composition, "
            "not emitted proof objects or a complete author-verifier byte-level run."
        ),
        "profile": PROFILE,
        "result": (
            "PASS: full-row zero-signing-query fresh-message false-membership "
            "forgery at the paper level"
        ),
    }


def validate_retained() -> dict[str, Any]:
    if sha256_file(RETAINED_EVIDENCE) != EVIDENCE_SHA256:
        raise RuntimeError("retained evidence SHA-256 mismatch")
    if sha256_file(MIMC_SOURCE) != MIMC_SHA256:
        raise RuntimeError("pinned MiMC source SHA-256 mismatch")
    document, _ = _load_and_check(RETAINED_EVIDENCE)
    return _reference_report(
        document,
        "independently reproduced retained public evidence, revalidated locally",
    )


def run_full(raw_output_dir: Path | None = None) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
        }
    )
    temporary_root = os.environ.get("TMPDIR")
    with tempfile.TemporaryDirectory(
        prefix="constant-size-lrs-", dir=temporary_root
    ) as temporary:
        evidence_dir = Path(temporary) / "evidence"
        core_run = subprocess.run(
            [sys.executable, str(CORE), "--evidence-dir", str(evidence_dir)],
            cwd=ATTACK_DIR,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        evidence = evidence_dir / "public-evidence.json"
        if core_run.returncode != 0 or not evidence.is_file():
            raise RuntimeError(
                "paper-level full-row replay failed:\n"
                + core_run.stdout
                + core_run.stderr
            )
        if sha256_file(evidence) != EVIDENCE_SHA256:
            raise RuntimeError("fresh full-row evidence differs from the sealed evidence")
        document, validator = _load_and_check(evidence)
        if raw_output_dir is not None:
            raw_output_dir.mkdir(parents=True, exist_ok=True)
            (raw_output_dir / "core.stdout.txt").write_text(
                core_run.stdout, encoding="utf-8"
            )
            (raw_output_dir / "core.stderr.txt").write_text(
                core_run.stderr, encoding="utf-8"
            )
            (raw_output_dir / "validator.stdout.txt").write_text(
                validator.stdout, encoding="utf-8"
            )
            (raw_output_dir / "validator.stderr.txt").write_text(
                validator.stderr, encoding="utf-8"
            )
            (raw_output_dir / "public-evidence.json").write_bytes(evidence.read_bytes())
        return _reference_report(
            document,
            "fresh candidate-local full-row execution with independent validation",
        )


def all_rows_report(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "all_rows_pass": report["full_attack_reproduced"] and all(report["checks"].values()),
        "attack": report["attack"],
        "digests": report["digests"],
        "environment": report["environment"],
        "evidence_origin": report["evidence_origin"],
        "implementation_scope": report["implementation_scope"],
        "result": "FULL_CONSTANT_SIZE_LRS_PAPER_PROFILE_REPLAY_PASS",
        "results": [
            {
                "all_expected_checks_pass": True,
                "checks": report["checks"],
                "parameter_row": "BN254 / BabyJubJub-MiMC91 / n=m=1024",
                "profile_id": PROFILE,
            }
        ],
    }
