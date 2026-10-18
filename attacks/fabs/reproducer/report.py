"""Stable public reports for the FABS Figure 1 reproducer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .fabs_reference import run


TARGET_PAPER_SHA256 = (
    "0660d99b322467489a85f9a7f239c145b00b5a024958e474cee295361364e8a8"
)
INDEPENDENT_MANIFEST_SHA256 = (
    "348d1a6557ce212ef33c312e63d1da5e0162363e9967c0d3be3f8343f8da10bf"
)
INDEPENDENT_VERDICT_SHA256 = (
    "2e51b768bf14783990beeeb545bff68aaaaea91a7b0bc2ce7d4d010cf28dd68d"
)
INDEPENDENT_HANDOFF_SHA256 = (
    "8f43c3ce8af69a3f90d69520023ca435a0d79b001e2d972e8d77e59a8021e92d"
)
INDEPENDENT_STDOUT_SHA256 = (
    "df517733aa6c7cfb48b1e2ac6729ddb04a2c56647baaa713566ebe5a62e33907"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _evidence() -> tuple[dict[str, Any], dict[str, str]]:
    raw = run()
    core = Path(__file__).with_name("fabs_reference.py")
    actual = Path(__file__).with_name("actual-bn254")
    digests = {
        "actual_bn254_cargo_lock_sha256": _sha256((actual / "Cargo.lock").read_bytes()),
        "actual_bn254_cargo_toml_sha256": _sha256((actual / "Cargo.toml").read_bytes()),
        "actual_bn254_encoding_sha256": _sha256((actual / "ENCODING.md").read_bytes()),
        "actual_bn254_source_sha256": _sha256((actual / "src" / "main.rs").read_bytes()),
        "independent_first_run_stdout_sha256": INDEPENDENT_STDOUT_SHA256,
        "independent_reproduction_handoff_sha256": INDEPENDENT_HANDOFF_SHA256,
        "independent_reproduction_manifest_sha256": INDEPENDENT_MANIFEST_SHA256,
        "independent_reproduction_verdict_sha256": INDEPENDENT_VERDICT_SHA256,
        "reproducer_core_sha256": _sha256(core.read_bytes()),
        "stable_raw_output_sha256": _sha256(_canonical(raw)),
        "target_paper_sha256": TARGET_PAPER_SHA256,
    }
    return raw, digests


def quick_report() -> dict[str, Any]:
    """Return a compact replay of the full 100-attribute attack endpoint."""

    raw, digests = _evidence()
    attacks = raw["attack_runs"]
    negatives = raw["negative_controls_acceptance"]
    fresh = raw["fresh_message_controls"]
    resources = raw["adversary_resources_per_forgery"]
    checks = {
        "all_eight_negative_controls_rejected": len(negatives) == 8
        and not any(negatives.values()),
        "all_identity_100_accepted": attacks["all_identity_attributes_100"]["accepted"],
        "fresh_message_forgeries_accepted": len(fresh) == 4 and all(fresh.values()),
        "honest_100_attribute_control_accepted": raw["honest_controls"]["all_and_100"],
        "minimal_nonidentity_100_accepted": attacks["nonidentity_attributes_100"]["accepted"],
        "strengthened_nonidentity_100_accepted": attacks[
            "strengthened_nonidentity_attributes_100"
        ]["accepted"],
        "strengthened_transmitted_components_nonidentity": not any(
            attacks["strengthened_nonidentity_attributes_100"][name]
            for name in ("A_identity", "B_identity", "C_identity")
        ),
        "zero_key_and_signing_queries": resources["key_generation_queries"] == 0
        and resources["signing_queries"] == 0,
    }
    if not all(checks.values()):
        raise AssertionError("FABS quick replay failed")
    return {
        "attack": {
            "H0_queries": 1,
            "key_generation_queries": 0,
            "signing_queries": 0,
        },
        "checks": checks,
        "digests": digests,
        "environment": {
            "dependencies": "Python 3 standard library",
            "workers": 1,
        },
        "full_attack_reproduced": True,
        "independent_reproduction": {
            "actual_pairing": True,
            "backend": "ark-bn254 0.4.0 via Arkworks 0.4",
            "peak_rss_kib": 31744,
            "setup_alphas_role": "fixed deterministic controls, not random-key statistical trials",
            "setup_alphas_u64": [1, 2, 3, 5, 7],
            "status": "PASS",
            "successes": 5,
            "trials": 5,
            "wall_seconds": 3.77,
            "workers": 1,
        },
        "mode": "stable_paper_level_and100_package_replay",
        "result": (
            "PASS: literal Figure 1 accepted all-identity, nonidentity, and "
            "strengthened zero-signing-query fresh-message forgeries"
        ),
    }


def all_rows_report() -> dict[str, Any]:
    """Return stable reports for every retained public attack presentation."""

    raw, digests = _evidence()
    attacks = raw["attack_runs"]
    reference = raw["reference_case"]
    cases = (
        (
            "FABS-FIGURE1-IDENTITY-AND100",
            "all_identity_attributes_100",
            {
                "ordinary_verifier_accepted": True,
                "one_H0_query": True,
                "zero_H1_queries": True,
                "zero_key_queries": True,
                "zero_signing_queries": True,
            },
        ),
        (
            "FABS-FIGURE1-NONIDENTITY-AND100",
            "nonidentity_attributes_100",
            {
                "A_B_C_nonidentity": True,
                "ordinary_verifier_accepted": True,
                "one_H0_query": True,
                "zero_H1_queries": True,
                "zero_key_queries": True,
                "zero_signing_queries": True,
            },
        ),
        (
            "FABS-FIGURE1-STRENGTHENED-NONIDENTITY-AND100",
            "strengthened_nonidentity_attributes_100",
            {
                "A_B_C_Z_W_nonidentity": True,
                "all_100_attribute_responses_nonzero": True,
                "ordinary_verifier_accepted": True,
                "one_H0_query": True,
                "one_H1_query_per_attribute": True,
                "zero_key_queries": True,
                "zero_signing_queries": True,
            },
        ),
    )
    results: list[dict[str, Any]] = []
    for row, key, expected in cases:
        attack = attacks[key]
        if row.endswith("IDENTITY-AND100") and "NONIDENTITY" not in row:
            checks = {
                "ordinary_verifier_accepted": attack["accepted"],
                "one_H0_query": attack["forger_h0_queries"] == 1,
                "zero_H1_queries": attack["forger_h1_queries"] == 0,
                "zero_key_queries": attack["key_queries"] == 0,
                "zero_signing_queries": attack["signing_queries"] == 0,
            }
        elif row == "FABS-FIGURE1-NONIDENTITY-AND100":
            checks = {
                "A_B_C_nonidentity": not any(
                    attack[name] for name in ("A_identity", "B_identity", "C_identity")
                ),
                "ordinary_verifier_accepted": attack["accepted"],
                "one_H0_query": attack["forger_h0_queries"] == 1,
                "zero_H1_queries": attack["forger_h1_queries"] == 0,
                "zero_key_queries": attack["key_queries"] == 0,
                "zero_signing_queries": attack["signing_queries"] == 0,
            }
        else:
            checks = {
                "A_B_C_Z_W_nonidentity": not any(
                    attack[name] for name in ("A_identity", "B_identity", "C_identity")
                )
                and not reference["strengthened_Z_identity"]
                and not reference["strengthened_W_identity"],
                "all_100_attribute_responses_nonzero": attack["s_i_all_nonzero"],
                "ordinary_verifier_accepted": attack["accepted"],
                "one_H0_query": attack["forger_h0_queries"] == 1,
                "one_H1_query_per_attribute": attack["forger_h1_queries"] == 100,
                "zero_key_queries": attack["key_queries"] == 0,
                "zero_signing_queries": attack["signing_queries"] == 0,
            }
        if checks != expected:
            raise AssertionError(f"FABS case failed: {row}")
        results.append(
            {
                "all_expected_checks_pass": all(checks.values()),
                "attribute_count": 100,
                "checks": checks,
                "parameter_row": row,
                "profile_id": raw["profile_id"],
            }
        )

    all_rows_pass = all(item["all_expected_checks_pass"] for item in results)
    if not all_rows_pass:
        raise AssertionError("FABS all-row replay failed")
    return {
        "all_rows_pass": all_rows_pass,
        "attack": {
            "H0_queries_per_forgery": 1,
            "key_generation_queries": 0,
            "signing_queries": 0,
        },
        "digests": digests,
        "evidence_origin": (
            "stable publication-package typed-group replay; distinct from the "
            "sealed fresh-context actual-pairing independent reproduction"
        ),
        "full_attack_reproduced": True,
        "independent_reproduction": {
            "actual_pairing": True,
            "backend": "ark-bn254 0.4.0 via Arkworks 0.4",
            "honest_attribute_counts": [1, 3, 100],
            "negative_controls_rejected_per_trial": 8,
            "peak_rss_kib": 31744,
            "setup_alphas_role": "fixed deterministic controls, not random-key statistical trials",
            "setup_alphas_u64": [1, 2, 3, 5, 7],
            "status": "PASS",
            "successes": 5,
            "trials": 5,
            "wall_seconds": 3.77,
            "workers": 1,
        },
        "result": "FULL_FABS_FIGURE1_PACKAGE_REPLAY_PASS",
        "results": results,
    }

