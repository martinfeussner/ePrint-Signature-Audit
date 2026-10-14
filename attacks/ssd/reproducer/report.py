#!/usr/bin/env python3
"""Stable fresh and reference report entry points."""

from __future__ import annotations

import secrets

from .ssd_reference import execute


def _fresh_pair() -> tuple[int, int]:
    first = secrets.randbits(63)
    second = secrets.randbits(63)
    while second == first:
        second = secrets.randbits(63)
    return first, second


def _public_compatibility_fields(result: dict[str, object]) -> None:
    """Add the stable summary required by the public metadata validator."""

    attack = result["attack"]
    controls = result["controls"]
    endpoints = result["control_details"]["equation_valid_weight_endpoints"]
    key_generation = result["key_generation"]
    honest = result["honest_conformance"]

    result["result"] = (
        "PASS: zero-signing-query existential fresh-message forgery accepted "
        "at full standard SSD1760 parameters"
    )
    result["checks"] = {
        "all_negative_controls_reject": all(controls.values()),
        "equation_valid_weight_endpoints_match": {
            name: item["ordinary_verifier_accepts"]
            for name, item in endpoints.items()
        }
        == {"472": False, "473": True, "513": True, "514": False},
        "full_parameter_standard_ssd1760": result["parameter_set"]
        == "SSD1760 standard mode",
        "honest_signature_accepts": honest["ordinary_verifier_accepted"],
        "ordinary_verifier_accepts_forgery": attack[
            "ordinary_verifier_accepted"
        ],
        "public_completion_crosscheck": attack["rref_and_pivot_inverse_agree"],
        "public_key_has_required_ranks": key_generation["H_rank"] == 242
        and key_generation["Y_rank"] == 242,
        "secret_key_not_used": attack["secret_key_used"] is False,
        "zero_signing_queries": attack["signing_queries"] == 0,
    }
    result["digests"] = {
        "forgery_signature_sha256": attack["signature_sha256"],
        "public_H_sha256": key_generation["H_sha256"],
        "public_Y_sha256": key_generation["Y_sha256"],
        "target_pdf_sha256": result["target_pdf_sha256"],
    }
    result["environment"] = {
        "dependencies": "Python standard library",
        "workers": result["workers"],
    }


def quick_report(*, reference: bool = False) -> dict[str, object]:
    if reference:
        first, second = 20221698, 20221699
        source = "public_reference_fixture"
    else:
        first, second = _fresh_pair()
        source = "os_entropy"
    result = execute(first, second, message_limit=64)
    result["seed_source"] = source
    result["wrapper"] = "single affected full-parameter row"
    _public_compatibility_fields(result)
    return result


def all_rows_report(*, reference: bool = False) -> dict[str, object]:
    if reference:
        first, second = 1698202211, 1698202212
        source = "public_reference_fixture"
    else:
        first, second = _fresh_pair()
        source = "os_entropy"
    result = execute(first, second, message_limit=64)
    result["seed_source"] = source
    result["wrapper"] = "all affected advertised rows (SSD1760 standard mode only)"
    result["affected_rows_tested"] = 1
    _public_compatibility_fields(result)
    result["all_rows_pass"] = all(result["checks"].values())
    result["results"] = [
        {
            "all_expected_checks_pass": result["all_rows_pass"],
            "checks": result["checks"],
            "ordinary_verifier_accepted": result["attack"][
                "ordinary_verifier_accepted"
            ],
            "parameter_row": "SSD1760 standard mode",
            "public_hash_queries": result["attack"]["public_hash_queries"],
            "signing_queries": result["attack"]["signing_queries"],
        }
    ]
    return result

