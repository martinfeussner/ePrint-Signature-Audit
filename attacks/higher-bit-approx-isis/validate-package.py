#!/usr/bin/env python3
"""Validate the verified attack package with the standard library."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def digest(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"PACKAGE VALIDATION: FAIL: {message}")


def main() -> int:
    metadata = json.loads((ROOT / "metadata.json").read_text(encoding="utf-8"))
    quick = json.loads((ROOT / "reference-output.json").read_text(encoding="utf-8"))
    full = json.loads(
        (ROOT / "all-rows-reference-output.json").read_text(encoding="utf-8")
    )
    rows = json.loads((ROOT / "affected-rows.json").read_text(encoding="utf-8"))
    tex = (ROOT / "paper/attack.tex").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    required = {
        "scheme",
        "eprint_id",
        "eprint_version",
        "attack_history_checked_at",
        "prior_public_attack_located",
        "attack_result",
        "attack_technique",
        "layer",
        "affected_parameters",
        "full_scale",
        "runtime_seconds",
        "peak_ram_mb",
        "workers",
        "independent_reproduction",
        "reproducer_sha256",
        "independent_reproducer_sha256",
        "public_reproducer_core_sha256",
        "sealed_independent_reproducer_sha256",
        "reference_output_sha256",
        "all_rows_reference_output_sha256",
        "attack_paper_authors",
        "attack_paper_affiliation",
        "attack_paper_contact",
        "attack_paper_sha256",
        "attack_paper_source_sha256",
        "attack_paper_makefile_sha256",
    }
    require(required <= metadata.keys(), "metadata is missing a schema field")
    require(metadata["eprint_id"] == "2022/1144", "wrong ePrint identifier")
    require(metadata["layer"] == "design", "wrong attack layer")
    require(metadata["full_scale"] is True, "full_scale must be true")
    require(metadata["workers"] == 1, "worker count must be one")
    require(metadata["independent_reproduction"] is True, "independent pass absent")
    require(metadata["prior_public_attack_located"] is False, "history field changed")
    require(
        metadata["attack_history_status"] == "PASS_NO_PRIOR_PUBLIC_ATTACK_LOCATED",
        "final history gate did not pass",
    )
    require(
        metadata["publication_status"] == "VERIFIED_ATTACK",
        "wrong publication status",
    )
    require(metadata["verified_attack"] is True, "verified attack flag is false")
    require(
        metadata["publication_gates"]["exact_target_history"] == "PASS",
        "exact-target history gate did not pass",
    )
    require(
        metadata["publication_gates"]["independent_publication_review"] == "PASS",
        "publication review gate did not pass",
    )
    require(
        metadata["attack_paper_authors"] == ["Martin Feussner"], "wrong paper byline"
    )
    require(
        metadata["attack_paper_affiliation"] == "Selmer Center, University of Bergen",
        "wrong affiliation",
    )
    require(metadata["attack_paper_contact"] == "martin.feussner@uib.no", "wrong contact")

    pins = {
        "reproducer_sha256": "reproduce.py",
        "independent_reproducer_sha256": "reproduce-all-rows.py",
        "public_reproducer_core_sha256": "reproducer/hbaisis_reference.py",
        "reference_output_sha256": "reference-output.json",
        "all_rows_reference_output_sha256": "all-rows-reference-output.json",
        "attack_paper_sha256": "paper/attack.pdf",
        "attack_paper_source_sha256": "paper/attack.tex",
        "attack_paper_makefile_sha256": "paper/Makefile",
    }
    for field, path in pins.items():
        require(metadata[field] == digest(path), f"metadata hash mismatch for {path}")
    require(
        metadata["sealed_independent_reproducer_sha256"]
        == "137fd994f361316755f0935a189ea723b75e6832b87303e56658abda481b0b25",
        "sealed independent reproducer hash changed",
    )

    require(quick["status"] == "PASS" and quick["rows_passed"] == 3, "quick result")
    require(quick["accepted_target_checks"] == 48, "quick target count")
    require(full["status"] == "PASS" and full["rows_passed"] == 3, "full result")
    require(full["accepted_target_checks"] == 384, "full target count")
    require(full["signing_queries"] == 0 and full["workers"] == 1, "full resources")
    require(len(rows["rows"]) == 3, "affected-row transcription")
    for report in (quick, full):
        require(isinstance(report.get("result"), str) and report["result"], "result")
        require(
            isinstance(report.get("checks"), dict)
            and report["checks"]
            and all(value is True for value in report["checks"].values()),
            "public compatibility checks",
        )
        require(
            isinstance(report.get("digests"), dict)
            and report["digests"]
            and all(
                key.endswith("_sha256")
                and isinstance(value, str)
                and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
                for key, value in report["digests"].items()
            ),
            "public compatibility digests",
        )
        require(
            report.get("attack", {}).get("signing_queries")
            == metadata["signing_queries"],
            "public compatibility signing-query count",
        )
        require(
            report.get("environment", {}).get("workers") == metadata["workers"],
            "public compatibility worker count",
        )
        require(report.get("all_rows_pass") is True, "all_rows_pass")
        compatibility_rows = report.get("results")
        require(
            isinstance(compatibility_rows, list)
            and len(compatibility_rows) == 3
            and len({result.get("parameter_row") for result in compatibility_rows}) == 3
            and all(
                isinstance(result.get("parameter_row"), str)
                and result["parameter_row"]
                and result.get("all_expected_checks_pass") is True
                for result in compatibility_rows
            ),
            "all-row compatibility results",
        )
        require(report["lifts"] == ["canonical", "centered"], "lift coverage")
        for row in report["rows"]:
            diagnostics = row["diagnostics"]["precommitted_target_vector"]["results"]
            require(
                all(diagnostics[lift]["accepts"] is False for lift in report["lifts"]),
                "precommitted in-domain diagnostic did not reject",
            )

    disclosure = (
        "This audit used the OpenAI model Daybreak Blue at the ultra reasoning level."
    )
    acknowledgement = (
        "\\section*{Acknowledgements}\n"
        "The computations were performed on the Norwegian Research and Education "
        "Cloud (NREC), using resources provided by the University of Bergen and "
        "the University of Oslo."
    )
    require(disclosure in tex, "required AI disclosure missing")
    require("OpenAI Codex generated and selected this paper's title" in tex, "title disclosure")
    require(acknowledgement in tex, "exact NREC acknowledgement missing")
    history_statement = (
        "No prior public attack against the Higher-Bit Approximate-ISIS hash-and-sign\n"
        "signature of ePrint 2022/1144 was located in the searches performed as of\n"
        "2026-10-14."
    )
    require(history_statement in tex, "conservative final-history wording missing from paper")
    require(history_statement in readme, "conservative final-history wording missing from README")
    history = metadata["history_evidence"]
    require(
        history["final_history_handoff_sha256"]
        == "daadbc0743cb5ff1c76d2b1cd842261157e3dd438f06bc35579ee1529431c81b",
        "final-history handoff hash mismatch",
    )
    require(
        history["prior_art_manifest_sha256"]
        == "9702681ceaaeb90882e0d04c9058f4558fe3f0a5412be2211bd3ede6212d4657",
        "final-history evidence-manifest hash mismatch",
    )

    print("PACKAGE VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

