#!/usr/bin/env python3
"""Validate the public SSD attack package with the Python standard library."""

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
    all_rows = json.loads(
        (ROOT / "all-rows-reference-output.json").read_text(encoding="utf-8")
    )
    affected = json.loads((ROOT / "affected-rows.json").read_text(encoding="utf-8"))
    tex = (ROOT / "paper/attack.tex").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    require(metadata["eprint_id"] == "2022/1698", "wrong target identifier")
    require(metadata["layer"] == "design", "wrong layer")
    require(metadata["full_scale"] is True, "full_scale must be true")
    require(metadata["workers"] == 1, "worker count must be one")
    require(metadata["signing_queries"] == 0, "signing-query count changed")
    require(metadata["independent_reproduction"] is True, "independent gate missing")
    require(metadata["attack_history_status"] == "PASS_FINAL_EXACT_TARGET_RECHECK", "history gate")
    require(
        metadata["publication_status"] == "VERIFIED_ATTACK",
        "publication status",
    )
    require(metadata["verified_attack"] is True, "verified attack flag")
    require(
        metadata["publication_gates"]["independent_reproduction"]
        == "PASS_5_OF_5_FRESH_KEYS",
        "independent reproduction gate",
    )
    require(
        metadata["publication_gates"]["exact_target_history"] == "PASS",
        "final history gate",
    )
    require(
        metadata["publication_gates"]["independent_publication_review"] == "PASS",
        "publication review gate",
    )
    require(metadata["attack_paper_authors"] == ["Martin Feussner"], "paper byline")
    require(
        metadata["attack_paper_affiliation"] == "Selmer Center, University of Bergen",
        "paper affiliation",
    )
    require(metadata["attack_paper_contact"] == "martin.feussner@uib.no", "paper contact")

    pins = {
        "reproducer_sha256": "reproduce.py",
        "independent_reproducer_sha256": "reproduce-all-rows.py",
        "public_reproducer_core_sha256": "reproducer/ssd_reference.py",
        "public_report_core_sha256": "reproducer/report.py",
        "reference_output_sha256": "reference-output.json",
        "all_rows_reference_output_sha256": "all-rows-reference-output.json",
        "attack_paper_sha256": "paper/attack.pdf",
        "attack_paper_source_sha256": "paper/attack.tex",
        "attack_paper_makefile_sha256": "paper/Makefile",
    }
    for field, path in pins.items():
        require(metadata[field] == digest(path), f"metadata hash mismatch for {path}")

    expected_probability = "0.9303737782253141"
    for report in (quick, all_rows):
        require(report["status"] == "PASS", "reference status")
        require(report["banner"] == "ATTACK REPRODUCTION: PASS", "reference banner")
        require(report["parameter_set"] == "SSD1760 standard mode", "parameter scope")
        require(report["workers"] == 1, "reference worker count")
        require(isinstance(report["result"], str) and report["result"], "public result")
        require(report["checks"] and all(report["checks"].values()), "public checks")
        require(report["digests"], "public digests")
        require(report["environment"]["workers"] == metadata["workers"], "public workers")
        require(report["attack"]["signing_queries"] == 0, "reference signing queries")
        require(
            report["attack"]["signing_queries"] == metadata["signing_queries"],
            "metadata signing-query mismatch",
        )
        require(report["attack"]["secret_key_used"] is False, "attack used a secret")
        require(report["attack"]["ordinary_verifier_accepted"] is True, "forgery rejected")
        require(
            report["attack"]["random_oracle_probability"]["decimal"]
            == expected_probability,
            "probability mismatch",
        )
        require(all(report["controls"].values()), "ordinary-verifier control failure")
        endpoints = report["control_details"]["equation_valid_weight_endpoints"]
        require(
            {key: value["ordinary_verifier_accepts"] for key, value in endpoints.items()}
            == {"472": False, "473": True, "513": True, "514": False},
            "endpoint semantics",
        )
        require(all(value["equation_holds"] for value in endpoints.values()), "endpoint equation")
        require(
            report["specification_diagnostics"]["gen1_alpha0_equals_r"][
                "cannot_supply_required_rows"
            ]
            is True,
            "Gen1 rank diagnostic",
        )

    require(all_rows["all_rows_pass"] is True, "all-rows result")
    require(len(all_rows["results"]) == 1, "all-rows result count")
    require(
        all_rows["results"][0]["parameter_row"] == "SSD1760 standard mode",
        "all-rows parameter identity",
    )
    require(
        all_rows["results"][0]["all_expected_checks_pass"] is True,
        "all-rows expected checks",
    )

    require(len(affected["rows"]) == 1, "affected-row count")
    require(affected["rows"][0]["id"] == "SSD1760-standard", "affected-row identity")

    disclosure = "This audit used the OpenAI model Daybreak Blue at the ultra reasoning level."
    acknowledgement = (
        "\\section*{Acknowledgements}\n"
        "The computations were performed on the Norwegian Research and Education "
        "Cloud (NREC), using resources provided by the University of Bergen and "
        "the University of Oslo."
    )
    require(disclosure in tex, "required opening disclosure missing")
    require("OpenAI Codex generated and selected this paper's title" in tex, "title disclosure")
    require(acknowledgement in tex, "exact NREC acknowledgement missing")
    require(tex.count(disclosure) == 1, "opening disclosure count")
    require(tex.index("\\maketitle") < tex.index(disclosure) < tex.index("\\begin{abstract}"), "disclosure placement")
    tex_lines = tex.splitlines()
    require(
        r"\title{\bfseries Syndromes Solved Directly:\\" in tex_lines
        and "A Zero-Signing-Query Forgery against SSD}" in tex_lines,
        "exact accurate paper title",
    )
    require(
        r"\author{Martin Feussner\\" in tex_lines
        and r"\small Selmer Center, University of Bergen\\" in tex_lines
        and r"\small \texttt{martin.feussner@uib.no}}" in tex_lines,
        "exact paper byline",
    )
    require("remain pending" not in tex.lower(), "stale pending gate in paper")
    require("remain pending" not in readme.lower(), "stale pending gate in README")
    stale_publication_phrases = (
        "private package",
        "publication-ready private report",
        "awaiting exact public import",
        "ready for exact import",
        "has not itself been published",
        "public repository is not modified by this package",
        "did not modify or publish the public repository",
    )
    for phrase in stale_publication_phrases:
        require(phrase not in tex.lower(), f"stale publication wording in paper: {phrase}")
        require(phrase not in readme.lower(), f"stale publication wording in README: {phrase}")
    require(
        "This public package is published in the ePrint Signature Audit repository"
        in readme,
        "public-package status missing from README",
    )
    require(
        "These materials are published in the ePrint Signature\nAudit repository."
        in tex,
        "public-package status missing from paper",
    )

    independent = metadata["independent_reproduction_evidence"]
    require(independent["fresh_keys"] == 5, "independent key count")
    require(independent["successes"] == 5, "independent success count")
    require(independent["total_central_signing_queries"] == 0, "independent signing queries")
    require(
        independent["sealed_manifest_sha256"]
        == "2608c672de46fd87302c8a8b6d5f3c08b3fb1ffbde39be599e4c8a7facf1abb6",
        "independent manifest pin",
    )
    require(
        metadata["history_evidence"]["final_history_handoff_sha256"]
        == "b9d961b3b4b4589eea231ffeb0adb511b3bea918c55e1e56a1a3ddbf58544759",
        "final history handoff pin",
    )

    for markdown in ROOT.rglob("*.md"):
        require("\\operatorname" not in markdown.read_text(encoding="utf-8"), f"operatorname in {markdown}")

    print("PACKAGE VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

