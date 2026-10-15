#!/usr/bin/env python3
"""Validate the final EagleSignV3 publication package."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parent
TITLE = "The Eagle Has Wrapped: Practical Public-r Key Recovery against EagleSignV3"
DISCLOSURE = "This audit used the OpenAI model Daybreak Blue at the ultra reasoning level."
ACKNOWLEDGEMENT = (
    "The computations were performed on the Norwegian Research and Education "
    "Cloud (NREC), using resources provided by the University of Bergen and "
    "the University of Oslo."
)
HISTORY_STATEMENT = (
    "No prior public substantive attack against EagleSignV3 (IACR ePrint "
    "2024/1234) was located in the searches performed as of 15 October 2026."
)
HISTORY_ATTRIBUTION = (
    "Pulles and Tibouchi previously broke EagleSign V1 and V2 using response "
    "statistics and ideal structure. Those schemes use different response "
    "relations, and EagleSign V2 includes an explicit centered-modulus-boundary "
    "rejection that is absent from the EagleSignV3 specification studied here. "
    "We located no earlier public disclosure applying the centered-modulus-wrap, "
    "public-commitment-label route to EagleSignV3. This is a bounded search "
    "statement; we make no absolute firstness or attack-technique novelty claim."
)
VERIFICATION_BASIS = (
    "Primary full-parameter attack, hostile adversarial review, prospectively "
    "sealed fresh-context independent reproduction, fresh-key public-package "
    "replay, final exact-target history recheck, and independent Publication "
    "Review passed"
)
REPRODUCER_FINAL_SENTENCE = "Final exact-target history and independent Publication Review passed."
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"PACKAGE VALIDATION: FAIL: {message}")


def digest(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_canonical_json(relative: str) -> Any:
    path = ROOT / relative
    source = path.read_text(encoding="utf-8")
    value = json.loads(source, object_pairs_hook=unique_object)
    canonical = json.dumps(value, indent=2, sort_keys=True) + "\n"
    require(source == canonical, f"{relative} is not canonical JSON")
    return value


def valid_digest(value: object) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None and value != "0" * 64


def validate_manifest(base: Path, *, allow_missing: bool) -> None:
    manifest = base / "SHA256SUMS"
    if allow_missing and not manifest.exists():
        return
    require(manifest.is_file() and not manifest.is_symlink(), f"{manifest.relative_to(ROOT)} missing")
    seen: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        relative = relative.removeprefix("./")
        require(relative != "SHA256SUMS", "manifest hashes itself")
        require(relative not in seen, f"duplicate manifest path {relative}")
        require(SHA256.fullmatch(expected) is not None, f"bad manifest hash for {relative}")
        path = base / relative
        require(path.is_file() and not path.is_symlink(), f"missing manifest path {relative}")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, f"hash mismatch {relative}")
        seen.add(relative)
    actual = {
        str(path.relative_to(base))
        for path in base.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path != manifest
        and "build" not in path.relative_to(base).parts
        and "output" not in path.relative_to(base).parts
        and path.suffix not in {".aux", ".log", ".out", ".toc"}
    }
    require(seen == actual, f"manifest coverage differs for {base.relative_to(ROOT) or Path('.')}")


def validate_reference(value: dict[str, Any], *, full: bool) -> None:
    require(isinstance(value.get("result"), str) and value["result"], "reference result")
    digests = value.get("digests")
    require(isinstance(digests, dict) and digests, "reference digests")
    require(
        all(name.endswith("_sha256") and valid_digest(item) for name, item in digests.items()),
        "reference digest format",
    )
    if not full:
        require(value["result"].startswith("STRUCTURAL_SMOKE_PASS"), "smoke result")
        require(value.get("mode") == "structural_smoke", "smoke mode")
        require(value.get("full_attack_reproduced") is False, "smoke boundary")
        require(value.get("environment", {}).get("workers") == 1, "smoke workers")
        checks = value.get("checks")
        require(isinstance(checks, dict) and checks and all(checks.values()), "smoke checks")
        return
    require(value["result"] == "FULL_FRESH_KEY_ATTACK_REPRODUCTION_PASS", "full result")
    require(value.get("full_attack_reproduced") is True, "full reproduction flag")
    require(value.get("all_rows_pass") is True, "all-rows pass flag")
    require(value.get("attack", {}).get("signing_queries") == 40000, "full query count")
    require(value.get("resources", {}).get("workers") == 1, "full worker count")
    require(value.get("resources", {}).get("full_pipeline_wall_seconds") == 296.09, "full runtime")
    require(value.get("resources", {}).get("full_pipeline_peak_rss_kib") == 221272, "full peak RSS")
    rows = value.get("results")
    require(isinstance(rows, list) and len(rows) == 1, "full row count")
    row = rows[0]
    require(row.get("all_expected_checks_pass") is True, "full row controls")
    require(row.get("signing_queries") == 40000, "full row queries")
    require(row.get("constraints") == 21982 and row.get("wraps") == 1767, "full row evidence")
    require(row.get("ordinary_verifier_rejected_outputs") == 1727, "full invalid-output count")
    checks = row.get("checks")
    require(isinstance(checks, dict) and len(checks) == 12 and all(checks.values()), "full checks")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-missing-manifest", action="store_true")
    args = parser.parse_args()

    required = (
        "README.md",
        "metadata.json",
        "affected-rows.json",
        "reference-output.json",
        "all-rows-reference-output.json",
        "reproduce.py",
        "reproduce-all-rows.py",
        "validate-package.py",
        "Makefile",
        "paper/attack.tex",
        "paper/attack.pdf",
        "paper/Makefile",
        "reproducer/README.md",
        "reproducer/Makefile",
        "reproducer/reproduce.sh",
        "reproducer/report.py",
        "reproducer/solve_milp.py",
        "reproducer/requirements.txt",
        "reproducer/SPECIFICATION_COMPLETIONS.md",
        "reproducer/validation/independent-replay-20261015.json",
        "reproducer/src/public_scheme.hpp",
        "reproducer/src/secret_scheme.hpp",
        "reproducer/src/selftest.cpp",
        "reproducer/src/keygen.cpp",
        "reproducer/src/oracle.cpp",
        "reproducer/src/recover.cpp",
        "reproducer/src/verify.cpp",
        "reproducer/src/compare_ground_truth.cpp",
    )
    for relative in required:
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"missing regular file {relative}")
    require(not any(path.is_symlink() for path in ROOT.rglob("*")), "symlink present")
    require(not any(path.name == "__pycache__" for path in ROOT.rglob("*")), "Python cache present")
    require(
        not any(path.suffix in {".aux", ".log", ".out", ".toc"} for path in ROOT.rglob("*")),
        "build debris present",
    )
    require(not (ROOT / "reproducer/build").exists(), "reproducer build directory present")
    require(not (ROOT / "reproducer/output").exists(), "reproducer output directory present")
    require(not (ROOT / "DRAFT_SHA256SUMS").exists(), "legacy draft manifest present")
    require(not (ROOT / "DRAFT_SHA256SUMS.sha256").exists(), "legacy draft sidecar present")
    require(not (ROOT / "DRAFT_STATUS.md").exists(), "draft status file present")

    metadata = load_canonical_json("metadata.json")
    affected = load_canonical_json("affected-rows.json")
    quick = load_canonical_json("reference-output.json")
    full = load_canonical_json("all-rows-reference-output.json")
    replay = load_canonical_json("reproducer/validation/independent-replay-20261015.json")
    validate_reference(quick, full=False)
    validate_reference(full, full=True)

    require(metadata["scheme"] == "EagleSignV3", "scheme")
    require(metadata["attack_title"] == TITLE, "attack title")
    require(metadata["eprint_date"] == "2024-08-03", "ePrint date")
    require(metadata["eprint_id"] == "2024/1234", "ePrint identifier")
    require(
        metadata["family"]
        == "Fiat-Shamir-with-aborts lattice signature over a negacyclic ring or module",
        "catalog family",
    )
    require(metadata["layer"] == "design", "attack layer")
    require(metadata["full_scale"] is True, "full-scale flag")
    require(metadata["signing_queries"] == 40000, "query count")
    require(metadata["workers"] == 1, "worker count")
    require(metadata["runtime_seconds"] == 296.09, "runtime")
    require(metadata["peak_ram_mb"] == 216.0859375, "peak RAM")
    require(metadata["independent_reproduction"] is True, "independent reproduction")
    require(metadata["technique_originality_claimed"] is False, "technique novelty boundary")
    require(metadata["prior_public_attack_located"] is False, "bounded history result")
    require(metadata["title_ai_generated"] is True, "AI title provenance")
    require(metadata["title_wordplay_selected_by_codex"] is True, "AI wordplay provenance")
    require(metadata["attack_paper_authors"] == ["Martin Feussner"], "paper author")
    require(metadata["attack_paper_affiliation"] == "Selmer Center, University of Bergen", "affiliation")
    require(metadata["attack_paper_contact"] == "martin.feussner@uib.no", "contact")
    require(metadata["attack_paper_pages"] == 9, "paper page count")
    require(metadata["human_verification"] is False, "human verification flag")
    require(metadata["human_verification_required"] is False, "human verification requirement")
    require(metadata["verified_attack"] is True, "verified attack flag")
    require(metadata["counts_as_completed_audit"] is True, "completed-audit count flag")
    require(metadata["counts_as_verified_attack"] is True, "verified-attack count flag")
    require(metadata["trials"] == 2 and metadata["successes"] == 2, "trial counts")
    require("primary execution and prospectively sealed independent reproduction" in metadata["trial_scope"], "two-key trial scope")
    require("supplemental release validation" in metadata["trial_scope"], "supplemental replay scope")
    require(metadata["publication_status"] == "VERIFIED_ATTACK", "publication status")
    require(metadata["verification_basis"] == VERIFICATION_BASIS, "verification basis")
    require(
        metadata["ai_provenance"]["publication_review"]
        == "independent AI Publication Reviewer; PASS / NO VETO",
        "Publication Review AI provenance",
    )
    require(metadata["publication_review_evidence"]["status"] == "PASS / NO VETO", "Publication Review status")
    gates = metadata["publication_gates"]
    require(gates["primary_reproduction"] == "PASS", "primary gate")
    require(gates["hostile_adversarial_review"] == "PASS_WITH_LIMITATIONS_NO_VETO", "adversarial gate")
    require(gates["fresh_context_independent_reproduction"] == "PASS", "independent gate")
    require(gates["final_exact_target_history"] == "PASS", "final history gate")
    require(gates["independent_publication_review"] == "PASS", "Publication Review gate")

    history = metadata["final_history_evidence"]
    require(history["status"] == "PASS / NO_PRIOR_PUBLIC_SUBSTANTIVE_EXACT_V3_ATTACK_LOCATED / NO_HISTORY_VETO", "history status")
    require(history["classification"] == "NO_PRIOR_PUBLIC_SUBSTANTIVE_EXACT_V3_ATTACK_LOCATED", "history classification")
    require(history["confidence"] == "MODERATE", "history confidence")
    require(history["cutoff"] == "2026-10-15", "history cutoff")
    require(history["history_supported_wording"] == HISTORY_STATEMENT, "history wording")
    related = history["related_public_work"]
    require(isinstance(related, list) and len(related) == 3, "history related-work count")
    works = "\n".join(item["work"] for item in related)
    require("2024/1137" in works and "2024/1256" in works and "2026/895" in works, "history related-work identities")
    require(all(item["exact_v3_attack"] is False for item in related), "history exact-V3 distinctions")

    history_pins = {
        "final_history_artifact_manifest_sha256": "d50ad9e9bebf5a1855c89f960592e131f19fce2b87d8bb5e4514f567d217454d",
        "final_history_canonical_handoff_sha256": "2a1cbf638453500b5749cbc040ece0d03abb453e0bb95f7ccd7f4d4f2df82faa",
        "final_history_query_ledger_sha256": "43b6eb77e399f8119fc88b162db57ff80d2d8dbf4a5ab127bfcfe4af700256c2",
        "final_history_review_handoff_sha256": "53b5c8f3ca4726764b9e0db6df5f6c458f25d988b693968044245a01bfe31d62",
        "final_history_review_inputs_sha256": "3f6cf02fc3c02a9398b60cd92ea4cbbb573bfd93d5173cc8ed0e780b45535582",
        "final_history_review_sha256": "0ce58f32c0b6ebe37bcc96a805cd6e80bb0cfbb58522d8c70942f688a05b1147",
        "final_history_sources_sha256": "f71cd94c1e1e6a9a3af690e39c63074e61aaf98aea7e1bd16705951b5c2f2f48",
        "final_history_verdict_sha256": "b28391fda40777c64919a61035a33f8135eccb60a2f635cc7e78d793e2093236",
    }
    provenance = metadata["evidence_provenance"]
    for field, expected in history_pins.items():
        require(provenance.get(field) == expected, f"history evidence pin {field}")

    publication_replay_pins = {
        "publication_package_replay_artifact_manifest_sha256": "8437db885f97a5021353cff69bef8b1cf7604ddbc200feb458196938da369837",
        "publication_package_replay_output_manifest_sha256": "b969b537a02e87439a2d07d25a44592e23fb5a187526bbcec9ff6ba8f4427fad",
        "publication_package_replay_report_sha256": "b1549fd2456b8f68d8393ddca1cf23e1ecd2cb43fc12cddb4337832796583e9a",
        "publication_package_replay_review_sha256": "ee6fefb703b8be1c50f5d2804c57f5a62bc1f7f377f1bf8ca0f7aef3769b7761",
    }
    source_candidate_pins = {
        "source_candidate_reproducer_manifest_sha256": "d5b48642fe37e2a043af4b6e9a79219452e9a73d4583c31d4c8a297579e249ac",
        "source_candidate_root_manifest_sha256": "9c8fecf3ba1ea16df8ebd60c52d117a014b0939ac1bb9c85a9fea511a25c93d5",
    }
    for field, expected in (publication_replay_pins | source_candidate_pins).items():
        require(provenance.get(field) == expected, f"publication replay provenance {field}")
    require(
        not any(field.startswith("supplemental_package_replay_") for field in provenance),
        "stale supplemental replay provenance name",
    )

    package_replay = metadata["publication_package_replay_evidence"]
    expected_package_replay = {
        "altered_signature_rejected": True,
        "changed_message_rejected": True,
        "counted_as_trial": False,
        "exact_D": True,
        "exact_G": True,
        "fresh_forgery_accepted": True,
        "fresh_unit_T_keys": 1,
        "inequalities": 22083,
        "ordinary_invalid_signatures": 1781,
        "ordinary_outputs": 40000,
        "ordinary_valid_signatures": 38219,
        "peak_rss_kib": 243116,
        "public_relation_passed": True,
        "solver_command_wall_seconds": 84.10,
        "solver_seconds": 83.31292366300477,
        "status": "PASS / PUBLIC PACKAGE FULL REPLAY",
        "trial_scope_effect": "none; supplemental release-readiness validation only",
        "workers": 1,
        "wraps": 1821,
    }
    require(package_replay == expected_package_replay, "exact publication package replay evidence")
    require("supplemental_package_replay_evidence" not in metadata, "stale replay evidence name")

    pins = {
        "affected_rows_sha256": "affected-rows.json",
        "all_rows_reference_output_sha256": "all-rows-reference-output.json",
        "attack_paper_makefile_sha256": "paper/Makefile",
        "attack_paper_sha256": "paper/attack.pdf",
        "attack_paper_source_sha256": "paper/attack.tex",
        "independent_reproducer_sha256": "reproduce-all-rows.py",
        "independent_validation_record_sha256": "reproducer/validation/independent-replay-20261015.json",
        "reference_output_sha256": "reference-output.json",
        "reproducer_sha256": "reproduce.py",
    }
    for field, relative in pins.items():
        require(valid_digest(metadata.get(field)), f"metadata digest format {field}")
        require(metadata[field] == digest(relative), f"metadata hash {field}")

    require(affected.get("eprint_id") == "2024/1234", "affected-row ePrint identifier")
    rows = affected.get("rows")
    require(isinstance(rows, list) and len(rows) == 1, "affected-row count")
    row = rows[0]
    require(row["n"] == 1024 and row["q"] == 59393 and row["tau"] == 16, "affected row")
    require(row["unit_T_condition"] is True, "unit-T condition")

    independent = metadata["independent_reproduction_evidence"]
    require(independent["constraints"] == 21982 and independent["wraps"] == 1767, "independent counts")
    require(independent["signer_outputs"] == 40000, "independent outputs")
    require(independent["ordinary_invalid_signatures"] == 1727, "independent invalid outputs")
    require(independent["solver"] == "SciPy 1.18.1 optimize.milp / HiGHS 1.12.0", "solver identity")
    require(replay["result"]["status"].startswith("PASS_"), "sealed replay status")
    require(replay["completion_profile"]["r_bytes"] == 64, "independent r profile")
    require(replay["resources"]["full_public_pipeline_wall_seconds"] == 296.09, "replay runtime")

    tex = (ROOT / "paper/attack.tex").read_text(encoding="utf-8")
    tex_words = " ".join(tex.split())
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_words = " ".join(readme.split())
    require(tex.count(DISCLOSURE) == 1, "exact Daybreak Blue sentence")
    require(tex.find(DISCLOSURE) > tex.find(r"\maketitle"), "disclosure after maketitle")
    require("OpenAI Codex generated and selected this paper's title" in tex_words, "title disclosure")
    require("deliberately chose" in tex_words and "wordplay" in tex_words, "wordplay disclosure")
    require(tex.count(r"\section*{Acknowledgements}") == 1, "Acknowledgements heading")
    require(tex.count(ACKNOWLEDGEMENT) == 1, "exact NREC acknowledgement")
    require(r"\author{Martin Feussner\\" in tex, "paper author")
    require("pdfauthor={Martin Feussner}" in tex, "PDF author")
    require("32-byte $r$" in tex and "64-byte $r$" in tex, "completion distinction")
    require("296.09" in tex and "221,272" in tex, "independent resource record")
    pending_history_marker = "[PENDING " + "FINAL HISTORY PLACEHOLDER.]"
    pending_review_marker = "[PENDING " + "PUBLICATION REVIEW PLACEHOLDER.]"
    require(pending_history_marker not in tex, "stale history placeholder")
    require(pending_review_marker not in tex, "stale Publication Review placeholder")
    require("PENDING INDEPENDENT REPRODUCTION" not in tex, "stale independent placeholder")
    require(HISTORY_STATEMENT in tex_words, "paper history statement")
    require(HISTORY_STATEMENT in readme_words, "README history statement")
    require(HISTORY_ATTRIBUTION in tex_words, "paper exact history attribution")
    require(HISTORY_ATTRIBUTION in readme_words, "README exact history attribution")
    for label, content in (("paper", tex_words), ("README", readme_words)):
        attribution_at = content.index(HISTORY_ATTRIBUTION)
        require("2024/1137" in content[max(0, attribution_at - 300):attribution_at], f"{label} adjacent 2024/1137 citation")
    require("Final history review | `PASS / NO_PRIOR_PUBLIC_SUBSTANTIVE_EXACT_V3_ATTACK_LOCATED / NO_HISTORY_VETO`" in readme, "README history gate")
    require("Publication Review | `PASS / NO VETO`" in readme, "README Publication Review gate")
    require("Publication status | `VERIFIED_ATTACK`" in readme, "README final status")
    require("(paper/attack.pdf)" in readme, "README PDF link")
    for eprint in ("2024/1137", "2024/1256", "2026/895"):
        require(eprint in tex and eprint in readme, f"history attribution {eprint}")
    for evidence_hash in publication_replay_pins.values():
        require(evidence_hash in tex and evidence_hash in readme, "supplemental replay evidence disclosure")
    for source_hash in source_candidate_pins.values():
        require(source_hash in tex and source_hash in readme, "source-candidate replay pin disclosure")
    replay_texts = (
        "38,219 passed ordinary verification and 1,781 failed it",
        "83.31292366300477 solver-wrapper seconds and 84.10 command-wall seconds",
        "These are old source-candidate pins, not hashes of this final package.",
    )
    for label, content in (("paper", tex_words), ("README", readme_words)):
        for statement in replay_texts:
            require(statement in content, f"{label} exact publication replay text")
    reproducer_readme = (ROOT / "reproducer/README.md").read_text(encoding="utf-8")
    require(reproducer_readme.rstrip().endswith(REPRODUCER_FINAL_SENTENCE), "reproducer final sentence")
    require(reproducer_readme.count(REPRODUCER_FINAL_SENTENCE) == 1, "unique reproducer final sentence")
    require("operatorname" not in readme, "forbidden Markdown macro")

    scanned = "\n".join(
        path.read_text(encoding="utf-8", errors="strict")
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.suffix in {".md", ".tex", ".py", ".sh", ".json", ".txt", ".hpp", ".cpp"}
        and path.name not in {"SHA256SUMS"}
    )
    stale_solver_label = "C" + "BC"
    stale_time_phrase = "six" + "-hour"
    stale_publication_phrases = (
        "PENDING " + "PUBLICATION REVIEW PLACEHOLDER",
        "CANDIDATE_" + "PENDING_INDEPENDENT_PUBLICATION_REVIEW",
        "PRIVATE_" + "UNCOUNTED",
        "Publication Review remains " + "pending",
        "private-" + "draft stage",
        "Private uncounted " + "draft",
        "Pending publication " + "gate",
    )
    require(
        re.search(rf"\b{stale_solver_label}\b", scanned, re.IGNORECASE) is None,
        "stale solver terminology",
    )
    require(stale_time_phrase not in scanned.lower(), "stale solver-window wording")
    for phrase in stale_publication_phrases:
        require(phrase not in scanned, f"stale publication wording: {phrase}")
    require("SciPy 1.18.1" in scanned and "HiGHS 1.12.0" in scanned, "sealed solver versions")
    require("21600" in (ROOT / "reproducer/reproduce.sh").read_text(encoding="utf-8"), "solver time limit")
    require("taskset" in (ROOT / "reproducer/reproduce.sh").read_text(encoding="utf-8"), "one-CPU affinity")

    validate_manifest(ROOT / "reproducer", allow_missing=args.allow_missing_manifest)
    validate_manifest(ROOT, allow_missing=args.allow_missing_manifest)
    print("PACKAGE VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
