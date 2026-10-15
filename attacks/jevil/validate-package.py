#!/usr/bin/env python3
"""Validate the staged Jevil publication package with the standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
TITLE = (
    "The Jevil Is in the Details: State Recovery and Fresh-Message Forgery "
    "Below Jevil's Signature Cliff"
)
DISCLOSURE = "This audit used the OpenAI model Daybreak Blue at the ultra reasoning level."
ACKNOWLEDGEMENT = (
    "The computations were performed on the Norwegian Research and Education "
    "Cloud (NREC), using resources provided by the University of Bergen and "
    "the University of Oslo."
)
PAPER_SHA256 = "c0da79bdf8b2d2c9667d6167d6ab008b8eeaf838b463a40eb64f2abe123c01c5"
SOURCE_COMMIT = "905466fbe3be99d90fd41e461e0c68271d09104b"
SOURCE_TREE = "f4a7366dac1a1f079186d87a2aca79c9918ee79e"
SOURCE_PINS_SHA256 = "bd5fc9b47d7c2a738723f5a9b18008013386eae797626711b051eb6136b86c20"
SIGN_RS_SHA256 = "34a61da541e7239402e2e49fedee76aaa50fc4c328c49cc9a307dca3bac2fb74"
VERIFY_RS_SHA256 = "d84341b99aa3b76413c20118f7fb0a78886754e1d9c7c0f952c7f930037e569b"
FULL_VALIDATION_SHA256 = "83ac7acf5f307962647e467be2171ca242344b86800c891a480c01ff061deed0"
SMOKE_VALIDATION_SHA256 = "6c01ca4cf285d34b97419140bd89d93077f475075d68eadba31d9277314f8cb4"
HISTORY_WORDING = (
    "No prior public practical signing attack against the current fourth-revision "
    "Jevil profile at n_star=1023, c=4, using at most 1,023 ordinary signing "
    "queries was located in the searches performed through 15 October 2026."
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"PACKAGE VALIDATION: FAIL: {message}")


def digest(path: str | Path) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def load_canonical_json(path: str) -> Any:
    file_path = ROOT / path
    value = json.loads(file_path.read_text(encoding="utf-8"))
    canonical = json.dumps(value, indent=2, sort_keys=True) + "\n"
    require(file_path.read_text(encoding="utf-8") == canonical, f"{path} is not canonical JSON")
    return value


def validate_reference(value: dict[str, Any], *, full: bool) -> None:
    require(isinstance(value.get("result"), str) and value["result"], "reference result")
    digests = value.get("digests")
    require(isinstance(digests, dict) and digests, "reference digests")
    require(
        all(name.endswith("_sha256") and isinstance(item, str) and len(item) == 64
            and all(character in "0123456789abcdef" for character in item)
            for name, item in digests.items()),
        "reference digest format",
    )
    if full:
        require(value["result"] == "FULL_FRESH_KEY_ATTACK_REPRODUCTION_PASS", "full reference result")
        require(value.get("full_attack_reproduced") is True, "full reproduction flag")
        require(value.get("all_rows_pass") is True, "full reference pass")
        require(value.get("attack", {}).get("signing_queries") == 650, "full query count")
        require(value.get("resources", {}).get("workers") == 1, "full worker count")
        results = value.get("results")
        require(isinstance(results, list) and len(results) == 1, "full reference result count")
        row = results[0]
        require(
            row.get("parameter_row")
            == "n_star=1023, c=4, N=131072, four degree-below-32768 rows",
            "parameter row",
        )
        require(row.get("all_expected_checks_pass") is True, "full row controls")
        require(row.get("signing_queries") == 650, "full row query count")
        require(row.get("maximum_zero_based_query_index") == 649, "full row maximum index")
        require(row.get("authenticated_openings") == 41600, "full opening count")
        require(row.get("distinct_positions", 0) >= 32768, "full interpolation threshold")
        checks = row.get("checks")
        require(isinstance(checks, dict) and len(checks) == 9, "full row check set")
        require(all(item is True for item in checks.values()), "full row checks")
    else:
        require(value["result"].startswith("STRUCTURAL_SMOKE_PASS"), "smoke result")
        require(value.get("mode") == "structural_smoke", "smoke mode")
        require(value.get("full_attack_reproduced") is False, "smoke full-attack boundary")
        require(value.get("environment", {}).get("workers") == 1, "smoke worker count")
        checks = value.get("checks")
        require(isinstance(checks, dict) and len(checks) == 2, "smoke check set")
        require(all(item is True for item in checks.values()), "smoke checks")


def validate_manifest(base: Path, *, allow_missing: bool) -> None:
    manifest = base / "SHA256SUMS"
    if allow_missing and not manifest.exists():
        return
    require(manifest.is_file() and not manifest.is_symlink(), "SHA256SUMS missing")
    seen: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        relative = relative.removeprefix("./")
        require(relative != "SHA256SUMS", "manifest hashes itself")
        require(relative not in seen, f"duplicate manifest path {relative}")
        seen.add(relative)
        require(len(expected) == 64 and all(c in "0123456789abcdef" for c in expected), "bad hash")
        path = base / relative
        require(path.is_file() and not path.is_symlink(), f"missing manifest path {relative}")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, f"hash mismatch {relative}")
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
    require(seen == actual, "manifest coverage differs from package inventory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final", action="store_true")
    parser.add_argument("--allow-missing-manifest", action="store_true")
    args = parser.parse_args()
    require(not args.allow_missing_manifest or args.final, "manifest exception requires --final")

    required = (
        "README.md", "metadata.json", "affected-rows.json", "reference-output.json",
        "all-rows-reference-output.json", "reproduce.py", "reproduce-all-rows.py",
        "validate-package.py", "Makefile", "paper/attack.tex", "paper/attack.pdf",
        "paper/Makefile", "reproducer/README.md", "reproducer/Makefile",
        "reproducer/reproduce.sh", "reproducer/NOTICE.md",
        "reproducer/LICENSE-APACHE", "reproducer/LICENSE-MIT",
        "reproducer/SHA256SUMS",
        "reproducer/SOURCE-PINS.sha256", "reproducer/rust-toolchain.toml",
        "reproducer/scripts/check-layout.py", "reproducer/scripts/check-pins.sh",
        "reproducer/scripts/report-full.py", "reproducer/scripts/validate-full.py",
        "reproducer/validation/full-replay-20261015.json",
        "reproducer/validation/structural-smoke-20261015.json",
        "reproducer/attack-source/Cargo.lock",
        "reproducer/attack-source/src/sign.rs",
        "reproducer/attack-source/src/verify.rs",
        "reproducer/clean-verifier-source/Cargo.lock",
        "reproducer/clean-verifier-source/src/sign.rs",
        "reproducer/clean-verifier-source/src/verify.rs",
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
    require(not (ROOT / "reproducer/HANDOFF.md").exists(), "staging handoff present")
    require(not (ROOT / "reproducer/integration-wrappers").exists(), "integration staging directory present")

    metadata = load_canonical_json("metadata.json")
    affected = load_canonical_json("affected-rows.json")
    quick = load_canonical_json("reference-output.json")
    full = load_canonical_json("all-rows-reference-output.json")
    validate_reference(quick, full=False)
    validate_reference(full, full=True)

    require(metadata["scheme"] == "Jevil", "scheme")
    require(metadata["attack_title"] == TITLE, "attack title")
    require(metadata["eprint_id"] == "2026/1103", "ePrint identifier")
    require(metadata["layer"] == "design", "attack layer")
    require(metadata["full_scale"] is True, "full-scale flag")
    require(metadata["signing_queries"] == 650, "published reproducer query count")
    require(metadata["workers"] == 1, "worker count")
    require(metadata["independent_reproduction"] is True, "independent reproduction")
    require(metadata["technique_originality_claimed"] is False, "technique novelty boundary")
    require(metadata["prior_public_attack_located"] is False, "exact-target history result")
    require(metadata["title_ai_generated"] is True, "AI title provenance")
    require(metadata["title_wordplay_selected_by_codex"] is True, "AI wordplay provenance")
    require(metadata["attack_paper_authors"] == ["Martin Feussner"], "paper author")
    require(metadata["attack_paper_affiliation"] == "Selmer Center, University of Bergen", "affiliation")
    require(metadata["attack_paper_contact"] == "martin.feussner@uib.no", "contact")
    require(metadata["scheme_source_commit"] == SOURCE_COMMIT, "source commit")
    require(metadata["target_pdf_sha256"] == PAPER_SHA256, "target PDF hash")
    require(metadata["final_history_evidence"]["history_supported_wording"] == HISTORY_WORDING, "history wording")
    require(len(metadata["final_history_evidence"]["mandatory_disclosures"]) == 2, "history disclosures")
    require(metadata.get("placeholder_hash_fields") is None, "placeholder hash list remains")
    for name, value in metadata.items():
        if name.endswith("_sha256"):
            require(isinstance(value, str) and len(value) == 64 and value != "0" * 64, f"bad {name}")

    pins = {
        "reproducer_sha256": "reproduce.py",
        "independent_reproducer_sha256": "reproduce-all-rows.py",
        "reference_output_sha256": "reference-output.json",
        "all_rows_reference_output_sha256": "all-rows-reference-output.json",
        "affected_rows_sha256": "affected-rows.json",
        "attack_paper_sha256": "paper/attack.pdf",
        "attack_paper_source_sha256": "paper/attack.tex",
        "attack_paper_makefile_sha256": "paper/Makefile",
    }
    for field, path in pins.items():
        require(metadata[field] == digest(path), f"metadata hash {field}")

    require(digest("reproducer/SOURCE-PINS.sha256") == SOURCE_PINS_SHA256, "source pin manifest hash")
    require(digest("reproducer/validation/full-replay-20261015.json") == FULL_VALIDATION_SHA256, "full validation hash")
    require(digest("reproducer/validation/structural-smoke-20261015.json") == SMOKE_VALIDATION_SHA256, "smoke validation hash")
    for source_tree in ("attack-source", "clean-verifier-source"):
        require(digest(f"reproducer/{source_tree}/src/sign.rs") == SIGN_RS_SHA256, f"{source_tree} sign.rs")
        require(digest(f"reproducer/{source_tree}/src/verify.rs") == VERIFY_RS_SHA256, f"{source_tree} verify.rs")

    replay = metadata.get("publication_package_replay_evidence")
    require(isinstance(replay, dict), "package replay evidence")
    require(replay.get("status") == "CRYPTOGRAPHIC_PIPELINE_PASS_WITH_POST_RUN_CLEANUP_FIX", "package replay status")
    require(replay.get("ordinary_queries") == 650, "package replay queries")
    require(replay.get("maximum_zero_based_query_index") == 649, "package replay index")
    require(replay.get("advertised_1024th_signature_unused") is True, "package replay cliff exclusion")
    require(replay.get("authenticated_openings") == 41600, "package replay openings")
    require(replay.get("distinct_positions", 0) >= 32768, "package replay interpolation threshold")
    require(replay.get("rows_recovered") == 4, "package replay rows")
    for check in (
        "root_reconstructed", "public_evaluation_reconstructed",
        "fresh_message_unqueried", "untouched_source_verifier_accepted",
        "changed_message_rejected", "changed_root_rejected",
        "altered_signature_rejected", "corrupted_row_rejected", "public_inputs_only",
    ):
        require(replay.get(check) is True, f"package replay check {check}")
    require(replay.get("workers") == 1, "package replay workers")
    require(replay.get("validation_record_sha256") == FULL_VALIDATION_SHA256, "package replay validation pin")
    require(replay.get("structural_smoke_validation_sha256") == SMOKE_VALIDATION_SHA256, "package smoke validation pin")
    require(replay.get("source_pins_sha256") == SOURCE_PINS_SHA256, "package source pin")

    require(affected.get("eprint_id") == "2026/1103", "affected-row ePrint identifier")
    rows = affected.get("rows")
    require(isinstance(rows, list) and len(rows) == 1, "affected row count")
    row = rows[0]
    require(row["n_star"] == 1023 and row["capacity"] == 4, "affected row profile")
    require(row["maximum_ordinary_signing_queries"] == 1023, "query ceiling")
    require(row["advertised_cliff_signature_number"] == 1024, "advertised cliff")
    require("do not use the advertised 1,024th signature" in affected["scope"], "cliff exclusion")

    tex = (ROOT / "paper/attack.tex").read_text(encoding="utf-8")
    tex_words = " ".join(tex.split())
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require(tex.count(DISCLOSURE) == 1, "exact Daybreak Blue sentence")
    require("OpenAI Codex generated and selected the title" in tex_words, "title generation disclosure")
    require("intentionally chose" in tex_words and "wordplay" in tex_words, "wordplay choice disclosure")
    require(tex.count(r"\section*{Acknowledgements}") == 1, "Acknowledgements heading")
    require(tex.count(ACKNOWLEDGEMENT) == 1, "exact NREC acknowledgement")
    require("3c7968ddacf4bddcbd178b3e7a61625148dabf9c" in tex, "root-binding disclosure")
    require("non-power-of-two Merkle-helper" in tex, "Merkle-helper disclosure")
    require("641" in readme and "650" in readme, "both demonstrated query counts")
    require("No prior public practical signing attack" in readme, "README history wording")
    require("operatorname" not in readme, "forbidden Markdown macro")

    if args.final:
        require(metadata["verified_attack"] is True, "final verified flag")
        require(metadata["publication_status"] == "VERIFIED_ATTACK", "final publication status")
        require(metadata["publication_gates"]["independent_publication_review"] == "PASS", "review gate")
        require("PUBLICATION CANDIDATE" not in readme, "candidate banner remains")
        require("Publication Review passed" in readme, "final README review statement")
    else:
        require(metadata["verified_attack"] is False, "draft verified flag")
        require(
            metadata["publication_status"]
            == "CANDIDATE_PENDING_INDEPENDENT_PUBLICATION_REVIEW",
            "draft publication status",
        )
        require(
            metadata["publication_gates"]["independent_publication_review"] == "PENDING",
            "draft review gate",
        )
        require("PUBLICATION CANDIDATE" in readme, "draft candidate banner")
        require("Candidate pending independent Publication Review" in readme, "draft README review statement")

    validate_manifest(ROOT / "reproducer", allow_missing=False)
    validate_manifest(ROOT, allow_missing=args.allow_missing_manifest)
    print("PACKAGE VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
