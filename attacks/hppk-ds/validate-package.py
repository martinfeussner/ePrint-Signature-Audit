#!/usr/bin/env python3
"""Validate the HPPK DS publication package using the standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DISCLOSURE = "This audit used the OpenAI model Daybreak Blue at the ultra reasoning level."
ACKNOWLEDGEMENT = (
    "The computations were performed on the Norwegian Research and Education "
    "Cloud (NREC), using resources provided by the University of Bergen and "
    "the University of Oslo."
)
OFFICIAL_TITLE = (
    "Homomorphic Polynomial Public Key Cryptography for Quantum-secure "
    "Digital Signature"
)
PAPER_TITLE = "HPPK with Nothing: A Universal All-Zero Forgery against HPPK DS"


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


def placeholders(value: Any, prefix: str = "") -> dict[str, str]:
    found: dict[str, str] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            label = f"{prefix}.{key}" if prefix else key
            found.update(placeholders(child, label))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.update(placeholders(child, f"{prefix}[{index}]"))
    elif isinstance(value, str) and value.startswith("__PENDING_"):
        found[prefix] = value
    return found


def validate_reference(report: dict[str, Any], *, expected_messages: int) -> None:
    require(report["status"] == "PASS", "reference status")
    require(report["banner"] == "ATTACK REPRODUCTION: PASS", "reference banner")
    require(report["all_rows_pass"] is True, "all_rows_pass")
    require(report["affected_rows_tested"] == 18, "reference row count")
    require(report["workers"] == 1, "reference worker count")
    require(report["environment"]["workers"] == 1, "reference environment workers")
    require(report["attack"]["signing_queries"] == 0, "reference signing queries")
    require(report["attack"]["fresh_message_trials"] == expected_messages, "message count")
    require(
        report["attack"]["accepted_fresh_messages"] == expected_messages,
        "accepted-message count",
    )
    require(report["checks"] and all(report["checks"].values()), "reference checks")
    require(
        set(report["digests"])
        == {"benchmark_pdf_sha256", "target_pdf_sha256"},
        "reference digest set",
    )
    results = report["results"]
    require(len(results) == 18, "reference results length")
    labels = [row["parameter_row"] for row in results]
    require(len(set(labels)) == 18, "duplicate parameter row")
    require(sum(label.startswith("target-v2-") for label in labels) == 3, "target rows")
    require(sum(label.startswith("bench-") for label in labels) == 15, "benchmark rows")
    for row in results:
        require(row["complete_hash_segments"] == 4, "segment count")
        require(row["forged_signature_pairs"] == [[0, 0]] * 4, "zero-pair object")
        require(row["attack_signing_queries"] == 0, "row signing query")
        require(row["row_exact_implementation_claimed"] is False, "row-exact overclaim")
        require(row["all_expected_checks_pass"] is True, "row controls")
        require(all(row["controls"].values()), "control failure")


def validate_manifest() -> None:
    manifest = ROOT / "SHA256SUMS"
    require(manifest.is_file() and not manifest.is_symlink(), "SHA256SUMS missing")
    seen: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        relative = relative.removeprefix("./")
        require(relative != "SHA256SUMS", "manifest must not hash itself")
        require(relative not in seen, "duplicate manifest path")
        seen.add(relative)
        require(len(expected) == 64 and all(c in "0123456789abcdef" for c in expected), "bad hash")
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"missing manifest path {relative}")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, f"hash mismatch {relative}")
    actual = {
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS"
    }
    require(seen == actual, "manifest coverage differs from regular-file inventory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final", action="store_true", help="enforce all publication gates")
    parser.add_argument(
        "--allow-missing-manifest",
        action="store_true",
        help="final preflight used immediately before generating SHA256SUMS",
    )
    args = parser.parse_args()
    require(not args.allow_missing_manifest or args.final, "manifest exception requires --final")

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
        "paper/Makefile",
        "reproducer/__init__.py",
        "reproducer/hppk_reference.py",
        "reproducer/report.py",
        "reproducer/reproduce.sh",
        "reproducer/README.md",
        "reproducer/Makefile",
        "reproducer/requirements.txt",
    )
    for relative in required:
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"missing regular file {relative}")
    require(not (ROOT / "PLACEHOLDERS.md").exists(), "staging-only PLACEHOLDERS.md present")
    require(not any(path.is_symlink() for path in ROOT.rglob("*")), "symlink present")
    require(not any(path.name == "__pycache__" for path in ROOT.rglob("*")), "Python cache present")
    require(
        not any(path.suffix in {".aux", ".log", ".out", ".toc"} for path in ROOT.rglob("*")),
        "LaTeX build debris present",
    )

    metadata = load_canonical_json("metadata.json")
    affected = load_canonical_json("affected-rows.json")
    quick = load_canonical_json("reference-output.json")
    full = load_canonical_json("all-rows-reference-output.json")
    validate_reference(quick, expected_messages=18)
    validate_reference(full, expected_messages=72)

    require(metadata["scheme"] == f"{OFFICIAL_TITLE} (HPPK DS)", "official target title")
    require(metadata["attack_title"] == PAPER_TITLE, "paper title")
    require(metadata["eprint_id"] == "2023/1768", "target identifier")
    require(metadata["benchmark_eprint_id"] == "2024/019", "benchmark identifier")
    require(metadata["layer"] == "design", "attack layer")
    require(metadata["full_scale"] is True, "full-scale flag")
    require(metadata["signing_queries"] == 0, "metadata signing queries")
    require(metadata["workers"] == 1, "metadata workers")
    require(metadata["technique_originality_claimed"] is False, "novelty claim")
    require(metadata["title_ai_generated"] is True, "title AI provenance")
    require(metadata["title_wordplay_selected_by_codex"] is True, "wordplay provenance")
    require(
        metadata["ai_provenance"]["final_history_review"]
        == "separately tasked AI final history reviewer plus independent public-history cross-checker; PASS",
        "final history AI provenance",
    )
    require(metadata["attack_paper_authors"] == ["Martin Feussner"], "byline")
    require(
        metadata["attack_paper_affiliation"] == "Selmer Center, University of Bergen",
        "affiliation",
    )
    require(metadata["attack_paper_contact"] == "martin.feussner@uib.no", "contact")
    claimed = metadata["claimed_security"]
    require(
        claimed["target_signature_entropy_bits_by_level"]
        == {"I": 192, "III": 288, "V": 384},
        "target claimed entropy",
    )
    require(
        claimed["benchmark_signature_entropy_bits_by_level"]
        == {"I": 144, "III": 208, "V": 272},
        "benchmark claimed entropy",
    )
    require("O(S1*S2/p)=O(p^3)" in claimed["target_key_recovery_claim"], "target key-recovery claim")
    require("O(S1*S2)" in claimed["target_forgery_claim"], "target forgery claim")
    require("O(2^L)" in claimed["benchmark_modulus_recovery_claim"], "benchmark work claim")
    require("L=2*|p|_2+16" in claimed["benchmark_modulus_recovery_claim"], "benchmark L relation")

    independent = metadata["independent_reproduction_evidence"]
    independent_expected = {
        "attack_signing_queries": 0,
        "attacker_checks": 192,
        "attacker_secret_reads": 0,
        "attacker_successes": 192,
        "attempt_1_addendum_sha256": "25e04eaa40cd786fe9b8a1800029a3cee956169d8288eedb6c591b1068d3f963",
        "attempt_2_preexecution_seal_sha256": "e1beb99963ba238dd8312066f05f642aeb1bf62441105039451af6bd09de639b",
        "corrected_harness_sha256": "aab3ddcac2558fd615fa62a79bf75b038d0afd17f1c5c0065e72f0bb4132bcd9",
        "executed_binary_sha256": "973a97914356fc4173b62d64bdc8b7ccface75ff7e24281ebb33cfbaf8a6c57d",
        "experiment": "experiments/hppk-ds-independent-reproduction-20261014T141324Z",
        "final_result_sha256": "029540674d54394614b473814cdf4661609219fe197680b359915fa30917fe81",
        "fresh_keys": 12,
        "fresh_messages": 48,
        "handoff_sha256": "b541f891c214fb633614e50211252cd4db2268ba0ca346b0bceacf5c3e20a18d",
        "honest_checks": 96,
        "honest_successes": 96,
        "manifest_sha256": "7e46c648643754e2de850e8854d50409275afba856519067a85a5e5a1f70b08f",
        "negative_control_rejections": 288,
        "negative_controls": 288,
        "paper_coefficient_pairs_checked": 1440,
        "paper_full_signature_successes": 72,
        "paper_full_signature_trials": 72,
        "paper_result_sha256": "fca4d1246dcc3f671022b5dd4e9ac471b29268f07e2529636889e244c9327dbe",
        "paper_rows": 18,
        "paper_segment_successes": 288,
        "paper_segment_trials": 288,
        "peak_rss_kib": 7680,
        "source_integrity": "PASS_PRE_AND_POST",
        "source_pre_post_manifest_sha256": "a0169dd8e2943e099c55c2795b188554d4ef1010160a33fd0553227f3efdb409",
        "source_profiles": 6,
        "source_result_sha256": "1af9a9ec0b3bf46f6faa9c03683547240cc595b9cef17e86e39755fc5e745c9c",
        "status": "PASS_18_ROWS_12_KEYS_48_MESSAGES",
        "wall_seconds": 0.34,
        "workers": 1,
    }
    for field, expected in independent_expected.items():
        require(independent.get(field) == expected, f"independent evidence {field}")
    require("sole source run" in independent["attempt_history"], "independent attempt history")
    require(metadata["independent_reproduction"] is True, "independent reproduction gate")
    require(
        metadata["independent_reproduction_status"] == "PASS_18_ROWS_12_KEYS_48_MESSAGES",
        "independent reproduction status",
    )
    require(metadata["runtime_seconds"] == 0.34, "independent source runtime")
    require(metadata["peak_ram_mb"] == 7.5, "independent source peak RAM")
    require(metadata["workers"] == 1, "independent source workers")

    history = metadata["final_history_evidence"]
    history_expected = {
        "completed_at": "2026-10-14T14:47:51Z",
        "confidence": "MODERATE_HIGH",
        "cutoff": "2026-10-14T14:47:51Z",
        "crosscheck_handoff_sha256": "95d17ab9e2876c8eef9ff85af49ca5973a94fefe0b4aba49118ad5cd1a99c70b",
        "crosscheck_status": "PASS",
        "decision_json_sha256": "1a34297acab9de8f35f513289cad7b5c8f54d3298ede2e7fd87e14cd7d109a95",
        "delta_query_ledger_sha256": "3585c4b4d3f33f40e891343d811fee373194e1bb705a27f48af1af9a81f18c71",
        "exact_target_other_practical_signing_compromise_located": False,
        "exact_target_previous_all_zero_report_located": False,
        "handoff_sha256": "bdc31cffbdb6e2e03df28e50c69f59df094ec1899b47ae31a1aeac5c94ad98e5",
        "manifest_entries": 15,
        "manifest_sha256": "b4ff7eaf0f4f7e4386665e4b223aea0049b36b72850e19ff5fb469c4cefcc4b2",
        "manifest_sidecar_sha256": "3c166281842435c055b2d651c95d0eed4fec0df3b7076919b68e07a95c28e47d",
        "narrative_sha256": "2527e95fdfd8b7fd4fd699cd3525699f23bef8566ddbd69ec85402e6f2a189a3",
        "primary_recheck_completed_at": "2026-10-14T14:43:18Z",
        "primary_recheck_cutoff": "2026-10-14T14:37:39Z",
        "status": "FINAL_HISTORY_PASS",
    }
    for field, expected in history_expected.items():
        require(history.get(field) == expected, f"final history evidence {field}")
    related = metadata["history_evidence"]["related_divergent_implementation_attack"]
    require(related["classification"] == "RELATED_DIVERGENT_IMPLEMENTATION_ATTACK", "related attack class")
    require(related["url"] == "https://github.com/sergelen02/HPPK_2/pull/1", "related attack URL")
    require(
        related["public_forgery_commit"] == "782f51815b011dbd16ac4dd5de48757e0fb69bf4",
        "related attack commit",
    )
    require(related["repository_owner_target_association_located"] is False, "related attack association")
    require(metadata["attack_history_status"] == "FINAL_HISTORY_PASS", "attack history status")
    require(metadata["attack_history_checked_at"] == "2026-10-14", "public history date")
    require(metadata["publication_gates"]["exact_target_history"] == "PASS", "final history gate")
    require(metadata["related_public_attack_located"] is True, "related public attack flag")
    require(
        set(metadata["evidence_provenance"])
        == {
            "adversarial_review_handoff_sha256",
            "algebra_domain_review_handoff_sha256",
            "final_history_handoff_sha256",
            "final_history_independent_crosscheck_sha256",
            "history_scope_handoff_sha256",
            "independent_reproduction_handoff_sha256",
            "primary_reproduction_handoff_sha256",
            "primary_title_correction_sha256",
            "reconstruction_handoff_sha256",
        },
        "unexpected evidence-provenance field",
    )

    pins = {
        "reproducer_sha256": "reproduce.py",
        "independent_reproducer_sha256": "reproduce-all-rows.py",
        "public_reproducer_core_sha256": "reproducer/hppk_reference.py",
        "public_report_core_sha256": "reproducer/report.py",
        "reference_output_sha256": "reference-output.json",
        "all_rows_reference_output_sha256": "all-rows-reference-output.json",
        "affected_rows_sha256": "affected-rows.json",
    }
    for field, relative in pins.items():
        require(field in metadata, f"metadata missing {field}")
        require(metadata[field] == digest(relative), f"metadata hash mismatch for {relative}")

    require(affected["counts"] == {"benchmark_table_2": 15, "target_table_1": 3, "total": 18}, "affected counts")
    require(len(affected["rows"]) == 18, "affected row inventory")
    for row in affected["rows"]:
        require(row["complete_hash_segments"] == 4, "affected segment count")
        require(row["forged_pairs"] == [[0, 0]] * 4, "affected zero pairs")
        require(row["row_exact_executable_available"] is False, "affected row-exact claim")

    tex = (ROOT / "paper/attack.tex").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    tex_flat = " ".join(tex.split())
    readme_flat = " ".join(readme.split())
    require(tex.count(DISCLOSURE) == 1, "exact opening disclosure count")
    require(tex.index("\\maketitle") < tex.index(DISCLOSURE) < tex.index("\\begin{abstract}"), "opening disclosure placement")
    require("OpenAI Codex generated and selected this paper's title" in tex, "title generation disclosure")
    require("HPPK visually echoes ``happy,''" in tex, "title wordplay disclosure")
    require("pdfauthor={Martin Feussner}" in tex, "PDF author metadata")
    author = (
        "\\author{Martin Feussner\\\\\n"
        "\\small Selmer Center, University of Bergen\\\\\n"
        "\\small \\texttt{martin.feussner@uib.no}}"
    )
    require(tex.count(author) == 1, "exact paper byline")
    require(OFFICIAL_TITLE in tex.replace("\n", " "), "official title absent from paper")
    require(OFFICIAL_TITLE in readme, "official title absent from README")
    abstract = tex.split("\\begin{abstract}", 1)[1].split("\\end{abstract}", 1)[0]
    require(OFFICIAL_TITLE in " ".join(abstract.split()), "official title absent from abstract")
    marker = "\\section*{Acknowledgements}"
    require(tex.count(marker) == 1, "Acknowledgements heading")
    acknowledgement_body = tex.split(marker, 1)[1].split("\\begin{thebibliography}", 1)[0].strip()
    require(acknowledgement_body == ACKNOWLEDGEMENT, "exact NREC acknowledgement body")
    located_boundary = (
        "No public or reviewed row-exact implementation or archived vector was located"
    )
    require(located_boundary in readme_flat, "README located paper/source boundary")
    require(located_boundary in tex_flat, "paper located paper/source boundary")
    require("not a row-exact implementation" in tex, "paper source boundary")
    require("\\label{eq:u-coefficient}" in tex, "U coefficient equation label")
    require("\\label{eq:v-coefficient}" in tex, "V coefficient equation label")
    require("eq:coefficients" not in tex, "ambiguous joint coefficient equation label")
    require("outer product" in abstract and "floor arguments" in abstract, "abstract zero mechanism")
    require("expression linear in" not in abstract, "abstract incorrectly calls floor expression linear")
    require("sum of terms multiplied by" not in tex, "paper incorrectly describes every term as multiplied")
    require("192, 288, and 384" in tex_flat and "144, 208, and 272" in tex_flat, "paper security claims")
    require("192, 288, and 384" in readme_flat and "144, 208, and 272" in readme_flat, "README security claims")
    require("`O(2^L)`" in readme and "$O(2^L)$" in tex, "benchmark work claim")
    require("`O(S1*S2/p)=O(p^3)`" in readme, "README target key-recovery claim")
    require("$O(S_1S_2/p)=O(p^3)$" in tex, "paper target key-recovery claim")
    require("| Conditions |" in readme, "README conditions row")
    require("| CPU model | AMD EPYC Processor |" in readme, "README CPU row")
    require("| AI provenance |" in readme and DISCLOSURE in readme, "README AI row")
    require("[`paper/attack.pdf`](paper/attack.pdf)" in readme, "README paper link")
    require("every message, public key" not in readme, "README unqualified every-public-key claim")
    require("every message,\npublic key" not in tex, "paper unqualified every-public-key claim")
    require(
        "OpenAI Codex independently reconstructed, derived, and verified the attack" in readme,
        "README AI derivation provenance",
    )
    require(
        "OpenAI Codex independently reconstructed,\nderived, and verified the attack" in tex,
        "paper AI derivation provenance",
    )
    require("72/72 complete" in readme and "192/192" in readme, "README independent counts")
    require("72/72 complete" in tex and "192/192" in tex, "paper independent counts")
    require("https://github.com/sergelen02/HPPK_2/pull/1" in readme, "README divergent attack link")
    require("sergelen02/HPPK_2/pull/1" in tex, "paper divergent attack link")
    require("782f51815b011dbd16ac4dd5de48757e0fb69bf4" in readme, "README public forgery commit")
    require("782f51815b011dbd16ac4dd5de48757e0fb69bf4" in tex, "paper public forgery commit")
    require("{F,H,U,V}" in readme and "{F,H}" in readme, "README signature-grammar distinction")
    require("$(F,H,U,V)$" in tex and "only $(F,H)$" in tex, "paper signature-grammar distinction")
    require("Propositions 3--5" in readme and "D-HPPK KEM" in readme, "README related-work scope")
    require("Propositions~3--5" in tex and "D-HPPK KEM" in tex, "paper related-work scope")
    require("bounded" in readme.lower() and "absolute" in readme.lower(), "README bounded history wording")
    require("bounded" in tex.lower() and "absolute" in tex.lower(), "paper bounded history wording")

    for markdown in ROOT.rglob("*.md"):
        require("\\operatorname" not in markdown.read_text(encoding="utf-8"), f"operatorname in {markdown.name}")

    pending = placeholders(metadata)
    if args.final:
        require(not pending, f"unresolved metadata placeholders: {sorted(pending)}")
        require(metadata["independent_reproduction"] is True, "independent reproduction gate")
        require(metadata["verified_attack"] is True, "verified-attack flag")
        require(metadata["publication_status"] == "VERIFIED_ATTACK", "publication status")
        require(metadata["publication_gates"]["independent_reproduction"].startswith("PASS"), "independent gate")
        require(metadata["publication_gates"]["exact_target_history"] == "PASS", "final history gate")
        require(metadata["publication_gates"]["independent_publication_review"] == "PASS", "publication review gate")
        final_text = "\n".join((readme, tex, json.dumps(metadata, sort_keys=True))).lower()
        for stale in (
            "staging",
            "publication review remains pending",
            "publication blocker",
            "not approved for publication",
            "not classified as a verified public attack",
            "machine-readable placeholders",
        ):
            require(stale not in final_text, f"stale final-publication prose: {stale}")
        require(not (ROOT / "PLACEHOLDERS.md").exists(), "PLACEHOLDERS.md present in final package")
        for field, relative in {
            "attack_paper_sha256": "paper/attack.pdf",
            "attack_paper_source_sha256": "paper/attack.tex",
            "attack_paper_makefile_sha256": "paper/Makefile",
        }.items():
            require(metadata[field] == digest(relative), f"final paper hash mismatch for {relative}")
        if not args.allow_missing_manifest:
            validate_manifest()
    else:
        require(pending, "draft unexpectedly has no explicit placeholders")
        require(metadata["independent_reproduction"] is True, "draft independent gate must be passed")
        require(metadata["verified_attack"] is False, "draft verified flag must remain false")
        require(
            metadata["publication_status"] == "STAGING_DRAFT_PENDING_PUBLICATION_REVIEW",
            "draft status",
        )
        require(metadata["publication_gates"]["adversarial_review"] == "PASS", "adversarial gate")
        require(
            metadata["publication_gates"]["independent_reproduction"]
            == "PASS_18_ROWS_12_KEYS_48_MESSAGES",
            "draft independent gate",
        )
        require(
            not any(path.startswith("independent_reproduction") for path in pending),
            "independent-reproduction placeholder remains",
        )
        require(
            not any("history" in path for path in pending),
            "history placeholder remains after final-history PASS",
        )
        require(not (ROOT / "SHA256SUMS").exists(), "draft must not contain final SHA256SUMS")
        require("Publication Review remains pending" in tex, "paper must disclose pending gate")
        require("Publication Review remains pending" in readme, "README must disclose pending gate")

    pdf = ROOT / "paper/attack.pdf"
    if pdf.is_file():
        require(pdf.stat().st_size > 0, "empty PDF")
        pdf_bytes = pdf.read_bytes()
        encoded_author = ("\ufeffMartin Feussner").encode("utf-16-be")
        hex_marker = b"/Author<" + encoded_author.hex().upper().encode("ascii") + b">"
        literal_marker = b"/Author(" + b"".join(
            bytes([value])
            if 33 <= value <= 126 and value not in b"()\\"
            else f"\\{value:03o}".encode("ascii")
            for value in encoded_author
        ) + b")"
        require(pdf_bytes.count(b"/Author") == 1, "PDF must contain one Author field")
        require(
            pdf_bytes.count(hex_marker) + pdf_bytes.count(literal_marker) == 1,
            "PDF Author metadata is not Martin Feussner",
        )

    print(
        "PACKAGE VALIDATION: PASS "
        + ("(final)" if args.final else f"(staging draft; {len(pending)} placeholders retained)")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
