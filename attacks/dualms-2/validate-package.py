#!/usr/bin/env python3
"""Validate the published DualMS 2.0 attack package."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
TITLE = "DualMS 2.0 Takes the Hint: Zero-Signing-Query Forgeries from Hint Slack"
DISCLOSURE = "This audit used the OpenAI model Daybreak Blue at the ultra reasoning level."
ACKNOWLEDGEMENT = (
    "The computations were performed on the Norwegian Research and Education "
    "Cloud (NREC), using resources provided by the University of Bergen and "
    "the University of Oslo."
)
HISTORY_WORDING = (
    "We located no previous public attack against DualMS 2.0, including either "
    "advertised rounded Table-6 profile (n=32 and n=1024), in searches completed "
    "on 16 October 2026. The closest earlier public analogue we located is NGCC "
    "CS finding sign-07-2, where a differently structured verifier permits a hint "
    "to absorb reconstruction terms; our result targets DualMS 2.0's printed "
    "verifier and parameter bounds and does not rely on CS's challenge-sign "
    "blindness or support grind. We make no claim that the general hint-absorption "
    "technique is novel."
)
PUBLICATION_REVIEW_SENTENCE = (
    "Independent Publication Review returned PASS / NO VETO for the sealed "
    "pre-integration candidate (manifest SHA-256 "
    "cd8a152ee60fef056df0c6c08f4f612848ee2007998259149037b698315899a0). "
    "Independent human verification was not performed and is not required."
)
PUBLIC_BANNER = "DUALMS 2.0 ATTACK REPRODUCTION: PASS"
PUBLICATION_STATUS = "VERIFIED_ATTACK"
VERIFICATION_BASIS = (
    "Paper/source/profile review, sealed primary experiment, hostile adversarial "
    "review, prospectively sealed fresh-context independent reproduction, final "
    "exact-target history recheck, and independent Publication Review passed."
)
PUBLICATION_REVIEW = {
    "approved_candidate_manifest_detached_record_sha256":
        "fff95ff619b929ed6d87a13ce4a4b72b43942bfd7a3a03ce2e57a573baceb551",
    "approved_candidate_manifest_sha256":
        "cd8a152ee60fef056df0c6c08f4f612848ee2007998259149037b698315899a0",
    "report_sha256":
        "0f4578e8d217c42377be4cac03cf47d97973cceb0fec1b75200e539351821c4f",
    "review_id": "dualms-2-2026-1941-publication-review-v2-20261016T201049Z",
    "review_manifest_detached_record_sha256":
        "89af8264bf101cafbfccd2ca40c724763b460a479663b2ea5da3b9eb5bebe555",
    "review_manifest_sha256":
        "32a004c460004747f28741ac41ada783e334046a44a0e085ae47c91792286fcb",
    "status": "PASS / NO VETO",
    "verdict_sha256":
        "c8211b6b7b472c5b3bdf537c6552645a16b2235c3bfde57237be777a0c7ca44c",
}
TEX_BYLINE = (
    r"\author{Martin Feussner\\" "\n"
    r"\small Selmer Center, University of Bergen\\" "\n"
    r"\small \texttt{martin.feussner@uib.no}}"
)
ORIGINAL_HOSTILE_MANIFEST_SHA256 = (
    "599892b8dd02d0baf728061b7751ec9985000070b63f169d66b4f9ed551a5376"
)
ORIGINAL_HOSTILE_VERDICT_SHA256 = (
    "10ddc4dd19e570671ee5d614df0cc9e58b9e86b0e2175ab38e46f853ee01498a"
)
RESTORED_HOSTILE_CHECK_RESULTS_SHA256 = (
    "2d3ecde1f0ca8ea7c88697e04268a5c5c07bfc683aad94c41f9842299e136e60"
)
CORRECTION_BUNDLE_PATH = (
    "state/reviews/dualms-2-2026-1941-primary-hostile-review-"
    "integrity-correction-20261016T194642Z/"
)
CORRECTION_MANIFEST_SHA256 = (
    "544415c48e44666023818ea13b6916e8d2b3791c8f97e1c11b88e8bfb0197234"
)
CORRECTION_DETACHED_RECORD_SHA256 = (
    "2cb5bf42c3856d47dfe854d17ec160836b39063f89a5e75085cf8d4f3279eeda"
)
ORIGINAL_HOSTILE_MANIFEST_ENTRIES = {
    "./CHECK_RESULTS.json": RESTORED_HOSTILE_CHECK_RESULTS_SHA256,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"PACKAGE VALIDATION: FAIL: {message}")


def digest(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def canonical_json(relative: str) -> Any:
    path = ROOT / relative
    value = json.loads(path.read_text(encoding="utf-8"))
    require(
        path.read_text(encoding="utf-8")
        == json.dumps(value, indent=2, sort_keys=True) + "\n",
        f"{relative} is not canonical JSON",
    )
    return value


def validate_root_wrapper() -> None:
    """Check fresh no-argument execution and byte-exact fixture emission."""
    relative = "reproduce.py"
    source = (ROOT / relative).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative)
    run_all_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_all"
    ]
    require(len(run_all_calls) == 1, "root wrapper must call run_all exactly once")
    call = run_all_calls[0]
    require(not call.args and not call.keywords, "root wrapper no-arg branch must call run_all()")
    require("REFERENCE_SEED" not in source, "root wrapper retains fixed-seed state")
    require(
        'sys.argv[1:] == ["--reference"]' in source
        and '"reference-output.json"' in source,
        "root wrapper reference-fixture branch",
    )
    replay = subprocess.run(
        [sys.executable, "-B", str(ROOT / relative), "--reference"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(replay.returncode == 0, "root wrapper --reference exit status")
    require(not replay.stderr, "root wrapper --reference wrote stderr")
    require(
        replay.stdout == (ROOT / "reference-output.json").read_bytes(),
        "root wrapper --reference differs from canonical fixture",
    )

    stable_relative = "reproduce-all-rows.py"
    stable_source = (ROOT / stable_relative).read_text(encoding="utf-8")
    stable_tree = ast.parse(stable_source, filename=stable_relative)
    stable_calls = [
        node
        for node in ast.walk(stable_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_all"
    ]
    require(len(stable_calls) == 1, "stable all-row helper run_all call count")
    stable_call = stable_calls[0]
    require(not stable_call.args, "stable all-row helper positional run_all arguments")
    require(
        len(stable_call.keywords) == 1
        and stable_call.keywords[0].arg == "seed"
        and isinstance(stable_call.keywords[0].value, ast.Name)
        and stable_call.keywords[0].value.id == "REFERENCE_SEED",
        "stable all-row helper must pass REFERENCE_SEED",
    )
    stable_replay = subprocess.run(
        [sys.executable, "-B", str(ROOT / stable_relative), "--reference"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(stable_replay.returncode == 0, "stable all-row --reference exit status")
    require(not stable_replay.stderr, "stable all-row --reference wrote stderr")
    require(
        stable_replay.stdout == (ROOT / "all-rows-reference-output.json").read_bytes(),
        "stable all-row --reference differs from canonical fixture",
    )


def validate_manifest() -> None:
    manifest = ROOT / "SHA256SUMS"
    require(manifest.is_file() and not manifest.is_symlink(), "SHA256SUMS missing")
    seen: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        relative = relative.removeprefix("./")
        require(relative != "SHA256SUMS", "manifest hashes itself")
        require(relative not in seen, f"duplicate manifest path {relative}")
        seen.add(relative)
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"missing manifest path {relative}")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, f"hash mismatch {relative}")
    actual = {
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path != manifest
        and path.suffix not in {".aux", ".log", ".out", ".toc", ".pyc"}
        and "__pycache__" not in path.parts
    }
    require(seen == actual, "manifest coverage differs from package inventory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-missing-manifest", action="store_true")
    args = parser.parse_args()

    required = (
        "README.md", "metadata.json", "affected-rows.json",
        "reference-output.json", "all-rows-reference-output.json",
        "reproduce.py", "reproduce-all-rows.py", "validate-package.py",
        "Makefile", "paper/attack.tex", "paper/attack.pdf", "paper/Makefile",
        "reproducer/README.md", "reproducer/Makefile",
        "reproducer/dualms2_reference.py", "reproducer/runner.py",
        "reproducer/reproduce.sh", "reproducer/reference-run-output.json",
    )
    for relative in required:
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"missing regular file {relative}")
    require(not any(path.is_symlink() for path in ROOT.rglob("*")), "symlink present")
    require(not any(path.name == "__pycache__" for path in ROOT.rglob("*")), "Python cache present")
    require(not any(path.suffix == ".pyc" for path in ROOT.rglob("*")), "Python bytecode present")
    require(
        not any(path.suffix in {".aux", ".log", ".out", ".toc"} for path in ROOT.rglob("*")),
        "LaTeX build debris present",
    )

    metadata = canonical_json("metadata.json")
    quick = canonical_json("reference-output.json")
    full = canonical_json("all-rows-reference-output.json")
    affected = canonical_json("affected-rows.json")
    raw = canonical_json("reproducer/reference-run-output.json")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    tex = (ROOT / "paper/attack.tex").read_text(encoding="utf-8")
    flat_tex = " ".join(tex.split())
    flat_tex_plain = flat_tex.replace(
        r"\hash{cd8a152ee60fef056df0c6c08f4f612848ee2007998259149037b698315899a0}",
        "cd8a152ee60fef056df0c6c08f4f612848ee2007998259149037b698315899a0",
    )

    require(metadata["scheme"] == "DualMS 2.0", "scheme")
    require(metadata["attack_title"] == TITLE, "title")
    require(metadata["eprint_id"] == "2026/1941", "ePrint identifier")
    require(
        metadata["target_pdf_sha256"]
        == "fdbf743b5108e66efefa686aac92e73f995a2e3e4b94ac27c38c89ead5a26691",
        "target PDF pin",
    )
    require(
        metadata["author_source"] == {
            "archive_sha256": "8719715c274b948b20d7c6d57e6dc593e6e2b0fbf8a4ac5aa1a662bec8510074",
            "commit": "227edcd891b93cb9c1d6b42bfc82c4e0b29d18f1",
            "repository": "https://github.com/barlogs/DualMS2.0-CCS-sub",
            "source_native_acceptance_claimed": False,
            "source_native_control": (
                "Environmental launch failure before compilation or target "
                "execution because the Go module cache path was unwritable."
            ),
            "tree": "87febdc8ac7bd4305ac82de8cae02ffd3435585e",
        },
        "author-source pins",
    )
    require(metadata["attack_history_checked_at"] == "2026-10-16", "history date")
    require(metadata["prior_public_attack_located"] is False, "history classification")
    require(metadata["layer"] == "design" and metadata["full_scale"] is True, "attack scope")
    require(metadata["signing_queries"] == 0, "zero signing-oracle queries")
    require(metadata["workers"] == 1, "worker count")
    require(metadata["independent_reproduction"] is True, "independent reproduction")
    require(metadata["human_verification"] is False, "human verification flag")
    require(metadata["human_verification_required"] is False, "human verification requirement")
    require(metadata["technique_originality_claimed"] is False, "technique novelty boundary")
    technique_urls = {entry["url"] for entry in metadata["technique_attribution"]}
    require(
        technique_urls == {
            "https://ngcc.dev/reports/sign-07.html#sign-07-2-verifier-challenge-sign-blindness-enables-universal-forgery",
            "https://patents.google.com/patent/EP4224785A1/en",
        },
        "mandatory related-technique attribution",
    )
    require(metadata["title_ai_generated"] is True, "AI-generated title flag")
    require(metadata["title_wordplay_selected_by_codex"] is True, "AI-selected wordplay flag")
    require(
        metadata["attack_paper_authors"] == ["Martin Feussner"]
        and metadata["attack_paper_affiliation"] == "Selmer Center, University of Bergen"
        and metadata["attack_paper_contact"] == "martin.feussner@uib.no",
        "paper byline metadata",
    )
    require(metadata["verified_attack"] is True, "verified-attack flag")
    require(metadata["attack_counted"] is True, "attack count flag")
    require(metadata["counts_as_verified_attack"] is True, "verified count flag")
    require(metadata["publication_status"] == PUBLICATION_STATUS, "publication status")
    require(metadata["verification_basis"] == VERIFICATION_BASIS, "verification basis")
    require(
        metadata["ai_provenance"]["publication_review"]
        == "independent AI Publication Reviewer; PASS / NO VETO",
        "AI publication-review provenance",
    )
    require(metadata["publication_review"] == PUBLICATION_REVIEW, "publication-review evidence")
    require("attack_result_candidate" not in metadata, "obsolete attack-result field")
    require("candidate_artifacts" not in metadata, "obsolete artifact field")
    require("staging_self_test" not in metadata, "obsolete self-test field")
    require("publication_artifacts" in metadata, "publication artifact field")
    require("publication_package_self_test" in metadata, "publication self-test field")
    require(
        "candidate_reproducer_completion" not in metadata["codec"]
        and "publication_reproducer_completion" in metadata["codec"],
        "publication reproducer-completion field",
    )
    metadata_text = json.dumps(metadata, sort_keys=True)
    require(
        "CANDIDATE_PENDING_INDEPENDENT_PUBLICATION_REVIEW" not in metadata_text,
        "candidate publication status remains in metadata",
    )
    require(
        "PRIVATE_STAGING_PENDING_REQUIRED_GATES" not in metadata_text,
        "private staging status remains in metadata",
    )
    require("pending Publication Review" not in metadata_text, "pending-review text remains in metadata")
    gates = metadata["publication_gates"]
    require(gates["fresh_context_independent_reproduction"] == "PASS", "independent gate")
    require(gates["final_exact_target_history"] == "PASS", "final history gate")
    require(gates["independent_publication_review"] == "PASS", "publication review gate")
    require(
        not any(value == "PENDING" for value in gates.values()),
        "pending publication gate remains",
    )
    require(metadata["final_history_evidence"]["history_supported_wording"] == HISTORY_WORDING, "history wording")
    require(metadata["history_evidence"]["final_report_sha256"] == "484f630020e4b9812891c99e026e0a6cb78e974888cad9c28367f8761b4b82b9", "history report pin")
    require(metadata["history_evidence"]["final_verdict_sha256"] == "4f99ca5db817198efb730ae1589834a91f7083620706c2ff8eea0fb236e1cb7a", "history verdict pin")
    require(metadata["history_evidence"]["final_source_query_ledger_sha256"] == "1e46b6a308cc9fbc294626aa42b418789ba977f20e5e23d55a39183cffd739c3", "history ledger pin")
    require(metadata["history_evidence"]["final_manifest_sha256"] == "2ec10a0339178163b80a5016d76b8612348a11a2bf9220af0e3a2af27d64144e", "history manifest pin")
    require(metadata["history_evidence"]["final_manifest_detached_sha256"] == "b2bc49d218e87cc65de9d520c864da8ac619e0c9af6a5e49553a8921818e1fbf", "history detached pin")
    hostile = metadata["hostile_review"]
    require(
        hostile["manifest_sha256"] == ORIGINAL_HOSTILE_MANIFEST_SHA256,
        "hostile-review original manifest pin",
    )
    require(
        hostile["verdict_sha256"] == ORIGINAL_HOSTILE_VERDICT_SHA256,
        "hostile-review verdict pin",
    )
    require(
        hostile["check_results_sha256"]
        == ORIGINAL_HOSTILE_MANIFEST_ENTRIES["./CHECK_RESULTS.json"],
        "hostile-review CHECK_RESULTS pin is not the original manifest entry",
    )
    require(
        hostile["integrity_correction_bundle_path"] == CORRECTION_BUNDLE_PATH,
        "hostile-review correction-bundle path",
    )
    require(
        hostile["integrity_correction_manifest_sha256"]
        == CORRECTION_MANIFEST_SHA256,
        "hostile-review correction-manifest pin",
    )
    require(
        hostile["integrity_correction_detached_record_sha256"]
        == CORRECTION_DETACHED_RECORD_SHA256,
        "hostile-review correction detached-record pin",
    )

    require(quick["result"].startswith("PASS:"), "quick reference result")
    require(all(quick["checks"].values()), "quick reference checks")
    require(quick["attack"]["signing_queries"] == 0, "quick signing-query count")
    require(quick["environment"]["workers"] == 1, "quick worker count")
    require(full["all_rows_pass"] is True, "all-row reference pass")
    require(full["attack"]["signing_queries"] == 0, "all-row signing-query count")
    require(len(full["results"]) == 2, "all-row result count")
    require(all(row["all_expected_checks_pass"] for row in full["results"]), "all-row checks")
    require([row["hsig_queries"] for row in full["results"]] == [19, 1], "stable Hsig counts")
    require([row["hint_norm_squared"] for row in full["results"]] == [136885, 47681], "stable hint norms")
    require(affected == {
        "eprint_id": "2026/1941",
        "rows": [
            {
                "n": 32,
                "profile": "DUALMS2-ROUNDED-N32-PAPER-Q2113928077-V1",
                "q": 2113928077,
                "result": "practical probabilistic fresh-message forgery",
            },
            {
                "n": 1024,
                "profile": "DUALMS2-ROUNDED-N1024-PAPER-Q4160748533-V1",
                "q": 4160748533,
                "result": "one-Hsig-query fresh-message forgery; every canonical hint fits",
            },
        ],
        "scope": "Both advertised rounded Table-6 rows; zero signing-oracle queries.",
    }, "exact affected rows")
    require(
        [(row["n"], row["N"], row["m"], row["ell"], row["q"], row["nu_b"], row["nu_w"])
         for row in metadata["affected_profiles"]]
        == [
            (32, 256, 7, 6, 2113928077, 11, 26),
            (1024, 256, 10, 6, 4160748533, 11, 28),
        ],
        "metadata affected profiles",
    )
    require(raw["banner"] == PUBLIC_BANNER, "raw public banner")
    require(raw["publication_status"] == PUBLICATION_STATUS, "raw publication status")
    require(raw["summary"]["profiles_passed"] == 2, "raw passed-profile count")
    require(raw["summary"]["profiles_total"] == 2, "raw total-profile count")
    require(raw["summary"]["signing_oracle_queries"] == 0, "raw signing queries")
    require(raw["summary"]["all_ordinary_verifiers_accepted"] is True, "raw verifier acceptance")
    require(raw["summary"]["all_negative_controls_rejected"] is True, "raw controls")
    require(len(raw["profiles"]) == 2, "raw profile count")
    require([row["profile"] for row in raw["profiles"]] == [
        "DUALMS2-ROUNDED-N32-PAPER-Q2113928077-V1",
        "DUALMS2-ROUNDED-N1024-PAPER-Q4160748533-V1",
    ], "raw exact profile rows")
    require(
        [row["attack"]["hsig_queries"] for row in raw["profiles"]] == [19, 1],
        "raw stable Hsig counts",
    )
    require(
        [row["attack"]["hint_norm_squared"] for row in raw["profiles"]]
        == [136885, 47681],
        "raw stable hint norms",
    )
    require(
        all(row["security_game"]["signing_oracle_queries"] == 0 for row in raw["profiles"]),
        "raw per-row signing-query count",
    )
    require(
        all(row["security_game"]["fresh_message"] for row in raw["profiles"]),
        "raw fresh-message flags",
    )
    require(
        all(row["attack"]["ordinary_verifier_accepted"] for row in raw["profiles"]),
        "raw per-row verifier acceptance",
    )
    require(
        all(row["all_negative_controls_rejected"] for row in raw["profiles"]),
        "raw per-row controls",
    )
    require(
        quick["digests"]["reproducer_core_sha256"]
        == full["digests"]["reproducer_core_sha256"]
        == digest("reproducer/dualms2_reference.py"),
        "reference-fixture core digest",
    )
    require(
        quick["digests"]["stable_raw_output_sha256"]
        == full["digests"]["stable_raw_output_sha256"]
        == digest("reproducer/reference-run-output.json"),
        "reference-fixture raw-output digest",
    )
    require(
        quick["digests"]["stable_seed_sha256"]
        == full["digests"]["stable_seed_sha256"]
        == "10a1909f0d7cb48eb904d6119c8c478dcd11a7265a6cd70d78d8a5bcb63ef2d4",
        "reference seed digest",
    )
    for summary, raw_row in zip(full["results"], raw["profiles"], strict=True):
        require(summary["parameter_row"] == raw_row["profile"], "summary/raw profile")
        require(summary["signature_sha256"] == raw_row["attack"]["signature_sha256"], "summary/raw signature")
        require(summary["hsig_queries"] == raw_row["attack"]["hsig_queries"], "summary/raw Hsig count")
        require(summary["hint_norm_squared"] == raw_row["attack"]["hint_norm_squared"], "summary/raw hint norm")

    independent = metadata["independent_reproduction_evidence"]
    require(independent["status"] == "PASS_INDEPENDENT_REPRODUCTION_BOTH_ADVERTISED_ROUNDED_ROWS", "independent verdict")
    require(independent["signing_oracle_queries"] == 0, "independent signing queries")
    require(independent["n32"]["attacker_hsig_queries"] == 4, "independent n32 Hsig queries")
    require(independent["n1024"]["attacker_hsig_queries"] == 1, "independent n1024 Hsig queries")
    require(independent["n1024"]["direct_full_list_hagg"] is True, "direct full-list Hagg")
    require(independent["n1024"]["list_prehash_substitution"] is False, "no list prehash")

    require(readme.count(HISTORY_WORDING) == 1, "README exact bounded history wording")
    require(tex.count(HISTORY_WORDING) == 1, "paper exact bounded history wording")
    require(
        readme.count(PUBLICATION_REVIEW_SENTENCE) == 1,
        "README exact publication-review sentence",
    )
    require(
        flat_tex_plain.count(PUBLICATION_REVIEW_SENTENCE) == 1,
        "paper exact publication-review sentence",
    )
    require(readme.count(DISCLOSURE) == 1 and tex.count(DISCLOSURE) == 1, "exact Daybreak disclosure")
    require("deliberately chose “Takes the Hint”" in readme, "README wordplay disclosure")
    require("deliberately chose ``Takes the Hint''" in flat_tex, "paper wordplay disclosure")
    require(tex.count(TEX_BYLINE) == 1, "paper byline")
    acknowledgement_block = (
        r"\section*{Acknowledgements}" + "\n\n" + ACKNOWLEDGEMENT
    )
    require(tex.count(acknowledgement_block) == 1, "exact unnumbered acknowledgements block")
    require(r"\section{Acknowledgements}" not in tex, "numbered acknowledgements heading")
    require(readme.count(ACKNOWLEDGEMENT) == 1 and tex.count(ACKNOWLEDGEMENT) == 1, "exact NREC acknowledgement")
    require(
        "execute both advertised rows with fresh operating-system entropy" in readme,
        "README fresh root-wrapper behavior",
    )
    require(
        "separate stable\nall-row helper" in readme,
        "README stable all-row-helper distinction",
    )
    require("`VERIFIED_ATTACK`" in readme, "README final publication status")
    require("verified practical design attack" in flat_tex, "paper verified wording")
    require("Verified cryptanalytic attack on IACR ePrint 2026/1941" in tex, "paper PDF subject")
    require(PUBLIC_BANNER in readme, "README public reproducer banner")
    core_source = (ROOT / "reproducer/dualms2_reference.py").read_text(encoding="utf-8")
    runner_source = (ROOT / "reproducer/runner.py").read_text(encoding="utf-8")
    reproducer_readme = (ROOT / "reproducer/README.md").read_text(encoding="utf-8")
    require(core_source.count(f'"banner": "{PUBLIC_BANNER}"') == 1, "core public banner")
    require(core_source.count(f'"publication_status": "{PUBLICATION_STATUS}"') == 1, "core public status")
    require(runner_source.count(f'"banner": "{PUBLIC_BANNER}"') == 1, "runner public banner")
    require(runner_source.count(f'"publication_status": "{PUBLICATION_STATUS}"') == 1, "runner public status")
    require("public reproducer" in reproducer_readme.lower(), "public reproducer README")
    require(
        all(term not in reproducer_readme.lower() for term in (
            "private staging", "pending publication", "publication candidate",
        )),
        "reproducer README retains staging-status language",
    )
    status_scan = "\n".join((
        readme.replace(PUBLICATION_REVIEW_SENTENCE, ""),
        tex.replace(
            "Independent Publication Review returned PASS /\n"
            "NO VETO for the sealed pre-integration candidate (manifest SHA-256\n"
            r"\hash{cd8a152ee60fef056df0c6c08f4f612848ee2007998259149037b698315899a0}). "
            "Independent human verification was not performed and is not required.",
            "",
        ),
        reproducer_readme,
        core_source,
        runner_source,
    )).lower()
    require("private staging" not in status_scan, "private staging status remains")
    require("pending publication" not in status_scan, "pending publication status remains")
    require("pending independent publication review" not in status_scan, "pending review status remains")
    require("candidate reproduction" not in status_scan, "candidate reproducer status remains")
    forbidden_macro = "operator" + "name"
    require(forbidden_macro not in readme, "forbidden README macro")

    validate_root_wrapper()

    pins = {
        "reproducer_sha256": "reproduce.py",
        "independent_reproducer_sha256": "reproduce-all-rows.py",
        "reference_output_sha256": "reference-output.json",
        "all_rows_reference_output_sha256": "all-rows-reference-output.json",
        "attack_paper_sha256": "paper/attack.pdf",
        "attack_paper_source_sha256": "paper/attack.tex",
        "attack_paper_makefile_sha256": "paper/Makefile",
    }
    for field, relative in pins.items():
        require(metadata[field] == digest(relative), f"metadata pin {field}")
    artifacts = metadata["publication_artifacts"]
    artifact_pins = {
        "paper_makefile_sha256": "paper/Makefile",
        "paper_pdf_sha256": "paper/attack.pdf",
        "paper_source_sha256": "paper/attack.tex",
        "reproducer_core_sha256": "reproducer/dualms2_reference.py",
        "reproducer_runner_sha256": "reproducer/runner.py",
    }
    for field, relative in artifact_pins.items():
        require(artifacts[field] == digest(relative), f"publication artifact pin {field}")
    require(artifacts["paper_pages"] == 8, "paper page count metadata")
    self_test = metadata["publication_package_self_test"]
    require(self_test["status"] == "PASS", "package self-test status")
    require(self_test["profiles_passed"] == 2 and self_test["profiles_total"] == 2, "package self-test rows")
    require(self_test["workers"] == 1, "package self-test workers")
    require(self_test["all_negative_controls_rejected"] is True, "package self-test controls")
    require(self_test["reference_output_sha256"] == digest("reproducer/reference-run-output.json"), "package self-test raw pin")
    require(self_test["seed_hex"] == raw["seed_hex"], "package self-test seed")
    require(self_test["n32_hsig_queries"] == raw["profiles"][0]["attack"]["hsig_queries"], "package self-test n32 Hsig")
    require(self_test["n1024_hsig_queries"] == raw["profiles"][1]["attack"]["hsig_queries"], "package self-test n1024 Hsig")
    require(metadata["affected_rows_sha256"] == digest("affected-rows.json"), "affected-row pin")

    if not args.allow_missing_manifest:
        validate_manifest()
    print("PACKAGE VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
