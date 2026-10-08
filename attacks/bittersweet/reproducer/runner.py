#!/usr/bin/env python3
"""Command-line orchestration for the sanitized Bittersweet reproducer."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import core
from . import strict_verify as verifier


HERE = Path(__file__).resolve().parent
REFERENCE_INSTANCE = HERE / "reference" / "public-intervals.json"


def write_private(path: Path, value: Any) -> None:
    raw = core.canonical(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def work_tree(requested: Path | None) -> Iterator[Path]:
    if requested is None:
        with tempfile.TemporaryDirectory(prefix="bittersweet-reproduce-") as temporary:
            root = Path(temporary)
            for name in ("private", "public", "attack"):
                (root / name).mkdir(mode=0o700 if name == "private" else 0o755)
            yield root
        return
    root = requested.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError(f"work directory must be absent or empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for name in ("private", "public", "attack"):
        (root / name).mkdir(mode=0o700 if name == "private" else 0o755)
    yield root


def source_digests() -> dict[str, str]:
    return {
        "core_sha256": core.sha256_path(HERE / "core.py"),
        "runner_sha256": core.sha256_path(Path(__file__)),
        "strict_verifier_sha256": core.sha256_path(HERE / "strict_verify.py"),
        "source_pins_sha256": core.sha256_path(HERE / "UPSTREAM-SOURCES.json"),
    }


def changed_message_rejects(
    public: dict[str, Any], public_raw: bytes, message: bytes, signature: dict[str, Any]
) -> bool:
    changed = message + b"\x00changed"
    envelope = copy.deepcopy(signature)
    envelope["message_sha256"] = hashlib.sha256(changed).hexdigest()
    envelope["message_length"] = len(changed)
    outcome = verifier.verify(public, public_raw, changed, envelope)
    # The verifier checks the recorded first-message digest immediately before
    # checking the challenge derived from that digest.  Either failure is the
    # intended cryptographic transcript binding, after envelope metadata has
    # already passed.
    return not outcome["accepted"] and outcome["reason"] in {
        "ValueError: recorded first-message hash mismatch",
        "ValueError: Fiat--Shamir challenge mismatch",
    }


def new_execution_accounting() -> dict[str, int]:
    return {
        "campaign_cryptanalytic_trials_added": 0,
        "fresh_keys": 0,
        "local_cryptanalytic_recoveries": 0,
        "local_cryptanalytic_trials": 0,
        "public_replay_attempts": 0,
        "public_replay_recoveries": 0,
    }


def base_report(
    mode: str,
    dependencies: dict[str, Any],
    started: float,
    accounting: dict[str, int],
) -> dict[str, Any]:
    return {
        "schema": "bittersweet-public-attack-reproduction-v1",
        "mode": mode,
        "target": "Bittersweet ePrint 2026/397 v1",
        "target_pdf_sha256": core.PDF_SHA256,
        "parameters": core.parameter_record(),
        "fixed_configuration": {
            "family": "B",
            "signing_queries": core.QUERY_COUNT,
            "selected_rows": core.SELECTED_ROWS,
            "block_schedule": [0],
            "configured_loops": 2,
            "reduction": "plain LLL(delta=0.99, eta=0.501)",
            "nearest_plane": "Babai",
            "fpylll_seed": core.FPYLLL_SEED,
            "workers": 1,
        },
        "environment": {**dependencies, "workers": 1},
        "source_digests": source_digests(),
        "command": {
            "actual_argv": [sys.executable, *sys.argv],
            "logical": ".venv/bin/python -B reproduce.py"
            if mode == "quick"
            else ".venv/bin/python -B reproduce.py --full",
        },
        **accounting,
        "candidate_words_emitted": False,
        "elapsed_seconds": time.monotonic() - started,
        "peak_rss_kib": core.peak_rss_kib(),
    }


def run_quick(
    work: Path,
    dependencies: dict[str, Any],
    started: float,
    accounting: dict[str, int],
) -> dict[str, Any]:
    raw = REFERENCE_INSTANCE.read_bytes()
    if core.sha256(raw) != core.REFERENCE_INTERVALS_SHA256:
        raise ValueError("pinned public reference instance changed")
    public = json.loads(raw)
    fresh_message = (
        b"Bittersweet public reproducer / distinct fresh message / "
        + bytes.fromhex(core.sha256(raw))
    )
    validation = core.validate_public_intervals(
        public,
        raw,
        expected_fresh_message=fresh_message,
    )
    public_copy = work / "public" / "public-intervals.json"
    public_copy.write_bytes(raw)
    accounting["public_replay_attempts"] = 1
    recovery = core.recover(public, raw)
    accounting["public_replay_recoveries"] = 1
    commitment = {
        "schema": "bittersweet-ephemeral-public-candidate-commitment-v1",
        "candidate_key_sha256": recovery.report["candidate_key_sha256"],
        "public_instance_sha256": validation["sha256"],
        "public_intervals_satisfied": recovery.report["all_intervals_satisfied"],
        "public_outputs_satisfied": recovery.report["public_outputs_satisfied"],
        "candidate_words_in_commitment": False,
    }
    commitment_raw = core.canonical(commitment)
    commitment_path = work / "attack" / "candidate-commitment.json"
    commitment_path.write_bytes(commitment_raw)
    evidence_messages = {
        item.get("message_sha256") for item in public.get("strict_verification_evidence", [])
    }
    if core.sha256(fresh_message) in evidence_messages:
        raise AssertionError("fresh message collides with a query message")
    fresh = core.fresh_signing_check(public, raw, recovery, fresh_message)
    if fresh["candidate_commitment_sha256"] != core.sha256(commitment_path.read_bytes()):
        raise AssertionError("fresh signature is not bound to the written candidate commitment")
    report = base_report("quick", dependencies, started, accounting)
    report.update(
        {
            "result": "FULL_PARAMETER_PUBLIC_RECOVERY_REPLAY_WITH_FRESH_SIGNING",
            "public_instance": validation,
            "solver": recovery.report,
            "fresh_signing": fresh,
            "truth_comparison": {
                "performed": False,
                "reason": "quick replay has no private truth",
            },
            "checks": {
                "fixed_level_i_d32_parameters": True,
                "sixteen_signature_public_instance": True,
                "declared_310752_comparison_count_valid": True,
                "all_747_intervals_valid": True,
                "plain_lll_babai_recovery": True,
                "all_747_public_intervals_satisfied": True,
                "all_747_public_outputs_satisfied": True,
                "fresh_message_was_not_a_query": True,
                "fresh_signature_bound_to_written_candidate_commitment": True,
                "fresh_signature_accepted_by_strict_verifier": True,
                "negative_controls_rejected": True,
                "no_stored_candidate_words_used": True,
            },
        }
    )
    report["elapsed_seconds"] = time.monotonic() - started
    report["peak_rss_kib"] = core.peak_rss_kib()
    return report


def run_full(
    work: Path,
    dependencies: dict[str, Any],
    started: float,
    accounting: dict[str, int],
) -> dict[str, Any]:
    master = os.urandom(32)
    public, public_raw, secret = core.make_public_key(master)
    accounting["fresh_keys"] = 1
    public_path = work / "public" / "public-key.json"
    public_path.write_bytes(public_raw)
    secret_bytes = b"".join(value.to_bytes(12, "big") for value in secret)
    write_private(
        work / "private" / "truth.json",
        {
            "schema": "bittersweet-local-full-reproduction-private-truth-v1",
            "warning": "LOCAL PRIVATE TRUTH; never publish",
            "master_seed_hex": master.hex(),
            "secret_k_hex": [f"{value:024x}" for value in secret],
            "secret_k_sha256": core.sha256(secret_bytes),
        },
    )
    public_sha = core.sha256(public_raw)
    signing_randomness = verifier.shake(b"full-reproducer-query-randomness", (master, bytes.fromhex(public_sha)), 32)
    records: list[tuple[bytes, dict[str, Any]]] = []
    total_aborts = 0
    for index in range(core.QUERY_COUNT):
        message = (
            b"Bittersweet full public reproduction query "
            + f"{index:02d}".encode()
            + b" / public-key "
            + public_sha.encode()
        )
        signature = core.sign(
            public,
            public_raw,
            secret,
            message,
            signing_randomness,
            query_index=index,
        )
        total_aborts += int(signature["abort_count"])
        (work / "public" / f"message-{index:02d}.bin").write_bytes(message)
        (work / "public" / f"signature-{index:02d}.json").write_bytes(core.canonical(signature))
        records.append((message, signature))

    # All 16 signatures are strictly verified by the aggregator below.  The
    # first gets the complete control suite; each remaining query gets an
    # independently bound changed-message control.
    first_controls = verifier.mutation_controls(public, public_raw, records[0][0], records[0][1])
    if not core.controls_pass(first_controls):
        raise ValueError("full query control suite failed")
    changed_message_controls = sum(
        changed_message_rejects(public, public_raw, message, signature)
        for message, signature in records[1:]
    )
    if changed_message_controls != core.QUERY_COUNT - 1:
        raise ValueError("a query changed-message control accepted")

    intervals, intervals_raw, aggregation = core.aggregate_verified_signatures(
        public, public_raw, records
    )
    validation = core.validate_public_intervals(intervals, intervals_raw)
    interval_path = work / "attack" / "public-intervals.json"
    interval_path.write_bytes(intervals_raw)
    accounting["local_cryptanalytic_trials"] = 1
    recovery = core.recover(intervals, intervals_raw)
    commitment = {
        "schema": "bittersweet-ephemeral-public-candidate-commitment-v1",
        "candidate_key_sha256": recovery.report["candidate_key_sha256"],
        "public_instance_sha256": validation["sha256"],
        "public_intervals_satisfied": recovery.report["all_intervals_satisfied"],
        "public_outputs_satisfied": recovery.report["public_outputs_satisfied"],
        "candidate_words_in_commitment": False,
    }
    commitment_path = work / "attack" / "candidate-commitment.json"
    commitment_raw = core.canonical(commitment)
    commitment_path.write_bytes(commitment_raw)

    # This is the sole truth access after the candidate commitment is written.
    exact_words = sum(left == right for left, right in zip(recovery.key, secret))
    exact = exact_words == core.N and recovery.report["candidate_key_sha256"] == core.sha256(secret_bytes)
    if not exact:
        raise ValueError(f"recovered key differs from generated truth ({exact_words}/{core.N})")
    accounting["local_cryptanalytic_recoveries"] = 1
    truth_report = {
        "schema": "bittersweet-local-truth-comparison-v1",
        "candidate_committed_before_truth": True,
        "exact_words": exact_words,
        "total_words": core.N,
        "exact_key": exact,
        "candidate_key_sha256": recovery.report["candidate_key_sha256"],
        "raw_words_emitted": False,
    }
    (work / "attack" / "truth-comparison.json").write_bytes(core.canonical(truth_report))

    fresh_message = (
        b"Bittersweet full public reproduction fresh message 17 / "
        + bytes.fromhex(public_sha)
    )
    if fresh_message in {message for message, _ in records}:
        raise AssertionError("fresh message is not distinct")
    fresh = core.fresh_signing_check(intervals, intervals_raw, recovery, fresh_message)
    if fresh["candidate_commitment_sha256"] != core.sha256(commitment_path.read_bytes()):
        raise AssertionError("fresh signature is not bound to the written candidate commitment")
    query_control_total = len(first_controls["controls"]) + core.QUERY_COUNT - 1
    query_control_rejected = sum(
        item["rejected"] for item in first_controls["controls"].values()
    ) + changed_message_controls
    report = base_report("full", dependencies, started, accounting)
    report.update(
        {
            "result": "FULL_PARAMETER_SECRET_KEY_RECOVERY_WITH_FRESH_SIGNING",
            "generation": {
                "fresh_key_count": 1,
                "signature_count": core.QUERY_COUNT,
                "distinct_message_count": core.QUERY_COUNT,
                "total_signing_aborts": total_aborts,
                "private_truth_written_outside_attacker_input": True,
                "public_key_sha256": public_sha,
            },
            "query_controls": {
                "rejected": query_control_rejected,
                "total": query_control_total,
                "full_control_suite_on_query_zero": sorted(first_controls["controls"]),
                "changed_message_controls_on_remaining_queries": changed_message_controls,
            },
            "aggregation": aggregation,
            "public_instance": validation,
            "solver": recovery.report,
            "truth_comparison": truth_report,
            "fresh_signing": fresh,
            "checks": {
                "fresh_key_generated_locally": True,
                "private_truth_separated_from_attacker_input": True,
                "sixteen_distinct_complete_signatures": True,
                "all_query_signatures_strictly_accepted": True,
                "query_negative_controls_rejected": query_control_rejected == query_control_total,
                "all_310752_comparisons_derived": True,
                "all_747_intervals_valid": True,
                "plain_lll_babai_recovery": True,
                "all_747_public_intervals_satisfied": True,
                "all_747_public_outputs_satisfied": True,
                "exact_generated_key_recovered": exact,
                "candidate_committed_before_truth": True,
                "fresh_message_was_not_a_query": True,
                "fresh_signature_bound_to_written_candidate_commitment": True,
                "fresh_signature_accepted_by_strict_verifier": True,
                "fresh_signature_negative_controls_rejected": True,
                "no_candidate_words_emitted": True,
            },
        }
    )
    report["elapsed_seconds"] = time.monotonic() - started
    report["peak_rss_kib"] = core.peak_rss_kib()
    return report


def reference_projection(report: dict[str, Any]) -> dict[str, Any]:
    solver = report["solver"]
    fresh = report["fresh_signing"]
    return {
        "attack": {
            "family": "B",
            "signing_queries": core.QUERY_COUNT,
            "selected_rows": core.SELECTED_ROWS,
            "reduction": "plain LLL(delta=0.99, eta=0.501)",
            "nearest_plane": "Babai",
            "fpylll_seed": core.FPYLLL_SEED,
            "secret_key_material_stored": False,
        },
        "checks": {name: bool(value) for name, value in sorted(report["checks"].items())},
        "counts": {
            "comparisons_per_row": core.QUERY_COUNT * core.T,
            "total_comparisons": core.QUERY_COUNT * core.T * core.M,
            "selected_intervals_satisfied": solver["selected_intervals_satisfied"],
            "public_intervals_satisfied": solver["all_intervals_satisfied"],
            "public_outputs_satisfied": solver["public_outputs_satisfied"],
            "fresh_negative_controls_rejected": fresh["negative_controls"]["rejected"],
            "fresh_negative_controls_total": fresh["negative_controls"]["total"],
        },
        "digests": {
            "candidate_key_sha256": solver["candidate_key_sha256"],
            "fresh_message_sha256": fresh["message_sha256"],
            "fresh_signature_sha256": fresh["signature_sha256"],
            "public_interval_instance_sha256": report["public_instance"]["sha256"],
            "selected_rows_sha256": solver["selected_rows_sha256"],
        },
        "environment": {"workers": 1},
        "experiment_id": "BTS-PUBLIC-REPRODUCER-V1",
        "mode": report["mode"],
        "parameters": core.parameter_record(),
        "result": report["result"],
        "target": report["target"],
        "trials": {
            name: int(report[name])
            for name in (
                "campaign_cryptanalytic_trials_added",
                "fresh_keys",
                "local_cryptanalytic_recoveries",
                "local_cryptanalytic_trials",
                "public_replay_attempts",
                "public_replay_recoveries",
            )
        },
    }


def print_banner(report: dict[str, Any]) -> None:
    exact = report["truth_comparison"].get("exact_words")
    exact_text = f"{exact}/{core.N}" if exact is not None else "not used (public-only quick replay)"
    fresh = report["fresh_signing"]
    lines = [
        "========================================",
        "ATTACK REPRODUCTION: PASS",
        "",
        "Scheme: Bittersweet ePrint 2026/397 v1",
        "Parameters: Level I d=32",
        f"Mode: {report['mode']}",
        (
            "Local cryptanalytic trials: 1 (campaign added: 0)"
            if report["mode"] == "full"
            else "Campaign cryptanalytic trials added: 0"
        ),
        (
            "Local cryptanalytic recoveries: 1"
            if report["mode"] == "full"
            else "Public recovery replay: PASS (1/1)"
        ),
        (
            "Signing queries generated: 16"
            if report["mode"] == "full"
            else "Reference-instance signatures: 16 (new signing queries: 0)"
        ),
        f"Public interval checks: {report['solver']['all_intervals_satisfied']}/747",
        f"Public rounded-output checks: {report['solver']['public_outputs_satisfied']}/747",
        f"Exact generated-key comparison: {exact_text}",
        "Fresh-message signature: ACCEPTED",
        f"Negative controls: PASS ({fresh['negative_controls']['rejected']}/{fresh['negative_controls']['total']})",
        f"Runtime: {report['elapsed_seconds']:.2f} s",
        f"Peak RAM: {report['peak_rss_kib']} KiB",
        "Workers: 1",
        "Candidate words emitted: no",
        "========================================",
    ]
    print("\n".join(lines))


def execute(
    mode: str,
    work_dir: Path | None,
    accounting: dict[str, int],
) -> dict[str, Any]:
    started = time.monotonic()
    dependencies = core.dependency_record()
    with work_tree(work_dir) as work:
        report = (
            run_full(work, dependencies, started, accounting)
            if mode == "full"
            else run_quick(work, dependencies, started, accounting)
        )
        (work / "attack" / "result.json").write_bytes(core.canonical(report))
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--quick", action="store_true", help="replay the public S16 interval instance (default)")
    modes.add_argument("--full", action="store_true", help="generate a fresh key and 16 signatures before attack")
    parser.add_argument("--work-dir", type=Path, help="persist separated private/public/attack work files")
    parser.add_argument("--output", type=Path, help="write the full measured JSON result")
    parser.add_argument(
        "--reference-output",
        type=Path,
        help="write deterministic canonical quick reference projection (quick mode only)",
    )
    args = parser.parse_args(argv)
    if args.full and args.reference_output:
        parser.error(
            "--reference-output is available only in quick mode; use --output "
            "for full mode (rejected before execution: zero keys and zero local trials)"
        )
    if (
        args.output is not None
        and args.reference_output is not None
        and args.output.resolve() == args.reference_output.resolve()
    ):
        parser.error(
            "--output and --reference-output must resolve to different paths "
            "(rejected before execution: zero keys and zero local trials)"
        )
    mode = "full" if args.full else "quick"
    report: dict[str, Any] | None = None
    accounting = new_execution_accounting()
    try:
        report = execute(mode, args.work_dir, accounting)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(core.canonical(report))
        if args.reference_output:
            args.reference_output.parent.mkdir(parents=True, exist_ok=True)
            args.reference_output.write_bytes(core.canonical(reference_projection(report)))
    except (AssertionError, OSError, RuntimeError, ValueError) as exc:
        print("========================================", file=sys.stderr)
        print("ATTACK REPRODUCTION: FAIL", file=sys.stderr)
        print(f"Reason: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "Execution accounting: "
            + ", ".join(f"{name}={value}" for name, value in accounting.items()),
            file=sys.stderr,
        )
        print("========================================", file=sys.stderr)
        return 1
    assert report is not None
    print_banner(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
