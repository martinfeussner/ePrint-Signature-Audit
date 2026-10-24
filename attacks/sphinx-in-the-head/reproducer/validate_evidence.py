#!/usr/bin/env python3
"""Standalone validator for retained or fresh typed-paper evidence.

This program never imports or executes the attack model. It parses JSON,
checks the evidence contract, and hashes the exact clean-room implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "evidence" / "evidence.json"
DEFAULT_IMPLEMENTATION = ROOT / "reproduce-all-rows.py"
REFERENCE_OUTPUT = ROOT / "reference-output.json"
ALL_ROWS_OUTPUT = ROOT / "all-rows-reference-output.json"

PROFILE_ID = (
    "SITH-2024-649-HBGS-TEST2-N255-Q1024-H1-D16-K70-"
    "NR1120-NU70-Q128-G2P10-PAPER-ALG2-ZEROPAD"
)
PAPER_SHA256 = "67581ad5d1ae2455573cdb9b043344d91ca04788797318a7906ed500380a9881"
IMPLEMENTATION_SHA256 = (
    "3b3b62d9018b28cda7a279fd2145697421f5b132a5d3728d6c99daf2178ee863"
)
RETAINED_EVIDENCE_SHA256 = (
    "f4b829edf9f822a8f44fbbf94108416a603571e7305d2e5bc1671e484995cfcd"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class DuplicateKeyError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> tuple[Any, str]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    return value, text


def lookup(value: Any, path: str) -> Any:
    current = value
    for component in path.split("."):
        if isinstance(current, list):
            current = current[int(component)]
        elif isinstance(current, dict):
            current = current[component]
        else:
            raise KeyError(path)
    return current


class Checks:
    def __init__(self) -> None:
        self.count = 0
        self.errors: list[str] = []

    def require(self, condition: bool, label: str) -> None:
        self.count += 1
        if not condition:
            self.errors.append(label)

    def equal(self, actual: Any, expected: Any, label: str) -> None:
        self.require(actual == expected, f"{label}: expected {expected!r}, got {actual!r}")

    def path_equal(self, value: Any, path: str, expected: Any) -> None:
        try:
            actual = lookup(value, path)
        except (KeyError, IndexError, TypeError, ValueError):
            self.require(False, f"missing or malformed field {path}")
            return
        self.equal(actual, expected, path)


def validate_reference_files(checks: Checks) -> None:
    reference, reference_text = load_json(REFERENCE_OUTPUT)
    canonical = json.dumps(reference, indent=2, sort_keys=True) + "\n"
    checks.equal(reference_text, canonical, "reference-output.json canonical form")
    checks.path_equal(reference, "result", "PASS / independently reproduced typed-paper forgery")
    checks.path_equal(reference, "attack.signing_queries", 1)
    checks.path_equal(reference, "environment.workers", 1)
    for name, passed in reference.get("checks", {}).items():
        checks.require(isinstance(name, str) and passed is True, f"reference check {name}")
    expected_digests = {
        "independent_reproducer_sha256": IMPLEMENTATION_SHA256,
        "retained_evidence_sha256": RETAINED_EVIDENCE_SHA256,
        "target_paper_sha256": PAPER_SHA256,
    }
    checks.equal(reference.get("digests"), expected_digests, "reference digests")

    all_rows, all_rows_text = load_json(ALL_ROWS_OUTPUT)
    all_rows_canonical = json.dumps(all_rows, indent=2, sort_keys=True) + "\n"
    checks.equal(all_rows_text, all_rows_canonical, "all-rows-reference-output canonical form")
    checks.path_equal(all_rows, "all_rows_pass", True)
    results = all_rows.get("results") if isinstance(all_rows, dict) else None
    checks.require(isinstance(results, list) and len(results) == 1, "one frozen profile row")
    if isinstance(results, list) and len(results) == 1:
        checks.equal(results[0].get("parameter_row"), PROFILE_ID, "profile row identity")
        checks.equal(results[0].get("all_expected_checks_pass"), True, "profile row verdict")


def validate_trial(checks: Checks, trial: Any, number: int) -> None:
    label = f"trial[{number}]"
    checks.require(isinstance(trial, dict), f"{label} object")
    if not isinstance(trial, dict):
        return
    checks.equal(trial.get("trial"), number + 1, f"{label} number")
    checks.equal(trial.get("success"), True, f"{label} success")
    checks.equal(trial.get("profile_id"), PROFILE_ID, f"{label} profile")

    ledger = trial.get("oracle_ledger")
    checks.require(isinstance(ledger, dict), f"{label} oracle ledger")
    if isinstance(ledger, dict):
        for name in ("AddHU", "GSigHU", "TraceU"):
            checks.equal(ledger.get(name), 1, f"{label} {name} count")
        checks.equal(ledger.get("GSigHU_query_message"), "epsilon (0-bit string)", f"{label} signing message")
        checks.equal(ledger.get("TraceU_revocation_epoch"), 0, f"{label} trace epoch")
        checks.equal(ledger.get("honest_log_exact_pair_count"), 1, f"{label} honest log")

    transformation = trial.get("transformation")
    checks.require(isinstance(transformation, dict), f"{label} transformation")
    if isinstance(transformation, dict):
        expected = {
            "returned_str_name": "u",
            "returned_str_width_bits": 255,
            "fresh_msg_star_equals_u": True,
            "fresh_msg_star_width_bits": 255,
            "replacement_str_star": "0^255",
            "replacement_str_star_is_zero": True,
            "H1_epsilon_concat_u_equals_H1_u": True,
            "H1_u_equals_H1_u_concat_zero255": True,
            "original_and_transformed_sid_equal": True,
        }
        for key, expected_value in expected.items():
            checks.equal(transformation.get(key), expected_value, f"{label} transformation.{key}")
        checks.equal(
            transformation.get("retained_fields"),
            {"commitment_com": True, "group_proof_pi_G": True, "tracing_token_stt": True},
            f"{label} retained fields",
        )
        checks.require(
            isinstance(transformation.get("returned_str_is_zero"), bool),
            f"{label} observed u-zero flag",
        )

    endpoint = trial.get("figure8_endpoint")
    checks.require(isinstance(endpoint, dict), f"{label} Figure-8 endpoint")
    if isinstance(endpoint, dict):
        expected = {
            "tau": 0,
            "RL_tau": "RL_0",
            "TraceU_GVf_gate_accepts": True,
            "TraceU_returns_id_h": True,
            "GVf_msg_star_sigma_star_RL0": True,
            "exact_pair_msg_star_sigma_star_absent_from_S": True,
            "message_fresh_despite_not_required_by_exact_pair_game": True,
            "message_fresh_even_if_u_is_zero": True,
            "TVf_id_h_pi_t_star_sigma_star_msg_star": True,
            "Figure_8_returns_1": True,
        }
        for key, expected_value in expected.items():
            checks.equal(endpoint.get(key), expected_value, f"{label} endpoint.{key}")

    expected_controls = {
        "changed_statement_proof_reuse_rejected",
        "framed_domain_separated_H1_counterfactual_rejected",
        "nonzero_replacement_str_rejected",
        "public_credential_synthesis_rejected",
        "public_only_zero_query_signature_construction_rejected",
        "public_proof_synthesis_rejected",
        "revocation_rejected",
        "signature_field_mutation_rejected",
    }
    controls = trial.get("controls")
    checks.require(isinstance(controls, dict), f"{label} controls object")
    if isinstance(controls, dict):
        checks.equal(set(controls), expected_controls, f"{label} control names")
        checks.require(all(value is True for value in controls.values()), f"{label} all controls pass")

    framed = trial.get("framed_counterfactual_detail")
    checks.require(isinstance(framed, dict), f"{label} framed control")
    if isinstance(framed, dict):
        for key in (
            "separate_control_world",
            "original_signature_accepts",
            "original_and_transformed_sid_differ",
            "transformed_signature_rejected",
            "control_passes",
        ):
            checks.equal(framed.get(key), True, f"{label} framed.{key}")
        checks.equal(framed.get("figure8_GSigHU_queries"), 0, f"{label} framed game queries")
        checks.equal(framed.get("ordinary_direct_signature_generations"), 1, f"{label} framed direct signatures")

    boundary = trial.get("credential_and_proof_boundary")
    checks.require(isinstance(boundary, dict), f"{label} capability boundary")
    if isinstance(boundary, dict):
        checks.equal(boundary.get("credential_issuance_controlled"), True, f"{label} controlled issuance")
        checks.equal(boundary.get("proof_generation_requires_member_witness_and_issued_credential"), True, f"{label} proof capability")
        checks.equal(boundary.get("public_recomputation_interface_present"), False, f"{label} public proof creation")
        checks.equal(boundary.get("member_or_authority_secret_fields_in_attacker_view"), [], f"{label} attacker-view secrets")
        checks.equal(boundary.get("raw_secret_values_written_to_evidence"), False, f"{label} raw evidence secrets")
        checks.equal(boundary.get("deterministic_seed_option"), False, f"{label} seed option")

    padding = trial.get("algorithm2_padding")
    checks.require(isinstance(padding, dict), f"{label} padding record")
    if isinstance(padding, dict):
        checks.equal(padding.get("all_primary_top_tree_builds_exact"), True, f"{label} exact padding")
        checks.equal(padding.get("appendix_E5_node_lifting_used"), False, f"{label} no lifting")
        builds = padding.get("builds")
        checks.require(isinstance(builds, list) and len(builds) == 2, f"{label} two tree builds")
        if isinstance(builds, list):
            for index, build in enumerate(builds):
                expected = {
                    "algorithm": "Appendix-B Algorithm-2 zero padding",
                    "appended_zero_leaf_count": 58,
                    "capacity": 128,
                    "height": 7,
                    "initial_leaf_count": 70,
                    "lifted_node_count": 0,
                    "root_width_bits": 1120,
                    "zero_leaf_width_bits": 255,
                }
                checks.equal(build, expected, f"{label} padding build {index}")

    ordinary = trial.get("ordinary_api")
    checks.require(isinstance(ordinary, dict), f"{label} ordinary API")
    if isinstance(ordinary, dict):
        checks.equal(ordinary.get("GSig_and_GVf_share_sid_policy"), "paper-unframed-H1(msg||str)", f"{label} sid policy")
        checks.equal(ordinary.get("attack_only_verifier_branch"), False, f"{label} no attack branch")
        checks.equal(ordinary.get("original_signature_accepts"), True, f"{label} original acceptance")
        checks.equal(ordinary.get("str_sampler_conditions_away_zero"), False, f"{label} unconditioned str")

    fingerprints = trial.get("public_fingerprints_sha256")
    checks.require(isinstance(fingerprints, dict) and len(fingerprints) == 3, f"{label} fingerprints")
    if isinstance(fingerprints, dict):
        checks.require(all(isinstance(value, str) and HEX64.fullmatch(value) for value in fingerprints.values()), f"{label} fingerprint format")
    runtime = trial.get("runtime_seconds")
    checks.require(isinstance(runtime, (int, float)) and not isinstance(runtime, bool) and math.isfinite(runtime) and runtime >= 0, f"{label} runtime")


def validate_evidence(evidence_path: Path, implementation_path: Path, reference: bool) -> tuple[Checks, str]:
    checks = Checks()
    evidence, source = load_json(evidence_path)
    checks.require(isinstance(evidence, dict), "top-level evidence object")
    if not isinstance(evidence, dict):
        return checks, ""

    canonical = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    checks.equal(source, canonical, "evidence canonical JSON")
    implementation_hash = sha256_file(implementation_path)
    checks.equal(implementation_hash, IMPLEMENTATION_SHA256, "exact clean-room implementation hash")
    evidence_hash = sha256_file(evidence_path)
    if reference or evidence_path.resolve() == DEFAULT_EVIDENCE.resolve():
        checks.equal(evidence_hash, RETAINED_EVIDENCE_SHA256, "retained evidence hash")

    checks.path_equal(evidence, "schema_version", "1.0")
    checks.path_equal(evidence, "artifact_type", "independent_typed_paper_reproduction_evidence")
    checks.path_equal(evidence, "candidate_id", "sphinx-independent-typed-paper-v2")
    checks.path_equal(evidence, "paper.eprint", "2024/649")
    checks.path_equal(evidence, "paper.sha256", PAPER_SHA256)
    checks.path_equal(evidence, "profile.profile_id", PROFILE_ID)
    expected_profile = {
        "n": 255,
        "q": 1024,
        "h": 1,
        "d": 16,
        "k": 70,
        "NR": 1120,
        "NU": 70,
        "gp": [255, 1024, 1, 16, 70],
        "claimed_quantum_security_bits": 128,
        "mfors_base_tree_count": 70,
        "mfors_base_tree_logical_leaves_each": 65536,
        "mfors_public_key_bits_d_times_k": 1120,
        "mpc_parties": 16,
        "partial_path_repetitions": 16,
        "top_tree_capacity": 128,
        "top_tree_height": 7,
        "top_tree_zero_leaves": 58,
    }
    profile = evidence.get("profile")
    if isinstance(profile, dict):
        for key, expected in expected_profile.items():
            checks.equal(profile.get(key), expected, f"profile.{key}")
    else:
        checks.require(False, "profile object")

    expected_scope = {
        "author_byte_conformance": False,
        "full_parameter_profile": True,
        "ideal_credential_and_proof_abstraction": True,
        "official_source_reproduction": False,
        "primary_endpoint": "Figure 8 ExpNon-Frame with tau=0",
        "real_LowMC": False,
        "real_MFORS": False,
        "real_MPCitH": False,
        "source_independent_typed_paper_model": True,
    }
    checks.equal(evidence.get("claim_scope"), expected_scope, "claim scope")
    checks.equal(evidence.get("implementation_sha256"), implementation_hash, "evidence/code binding")

    execution = evidence.get("execution")
    checks.require(isinstance(execution, dict), "execution object")
    trial_count = 0
    if isinstance(execution, dict):
        trial_count = execution.get("trials", 0)
        successes = execution.get("successes")
        workers = execution.get("workers")
        runtime = execution.get("runtime_seconds")
        checks.require(isinstance(trial_count, int) and not isinstance(trial_count, bool) and 1 <= trial_count <= 1000, "execution trial count")
        checks.equal(successes, trial_count, "execution successes")
        checks.equal(workers, 1, "execution workers")
        checks.require(isinstance(runtime, (int, float)) and not isinstance(runtime, bool) and math.isfinite(runtime) and runtime >= 0, "execution runtime")
        peak = execution.get("peak_ram")
        checks.require(isinstance(peak, dict), "peak RAM record")
        if isinstance(peak, dict):
            value = peak.get("value")
            checks.require(value is None or (isinstance(value, (int, float)) and value >= 0), "peak RAM value")

    trials = evidence.get("trials")
    checks.require(isinstance(trials, list) and len(trials) == trial_count, "trial list length")
    if isinstance(trials, list):
        for index, trial in enumerate(trials):
            validate_trial(checks, trial, index)
    checks.equal(evidence.get("all_trials_pass"), True, "aggregate verdict")

    aggregate = evidence.get("aggregate_oracle_ledger")
    checks.require(isinstance(aggregate, dict), "aggregate oracle ledger")
    if isinstance(aggregate, dict):
        for name in ("AddHU", "GSigHU", "TraceU"):
            checks.equal(aggregate.get(name), trial_count, f"aggregate {name}")
        checks.equal(aggregate.get("per_trial_required_counts"), {"AddHU": 1, "GSigHU": 1, "TraceU": 1}, "per-trial query counts")
        checks.equal(aggregate.get("per_trial_GSigHU_message"), "epsilon", "aggregate query message")
        checks.equal(aggregate.get("per_trial_TraceU_list"), "RL_0", "aggregate trace list")
        checks.equal(aggregate.get("counterfactual_signatures_not_counted_as_game_queries"), trial_count, "counterfactual accounting")

    serialized_strings = json.dumps(evidence, sort_keys=True)
    checks.require("/data/" not in serialized_strings and "state/" not in serialized_strings, "no internal project path in evidence")
    checks.require("BEGIN PRIVATE KEY" not in serialized_strings and "PRIVATE KEY-----" not in serialized_strings, "no private-key material in evidence")
    if reference:
        validate_reference_files(checks)
    return checks, evidence_hash


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--implementation", type=Path, default=DEFAULT_IMPLEMENTATION)
    parser.add_argument(
        "--reference",
        action="store_true",
        help="also require the retained evidence digest and public reference files",
    )
    args = parser.parse_args(argv)
    try:
        checks, evidence_hash = validate_evidence(args.evidence, args.implementation, args.reference)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        print(f"EVIDENCE VALIDATION: FAIL ({exc})", file=sys.stderr)
        return 1

    if checks.errors:
        print("EVIDENCE VALIDATION: FAIL", file=sys.stderr)
        for error in checks.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"Assertions: {checks.count - len(checks.errors)}/{checks.count}", file=sys.stderr)
        return 1

    retained = args.evidence.resolve() == DEFAULT_EVIDENCE.resolve()
    print("========================================")
    print("RETAINED EVIDENCE VALIDATION: PASS" if retained else "FRESH USER-RUN EVIDENCE VALIDATION: PASS")
    print(f"Profile: {PROFILE_ID}")
    print("Result: one-query fresh-message typed-paper forgery")
    print("Ordinary GVf: ACCEPTED")
    print("TraceU / TVf honest-member attribution: ACCEPTED")
    print(f"Evidence SHA-256: {evidence_hash}")
    print(f"Assertions: {checks.count}/{checks.count}")
    print("Attack execution: NOT RUN by this validator")
    print("========================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
