#!/usr/bin/env python3
"""Bind the full Magma signer output to the checked public forgery witness.

The signer runs before this script and never reads the expected witness.  This
post-processing step parses its salt and signature, creates a replay witness,
and requires byte-level JSON equivalence after canonical parsing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def load_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signer-output", default="work/full-attack-results.txt")
    parser.add_argument("--public-key", default="full-q5-128-public-key.json")
    parser.add_argument("--expected", default="full-q5-128-forgery.json")
    parser.add_argument("--output", default="work/replay-forgery.json")
    args = parser.parse_args()

    signer_path = Path(args.signer_output)
    public_path = Path(args.public_key)
    expected_path = Path(args.expected)
    output_path = Path(args.output)
    transcript = signer_path.read_text(encoding="utf-8").replace("\\\n", "")
    required_markers = (
        "public_fixed_rhs_accept=true",
        "changed_message_accepting_salts=0",
        "changed_message_reject=true",
        "ATTACK_REPRODUCTION: PASS",
    )
    if any(marker not in transcript for marker in required_markers):
        raise SystemExit("signer transcript is missing an acceptance marker")

    message_match = re.search(
        r"fresh_message_hex=([0-9a-f]+)\s+salt=([0-9]+)\s+root_attempts=([0-9]+)",
        transcript,
    )
    signature_match = re.search(
        r"forged_signature_fq=\[([^]]+)\]\s+public_fixed_rhs_accept=true",
        transcript,
        re.DOTALL,
    )
    if message_match is None or signature_match is None:
        raise SystemExit("could not parse signer-generated message, salt, and signature")

    message_hex = message_match.group(1)
    salt = int(message_match.group(2))
    signature = [int(value) for value in re.findall(r"[0-9]+", signature_match.group(1))]
    if len(signature) != 94 or any(not 0 <= value < 5 for value in signature):
        raise SystemExit("signer-generated signature has invalid dimensions or symbols")

    public = load_object(public_path)
    messages = {item["label"]: item for item in public["fixed_rhs_test"]["messages"]}
    if message_hex != messages["fresh"]["message_hex"]:
        raise SystemExit("signer-generated message does not match the public fresh message")
    public_digest = hashlib.sha256(public_path.read_bytes()).hexdigest()
    replay = {
        "message_hex": message_hex,
        "message_label": "fresh",
        "parameter": public["parameter"],
        "public_artifact": public_path.name,
        "public_artifact_sha256": public_digest,
        "rhs_interpretation": "v5 all-ones public RHS after minus projection",
        "salt": salt,
        "schema": "djames-full-q5-public-forgery-witness-v2",
        "scope": "signature, salt, and message label only; verify against sanitized public coefficients",
        "signature_fq": signature,
    }
    expected = load_object(expected_path)
    if replay != expected:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n")
        raise SystemExit(
            f"signer-generated witness differs from {expected_path}; "
            f"generated candidate retained at {output_path}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n")
    print(
        "replay_witness_matches_published=true "
        f"salt={salt} signature_symbols={len(signature)} "
        f"root_attempts={int(message_match.group(3))}"
    )


if __name__ == "__main__":
    main()
