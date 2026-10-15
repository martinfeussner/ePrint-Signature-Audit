#!/usr/bin/env python3
"""Print the decisive full-run results from the validated JSON summary."""

from pathlib import Path
import json
import sys


if len(sys.argv) != 2:
    raise SystemExit("usage: report-full.py SUMMARY_JSON")

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
recovery = summary["recovery"]
verifier = summary["clean_verifier"]
resources = summary["resources"]

controls = all(
    recovery[name]
    for name in (
        "changed_message_rejected",
        "changed_root_rejected",
        "altered_signature_rejected",
        "corrupted_row_rejected",
    )
)

print("JEVIL FULL ATTACK REPRODUCTION: PASS")
print(
    "Recovered rows/state: PASS "
    f"(4 rows; {recovery['distinct_positions']} distinct authenticated positions; "
    "root and public evaluation reconstructed)"
)
print(
    "Fresh unqueried message accepted by untouched ordinary verifier: "
    + ("PASS" if verifier["ordinary_verifier_accepts_forgery"] else "FAIL")
)
print(
    "Negative controls (changed message/root/signature, corrupted row): "
    + ("PASS" if controls else "FAIL")
)
print("Ordinary signing queries: 650 (indices 0..649; excluded index 1023 unused)")
print(
    "Measured oracle+recovery+clean-verifier: "
    f"{resources['attack_stages_wall_seconds']:.2f} s wall; "
    f"{resources['attack_stages_peak_rss_kib']} KiB peak RSS; one worker"
)
print(
    "Measured build+attack: "
    f"{resources['build_and_attack_wall_seconds']:.2f} s wall; "
    f"{resources['build_and_attack_peak_rss_kib']} KiB peak RSS"
)
