#!/usr/bin/env python3
"""Run the separately written full-row TOT reproduction."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent
INDEPENDENT = ROOT / "reproducer" / "independent"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tot-independent-") as temp_name:
        run_dir = pathlib.Path(temp_name) / "run"
        env = dict(os.environ)
        env.update(
            {
                "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "LC_ALL": "C",
                "TZ": "UTC",
            }
        )
        subprocess.run(
            ["bash", str(INDEPENDENT / "reproduce.sh"), str(run_dir)],
            env=env,
            check=True,
            timeout=240,
            stdout=subprocess.DEVNULL,
        )
        result = json.loads((run_dir / "result.json").read_text())

    controls = result["negative_controls"]
    checks = {
        "changed_message_rejects": controls["changed_raw_message_bit_rejected"],
        "changed_signature_rejects": controls["changed_signature_bit_rejected"],
        "document_hash_scope_control_rejects": controls[
            "document_hash_wrapper_message_rejected"
        ],
        "fresh_raw_vector_forgery_accepts": result[
            "fresh_raw_vector_message_forgery"
        ]
        == "ACCEPTED",
        "nonzero_signature": result["signature_nonzero"],
        "truncated_signature_rejects": controls["truncated_signature_rejected"],
        "zero_secret_reads": result["secret_reads_by_attacker"] == 0,
        "zero_signing_queries": result["signing_queries"] == 0,
    }
    if result["status"] != "PASS" or not all(checks.values()):
        raise SystemExit("independent TOT reproduction failed")

    output = {
        "all_rows_pass": True,
        "implementation_sha256": sha256_file(INDEPENDENT / "src" / "tot_public.py"),
        "results": [
            {
                "all_expected_checks_pass": True,
                "checks": checks,
                "controls_rejected": 4,
                "parameter_row": "q=2,n=128,d=6,t=64",
                "public_key_only": True,
                "secret_reads": 0,
                "signing_queries": 0,
                "successes": 1,
                "trials": 1,
            }
        ],
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
