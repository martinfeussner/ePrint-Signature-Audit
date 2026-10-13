#!/usr/bin/env python3
"""Run the full-row TOT zero-query forgery reproduction.

The underlying fixture uses a fresh OS-random conforming key.  This wrapper
emits only stable, review-relevant fields so its output can be compared with
the checked-in reference result.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent
PRIMARY = ROOT / "reproducer" / "primary"
TARGET_PDF_SHA256 = (
    "8ee1200e43b60123cf02f0261bee8e381b1229fde8c7722df086d95e6b7784bc"
)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tot-primary-") as temp_name:
        run_dir = pathlib.Path(temp_name) / "primary"
        shutil.copytree(PRIMARY, run_dir)
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
            ["bash", "run.sh"],
            cwd=run_dir,
            env=env,
            check=True,
            timeout=240,
            stdout=subprocess.DEVNULL,
        )

        result = json.loads((run_dir / "results.json").read_text())
        fixture = json.loads((run_dir / "fixture-results.json").read_text())
        verification = json.loads(
            (run_dir / "verification-results.json").read_text()
        )
        toy = json.loads((run_dir / "patent-toy-results.json").read_text())

    checks = {
        "all_four_negative_controls_reject": (
            verification["negative_control_rejects"] == 4
            and verification["negative_control_count"] == 4
        ),
        "canonical_full_quadratic_public_key": (
            fixture["public_payload_bits"] == 1_073_280
            and fixture["canonical_diagonal_nonzero"] == 0
        ),
        "exact_recommended_row": fixture["parameter_row"]
        == {"q": 2, "n": 128, "d": 6, "t": 64},
        "fresh_raw_vector": result["freshness_basis"]
        == "no message was submitted to a signing oracle",
        "no_private_material_serialized": not fixture["private_material_serialized"],
        "ordinary_verifier_accepts": verification["forged_pair_accepted"],
        "patent_toy_vector_accepts": toy["ordinary_verifier_accepts"],
        "zero_signing_queries": result["signing_queries"] == 0,
    }
    if result["status"] != "PASS" or not all(checks.values()):
        raise SystemExit("TOT attack reproduction failed")

    output = {
        "attack": {
            "fresh_message": True,
            "public_key_only": True,
            "signing_queries": 0,
        },
        "checks": checks,
        "controls_rejected": 4,
        "digests": {
            "primary_public_map_source_sha256": sha256_file(
                PRIMARY / "tot_public.py"
            ),
            "target_pdf_sha256": TARGET_PDF_SHA256,
        },
        "environment": {"workers": 1},
        "full_scale": True,
        "parameter_row": "q=2,n=128,d=6,t=64",
        "result": "VERIFIED_ATTACK",
        "scope": "literal raw F_2^128 message-vector interface",
        "successes": 1,
        "trials": 1,
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
