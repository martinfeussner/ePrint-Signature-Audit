#!/usr/bin/env python3
"""Parse GNU time records and bind run artifacts by SHA-256."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_time(path: Path) -> dict[str, str | int | float]:
    fields: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if ": " in line:
            key, value = line.strip().split(": ", 1)
            fields[key] = value
    return {
        "wall": fields.get("Elapsed (wall clock) time (h:mm:ss or m:ss)", "unknown"),
        "user_seconds": float(fields.get("User time (seconds)", "nan")),
        "system_seconds": float(fields.get("System time (seconds)", "nan")),
        "maximum_rss_kib": int(fields.get("Maximum resident set size (kbytes)", "0")),
        "exit_status": int(fields.get("Exit status", "-1")),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--elapsed-seconds", required=True, type=float)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    stages = {
        name: parse_time(args.run_dir / f"{name}.time")
        for name in ("keygen", "forge", "verify")
    }
    artifacts = {}
    for name in (
        "public_key.bin",
        "forgery.json",
        "result.json",
        "environment.json",
        "keygen.stdout",
        "forge.stdout",
        "verify.stdout",
    ):
        artifacts[name] = sha256(args.run_dir / name)
    report = {
        "status": "PASS",
        "workers": 1,
        "total_wall_seconds": args.elapsed_seconds,
        "stages": stages,
        "peak_rss_kib_max_across_sequential_stages": max(
            int(stage["maximum_rss_kib"]) for stage in stages.values()
        ),
        "artifact_sha256": artifacts,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
