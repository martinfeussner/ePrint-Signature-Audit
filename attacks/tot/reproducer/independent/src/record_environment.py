#!/usr/bin/env python3
"""Write a compact environment record without invoking extra workers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform


def cpu_model() -> str:
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def memory_total_kib() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1])
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    record = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_model": cpu_model(),
        "logical_cpu_count_host": os.cpu_count(),
        "experiment_workers": 1,
        "memory_total_kib_host": memory_total_kib(),
        "thread_limits": {
            name: os.environ.get(name)
            for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
        },
    }
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
