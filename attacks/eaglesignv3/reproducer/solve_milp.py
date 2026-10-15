#!/usr/bin/env python3
"""Solve the sealed ternary inequality system using SciPy/HiGHS only."""

import argparse
import json
import math
import re
import sys
import time

import numpy as np
import scipy
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_array


TERM = re.compile(r" ([+-]) (\d+) x(\d+)")


def parse_lp(path: str):
    rows = []
    cols = []
    vals = []
    rhs = []
    in_subject = False
    with open(path, "r", encoding="ascii") as handle:
        for line in handle:
            if line.rstrip("\n") == "Subject To":
                in_subject = True
                continue
            if line.rstrip("\n") == "Bounds":
                break
            if not in_subject:
                continue
            left, right = line.rsplit(" <= ", 1)
            row = len(rhs)
            terms = TERM.findall(left)
            if len(terms) != 16:
                raise ValueError(f"row {row} has {len(terms)} terms, expected 16")
            for sign, magnitude, column in terms:
                col = int(column)
                if not 0 <= col < 1024:
                    raise ValueError(f"column out of range: {col}")
                rows.append(row)
                cols.append(col)
                vals.append(int(magnitude) * (1 if sign == "+" else -1))
            rhs.append(int(right))
    if not rhs:
        raise ValueError("LP contains no constraints")
    matrix = coo_array(
        (np.asarray(vals, dtype=np.float64),
         (np.asarray(rows, dtype=np.int32), np.asarray(cols, dtype=np.int32))),
        shape=(len(rhs), 1024),
    ).tocsr()
    return matrix, np.asarray(rhs, dtype=np.float64)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lp")
    parser.add_argument("solution")
    parser.add_argument("report")
    parser.add_argument("--time-limit", type=float, default=21600.0)
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args()
    if args.threads != 1:
        raise ValueError("the public reproducer is restricted to one thread")

    started = time.monotonic()
    matrix, rhs = parse_lp(args.lp)
    parsed = time.monotonic()
    constraints = LinearConstraint(
        matrix, np.full(rhs.shape, -np.inf, dtype=np.float64), rhs
    )
    result = milp(
        c=np.zeros(1024, dtype=np.float64),
        integrality=np.ones(1024, dtype=np.uint8),
        bounds=Bounds(
            np.full(1024, -1.0, dtype=np.float64),
            np.full(1024, 1.0, dtype=np.float64),
        ),
        constraints=constraints,
        options={
            "disp": True,
            "presolve": True,
            "time_limit": args.time_limit,
            "mip_rel_gap": 0.0,
            "threads": 1,
        },
    )
    solved = time.monotonic()
    if result.x is None or not result.success:
        raise RuntimeError(
            f"HiGHS failed: status={result.status} message={result.message!r}"
        )
    rounded = np.rint(result.x).astype(np.int64)
    if np.max(np.abs(result.x - rounded)) > 1e-7:
        raise RuntimeError("HiGHS returned a nonintegral solution")
    if np.any(rounded < -1) or np.any(rounded > 1):
        raise RuntimeError("HiGHS returned a value outside {-1,0,1}")
    lhs = matrix @ rounded
    max_violation = float(np.max(lhs - rhs))
    if max_violation > 1e-7:
        raise RuntimeError(f"solution violates constraints by {max_violation}")

    with open(args.solution, "w", encoding="ascii") as handle:
        handle.write("Optimal - objective value 0\n")
        for index, value in enumerate(rounded.tolist()):
            handle.write(f"{index:7d} x{index} {value:21d} 0\n")
    report = {
        "status": "PASS",
        "solver": "scipy.optimize.milp/HiGHS",
        "scipy_version": scipy.__version__,
        "numpy_version": np.__version__,
        "workers": 1,
        "variables": 1024,
        "integer_variables": 1024,
        "bounds": [-1, 1],
        "constraints": int(matrix.shape[0]),
        "nonzeros": int(matrix.nnz),
        "parse_seconds": parsed - started,
        "solve_seconds": solved - parsed,
        "wall_seconds": solved - started,
        "mip_node_count": int(result.mip_node_count),
        "mip_gap": float(result.mip_gap),
        "max_constraint_violation": max_violation,
    }
    with open(args.report, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("MILP SOLVER: PASS " + json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"MILP SOLVER: FAIL: {exc}", file=sys.stderr)
        raise

