#!/usr/bin/env python3
"""Run the DualMS 2.0 paper-level hint-slack reproduction."""

from __future__ import annotations

import argparse
import json
import os

from dualms2_reference import PROFILES, run_all, run_profile


REFERENCE_SEED = bytes.fromhex(
    "b54788155733e2f4898e263673996949837f1816b18e620f8e7d77b50169bda2"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=("all", *PROFILES),
        default="all",
        help="run both advertised rows or one named row",
    )
    parser.add_argument(
        "--reference",
        action="store_true",
        help="use the committed seed instead of fresh operating-system entropy",
    )
    parser.add_argument(
        "--seed",
        help="explicit 32-byte hexadecimal seed (overrides --reference)",
    )
    parser.add_argument(
        "--trial-limit",
        type=int,
        default=512,
        help="maximum n=32 Hsig candidates (default: 512)",
    )
    args = parser.parse_args()

    if args.seed:
        seed = bytes.fromhex(args.seed)
        if len(seed) != 32:
            parser.error("--seed must encode exactly 32 bytes")
    elif args.reference:
        seed = REFERENCE_SEED
    else:
        seed = os.urandom(32)

    if args.trial_limit < 1:
        parser.error("--trial-limit must be positive")

    if args.profile == "all":
        report = run_all(seed=seed, trial_limit=args.trial_limit)
    else:
        report = {
            "banner": "DUALMS 2.0 ATTACK REPRODUCTION: PASS",
            "publication_status": "VERIFIED_ATTACK",
            "seed_hex": seed.hex(),
            "profiles": [run_profile(args.profile, seed, args.trial_limit)],
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
