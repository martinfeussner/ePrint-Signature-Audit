#!/usr/bin/env python3
"""Replay every retained Iceberg attack profile in this public package."""

import json

from reproduce import run


def main():
    evidence = run()
    checks = evidence["checks"]
    passed = all(checks.values()) and evidence["verdict"] == "PASS"
    output = {
        "all_rows_pass": passed,
        "result": "FULL_ICEBERG_RETAINED_PROFILE_REPLAY_PASS" if passed else "FAIL",
        "results": [
            {
                "all_expected_checks_pass": passed,
                "checks": checks,
                "parameter_row": "Iceberg t=2, n=4, mu=3, nu=2 over secp256k1",
                "profile_id": evidence["profile"],
            }
        ],
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
