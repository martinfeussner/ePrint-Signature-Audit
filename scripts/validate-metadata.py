#!/usr/bin/env python3
"""Validate the public catalog and published-attack metadata.

This validator deliberately uses only the Python standard library. CI does not
rerun full cryptanalytic experiments; it checks exports, attack-to-catalog
links, pinned artifacts, and canonical reference results instead.
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import math
import pathlib
import re
import sys
from typing import Any
from urllib.parse import urlsplit


ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG_JSON = ROOT / "catalog" / "schemes.json"
CATALOG_CSV = ROOT / "catalog" / "schemes.csv"
README = ROOT / "README.md"
ATTACKS = ROOT / "attacks"

EPRINT = re.compile(r"^(?:19|20)[0-9]{2}/[1-9][0-9]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")

STATES = {
    "VERIFIED_ATTACK",
    "AUDITED_NO_PRACTICAL_ATTACK",
    "QUEUED",
    "KNOWN_ATTACK_EXCLUDED",
    "IMPRACTICAL",
    "DUPLICATE_ACTIVE_AUDIT",
}
ATTACK_STATES = {"VERIFIED_ATTACK"}
AUDITED_STATES = ATTACK_STATES | {"AUDITED_NO_PRACTICAL_ATTACK"}

CSV_FIELDS = [
    "scheme",
    "eprint_id",
    "eprint_version",
    "eprint_date",
    "family",
    "status",
    "attack_history_checked_at",
    "url",
]

CATALOG_REQUIRED_STRINGS = (
    "scheme",
    "eprint_id",
    "eprint_version",
    "eprint_date",
    "family",
    "status",
    "attack_history_checked_at",
    "url",
)

ATTACK_REQUIRED = {
    "scheme",
    "eprint_id",
    "eprint_version",
    "attack_history_checked_at",
    "prior_public_attack_located",
    "attack_result",
    "attack_technique",
    "layer",
    "affected_parameters",
    "full_scale",
    "runtime_seconds",
    "peak_ram_mb",
    "workers",
    "independent_reproduction",
    "reproducer_sha256",
    "independent_reproducer_sha256",
    "reference_output_sha256",
    "all_rows_reference_output_sha256",
    "attack_paper_authors",
    "attack_paper_affiliation",
    "attack_paper_contact",
    "attack_paper_sha256",
    "attack_paper_source_sha256",
    "attack_paper_makefile_sha256",
}

ATTACK_PAPER_AUTHOR = "Martin Feussner"
ATTACK_PAPER_AFFILIATION = "Selmer Center, University of Bergen"
ATTACK_PAPER_CONTACT = "martin.feussner@uib.no"
ATTACK_PAPER_AI_ENVIRONMENT = (
    "This audit used the OpenAI model Daybreak Blue at the ultra reasoning level."
)
ATTACK_PAPER_TEX_BYLINE = (
    r"\author{Martin Feussner\\" "\n"
    r"\small Selmer Center, University of Bergen\\" "\n"
    r"\small \texttt{martin.feussner@uib.no}}"
)
ATTACK_PAPER_PDF_AUTHOR_BYTES = ("\ufeff" + ATTACK_PAPER_AUTHOR).encode("utf-16-be")
ATTACK_PAPER_PDF_AUTHORS = (
    b"/Author<" + ATTACK_PAPER_PDF_AUTHOR_BYTES.hex().upper().encode("ascii") + b">",
    b"/Author("
    + b"".join(
        bytes([value])
        if 33 <= value <= 126 and value not in b"()\\"
        else f"\\{value:03o}".encode("ascii")
        for value in ATTACK_PAPER_PDF_AUTHOR_BYTES
    )
    + b")",
)


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains a duplicate member name."""


class Reporter:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def fail(self, message: str) -> None:
        self.errors.append(message)
        print(f"ERROR: {message}", file=sys.stderr)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def load_json(path: pathlib.Path, reporter: Reporter) -> Any | None:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError) as exc:
        reporter.fail(f"{path.relative_to(ROOT)}: {exc}")
        return None


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def parse_date(value: Any, label: str, reporter: Reporter) -> dt.date | None:
    if not isinstance(value, str):
        reporter.fail(f"{label} must be an ISO 8601 date string")
        return None
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError:
        reporter.fail(f"{label} has invalid date {value!r}")
        return None
    if parsed.isoformat() != value:
        reporter.fail(f"{label} must use YYYY-MM-DD form, got {value!r}")
        return None
    return parsed


def check_https_url(value: Any, label: str, reporter: Reporter) -> None:
    if not isinstance(value, str):
        reporter.fail(f"{label} must be a string")
        return
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        reporter.fail(f"{label} must be an absolute HTTPS URL")


def check_sha256(value: Any, label: str, reporter: Reporter) -> bool:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        reporter.fail(f"{label} must be a lowercase 64-digit SHA-256 hex digest")
        return False
    return True


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_catalog_entry(
    item: Any, index: int, reporter: Reporter
) -> tuple[str, str] | None:
    label = f"catalog/schemes.json entry {index}"
    if not isinstance(item, dict):
        reporter.fail(f"{label} must be an object")
        return None

    for field in CATALOG_REQUIRED_STRINGS:
        if not is_nonempty_string(item.get(field)):
            reporter.fail(f"{label}.{field} must be a nonempty string")

    eprint_id = item.get("eprint_id")
    if not isinstance(eprint_id, str) or EPRINT.fullmatch(eprint_id) is None:
        reporter.fail(f"{label}.eprint_id has invalid value {eprint_id!r}")

    status = item.get("status")
    if status not in STATES:
        reporter.fail(f"{label}.status has unknown value {status!r}")

    eprint_date = parse_date(item.get("eprint_date"), f"{label}.eprint_date", reporter)
    history_date = parse_date(
        item.get("attack_history_checked_at"),
        f"{label}.attack_history_checked_at",
        reporter,
    )
    if eprint_date and history_date and history_date < eprint_date:
        reporter.fail(f"{label}: attack-history check predates the ePrint publication")

    expected_url = f"https://eprint.iacr.org/{eprint_id}"
    if item.get("url") != expected_url:
        reporter.fail(f"{label}.url must be {expected_url!r}")

    aliases = item.get("aliases")
    if aliases is not None and (
        not isinstance(aliases, list)
        or not aliases
        or any(not is_nonempty_string(alias) for alias in aliases)
        or len(set(aliases)) != len(aliases)
    ):
        reporter.fail(f"{label}.aliases must be a nonempty list of unique strings")

    if isinstance(item.get("scheme"), str) and isinstance(eprint_id, str):
        return item["scheme"], eprint_id
    return None


def validate_catalog_csv(catalog: list[Any], reporter: Reporter) -> None:
    try:
        with CATALOG_CSV.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fields = reader.fieldnames
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        reporter.fail(f"catalog/schemes.csv: {exc}")
        return

    if fields != CSV_FIELDS:
        reporter.fail(
            "catalog/schemes.csv header must be exactly " + ",".join(CSV_FIELDS)
        )
        return
    if len(rows) != len(catalog):
        reporter.fail(
            f"catalog JSON/CSV row-count mismatch: {len(catalog)} JSON, {len(rows)} CSV"
        )

    for index, (item, row) in enumerate(zip(catalog, rows)):
        if not isinstance(item, dict):
            continue
        if None in row:
            reporter.fail(f"catalog/schemes.csv row {index + 2} has extra columns")
        for field in CSV_FIELDS:
            expected = item.get(field)
            if row.get(field) != expected:
                reporter.fail(
                    f"catalog JSON/CSV mismatch at row {index + 2}, field {field}: "
                    f"JSON={expected!r}, CSV={row.get(field)!r}"
                )


def validate_reference_output(
    attack_dir: pathlib.Path, attack: dict[str, Any], reporter: Reporter
) -> None:
    path = attack_dir / "reference-output.json"
    relative = path.relative_to(ROOT)
    reference = load_json(path, reporter)
    if reference is None:
        return
    if not isinstance(reference, dict):
        reporter.fail(f"{relative} must contain a JSON object")
        return

    canonical = json.dumps(reference, indent=2, sort_keys=True) + "\n"
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        reporter.fail(f"{relative}: {exc}")
        return
    if source != canonical:
        reporter.fail(
            f"{relative} must use canonical sorted, two-space-indented JSON with a newline"
        )

    if not is_nonempty_string(reference.get("result")):
        reporter.fail(f"{relative}.result must be a nonempty string")

    checks = reference.get("checks")
    if not isinstance(checks, dict) or not checks:
        reporter.fail(f"{relative}.checks must be a nonempty object")
    else:
        for name, passed in checks.items():
            if not is_nonempty_string(name) or not isinstance(passed, bool):
                reporter.fail(f"{relative}.checks must map names to booleans")
                break
            if not passed:
                reporter.fail(f"{relative}.checks.{name} is not true")

    digests = reference.get("digests")
    if not isinstance(digests, dict) or not digests:
        reporter.fail(f"{relative}.digests must be a nonempty object")
    else:
        for name, value in digests.items():
            if not isinstance(name, str) or not name.endswith("_sha256"):
                reporter.fail(f"{relative}.digests has non-SHA-256 key {name!r}")
            else:
                check_sha256(value, f"{relative}.digests.{name}", reporter)

    reference_attack = reference.get("attack")
    if isinstance(reference_attack, dict) and "signing_queries" in attack:
        if reference_attack.get("signing_queries") != attack["signing_queries"]:
            reporter.fail(
                f"{relative}.attack.signing_queries disagrees with metadata.json"
            )

    environment = reference.get("environment")
    if isinstance(environment, dict) and "workers" in environment:
        if environment["workers"] != attack.get("workers"):
            reporter.fail(f"{relative}.environment.workers disagrees with metadata.json")


def validate_all_rows_output(attack_dir: pathlib.Path, reporter: Reporter) -> None:
    path = attack_dir / "all-rows-reference-output.json"
    relative = path.relative_to(ROOT)
    reference = load_json(path, reporter)
    if reference is None:
        return
    if not isinstance(reference, dict):
        reporter.fail(f"{relative} must contain a JSON object")
        return

    canonical = json.dumps(reference, indent=2, sort_keys=True) + "\n"
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        reporter.fail(f"{relative}: {exc}")
        return
    if source != canonical:
        reporter.fail(
            f"{relative} must use canonical sorted, two-space-indented JSON with a newline"
        )
    if reference.get("all_rows_pass") is not True:
        reporter.fail(f"{relative}.all_rows_pass must be true")
    results = reference.get("results")
    if not isinstance(results, list) or not results:
        reporter.fail(f"{relative}.results must be a nonempty list")
        return
    rows: set[str] = set()
    for index, result in enumerate(results):
        label = f"{relative}.results[{index}]"
        if not isinstance(result, dict):
            reporter.fail(f"{label} must be an object")
            continue
        row = result.get("parameter_row")
        if not is_nonempty_string(row):
            reporter.fail(f"{label}.parameter_row must be a nonempty string")
        elif row in rows:
            reporter.fail(f"{relative} repeats parameter row {row!r}")
        else:
            rows.add(row)
        if result.get("all_expected_checks_pass") is not True:
            reporter.fail(f"{label}.all_expected_checks_pass must be true")


def validate_attack(
    attack_dir: pathlib.Path,
    catalog_by_id: dict[str, list[dict[str, Any]]],
    reporter: Reporter,
) -> tuple[str | None, dict[str, Any] | None]:
    relative_dir = attack_dir.relative_to(ROOT)
    required_files = (
        "README.md",
        "metadata.json",
        "reproduce.py",
        "reproduce-all-rows.py",
        "reference-output.json",
        "all-rows-reference-output.json",
        "paper/attack.tex",
        "paper/attack.pdf",
        "paper/Makefile",
    )
    for name in required_files:
        path = attack_dir / name
        if not path.is_file() or path.is_symlink():
            reporter.fail(f"{relative_dir}/{name} must be a regular file")

    metadata_path = attack_dir / "metadata.json"
    attack = load_json(metadata_path, reporter)
    if attack is None:
        return None, None
    if not isinstance(attack, dict):
        reporter.fail(f"{relative_dir}/metadata.json must contain a JSON object")
        return None, None

    missing = sorted(ATTACK_REQUIRED - attack.keys())
    if missing:
        reporter.fail(f"{relative_dir}/metadata.json: missing {', '.join(missing)}")

    label = f"{relative_dir}/metadata.json"
    for field in (
        "scheme",
        "eprint_id",
        "eprint_version",
        "attack_history_checked_at",
        "attack_result",
        "attack_technique",
        "layer",
    ):
        if not is_nonempty_string(attack.get(field)):
            reporter.fail(f"{label}.{field} must be a nonempty string")

    eprint_id = attack.get("eprint_id")
    if not isinstance(eprint_id, str) or EPRINT.fullmatch(eprint_id) is None:
        reporter.fail(f"{label}.eprint_id has invalid value {eprint_id!r}")
        eprint_id = None

    history_date = parse_date(
        attack.get("attack_history_checked_at"),
        f"{label}.attack_history_checked_at",
        reporter,
    )
    eprint_date = None
    if "eprint_date" in attack:
        eprint_date = parse_date(attack["eprint_date"], f"{label}.eprint_date", reporter)
    if eprint_date and history_date and history_date < eprint_date:
        reporter.fail(f"{label}: attack-history check predates the ePrint publication")

    if attack.get("prior_public_attack_located") is not False:
        reporter.fail(f"{label}.prior_public_attack_located must be false")
    if attack.get("layer") != "design":
        reporter.fail(f"{label}.layer must be 'design'")
    if attack.get("full_scale") is not True:
        reporter.fail(f"{label}.full_scale must be true")
    if attack.get("independent_reproduction") is not True:
        reporter.fail(f"{label}.independent_reproduction must be true")
    if "technique_originality_claimed" in attack and not isinstance(
        attack["technique_originality_claimed"], bool
    ):
        reporter.fail(f"{label}.technique_originality_claimed must be a boolean")

    affected = attack.get("affected_parameters")
    if (
        not isinstance(affected, list)
        or not affected
        or any(not is_nonempty_string(value) for value in affected)
        or len(set(affected)) != len(affected)
    ):
        reporter.fail(
            f"{label}.affected_parameters must be a nonempty list of unique strings"
        )

    paper_authors = attack.get("attack_paper_authors")
    if paper_authors != [ATTACK_PAPER_AUTHOR]:
        reporter.fail(
            f"{label}.attack_paper_authors must be exactly [{ATTACK_PAPER_AUTHOR!r}]"
        )
    if attack.get("attack_paper_affiliation") != ATTACK_PAPER_AFFILIATION:
        reporter.fail(
            f"{label}.attack_paper_affiliation must be {ATTACK_PAPER_AFFILIATION!r}"
        )
    if attack.get("attack_paper_contact") != ATTACK_PAPER_CONTACT:
        reporter.fail(
            f"{label}.attack_paper_contact must be {ATTACK_PAPER_CONTACT!r}"
        )

    for field in ("runtime_seconds", "peak_ram_mb"):
        value = attack.get(field)
        if not is_number(value) or value < 0:
            reporter.fail(f"{label}.{field} must be a finite nonnegative number")
    workers = attack.get("workers")
    if not is_integer(workers) or workers < 1:
        reporter.fail(f"{label}.workers must be an integer of at least 1")

    for field in ("signing_queries", "trials", "successes"):
        if field in attack and (not is_integer(attack[field]) or attack[field] < 0):
            reporter.fail(f"{label}.{field} must be a nonnegative integer")
    if (
        is_integer(attack.get("successes"))
        and is_integer(attack.get("trials"))
        and attack["successes"] > attack["trials"]
    ):
        reporter.fail(f"{label}.successes cannot exceed trials")
    if "forge_seconds" in attack and (
        not is_number(attack["forge_seconds"]) or attack["forge_seconds"] < 0
    ):
        reporter.fail(f"{label}.forge_seconds must be a finite nonnegative number")

    for field, value in attack.items():
        if field.endswith("_sha256"):
            check_sha256(value, f"{label}.{field}", reporter)
    if "scheme_source_commit" in attack and (
        not isinstance(attack["scheme_source_commit"], str)
        or GIT_COMMIT.fullmatch(attack["scheme_source_commit"]) is None
    ):
        reporter.fail(f"{label}.scheme_source_commit must be a full lowercase commit ID")
    for field in ("paper_url", "source_url"):
        if field in attack:
            check_https_url(attack[field], f"{label}.{field}", reporter)
    if isinstance(eprint_id, str) and "paper_url" in attack:
        expected_paper_url = f"https://eprint.iacr.org/{eprint_id}"
        if attack["paper_url"] != expected_paper_url:
            reporter.fail(f"{label}.paper_url must be {expected_paper_url!r}")

    pinned_files = {
        "reproducer_sha256": attack_dir / "reproduce.py",
        "independent_reproducer_sha256": attack_dir / "reproduce-all-rows.py",
        "reference_output_sha256": attack_dir / "reference-output.json",
        "all_rows_reference_output_sha256": attack_dir / "all-rows-reference-output.json",
        "attack_paper_sha256": attack_dir / "paper" / "attack.pdf",
        "attack_paper_source_sha256": attack_dir / "paper" / "attack.tex",
        "attack_paper_makefile_sha256": attack_dir / "paper" / "Makefile",
    }

    attack_tex = attack_dir / "paper" / "attack.tex"
    if attack_tex.is_file():
        try:
            tex_source = attack_tex.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            reporter.fail(f"{attack_tex.relative_to(ROOT)}: {exc}")
        else:
            pdf_author_marker = f"pdfauthor={{{ATTACK_PAPER_AUTHOR}}}"
            if tex_source.count(pdf_author_marker) != 1 or len(
                re.findall(r"\bpdfauthor\s*=", tex_source)
            ) != 1:
                reporter.fail(
                    f"{attack_tex.relative_to(ROOT)} must contain exactly one "
                    f"{pdf_author_marker!r} setting"
                )
            if tex_source.count(ATTACK_PAPER_TEX_BYLINE) != 1 or len(
                re.findall(r"\\author\s*\{", tex_source)
            ) != 1:
                reporter.fail(
                    f"{attack_tex.relative_to(ROOT)} must contain exactly the standard "
                    "Martin Feussner author block once"
                )
            if tex_source.count(ATTACK_PAPER_AI_ENVIRONMENT) != 1:
                reporter.fail(
                    f"{attack_tex.relative_to(ROOT)} must contain the exact "
                    "Daybreak Blue model and ultra-reasoning disclosure once"
                )

    attack_pdf = attack_dir / "paper" / "attack.pdf"
    if attack_pdf.is_file():
        try:
            pdf_bytes = attack_pdf.read_bytes()
        except OSError as exc:
            reporter.fail(f"{attack_pdf.relative_to(ROOT)}: {exc}")
        else:
            encoded_author_count = sum(
                pdf_bytes.count(marker) for marker in ATTACK_PAPER_PDF_AUTHORS
            )
            if pdf_bytes.count(b"/Author") != 1 or encoded_author_count != 1:
                reporter.fail(
                    f"{attack_pdf.relative_to(ROOT)} must contain exactly one PDF "
                    f"Author metadata value for {ATTACK_PAPER_AUTHOR!r}"
                )
    for field, path in pinned_files.items():
        expected = attack.get(field)
        if path.is_file() and check_sha256(expected, f"{label}.{field}", reporter):
            actual = sha256_file(path)
            if actual != expected:
                reporter.fail(
                    f"{label}.{field} is {expected}, but {path.name} hashes to {actual}"
                )

    if eprint_id is not None:
        catalog_candidates = catalog_by_id.get(eprint_id, [])
        if not catalog_candidates:
            reporter.fail(f"{label}: ePrint {eprint_id} is absent from the catalog")
        else:
            matching_candidates = [
                item
                for item in catalog_candidates
                if item.get("scheme") == attack.get("scheme")
            ]
            if len(matching_candidates) != 1:
                reporter.fail(
                    f"{label}: ePrint {eprint_id} must have exactly one catalog "
                    f"entry for scheme {attack.get('scheme')!r}"
                )
            else:
                catalog_item = matching_candidates[0]
                for field in ("scheme", "eprint_version", "eprint_date", "family"):
                    if field in attack and attack[field] != catalog_item.get(field):
                        reporter.fail(f"{label}.{field} disagrees with the catalog")
                status = catalog_item.get("status")
                if status not in ATTACK_STATES:
                    reporter.fail(
                        f"{label}: catalog status for {eprint_id} must be one of "
                        f"{sorted(ATTACK_STATES)}, got {status!r}"
                    )

    if (attack_dir / "reference-output.json").is_file():
        validate_reference_output(attack_dir, attack, reporter)
    if (attack_dir / "all-rows-reference-output.json").is_file():
        validate_all_rows_output(attack_dir, reporter)
    return eprint_id, attack


def parse_dashboard(reporter: Reporter) -> dict[str, int]:
    try:
        contents = README.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        reporter.fail(f"README.md: {exc}")
        return {}
    lines = contents.splitlines()
    try:
        start = lines.index("## Dashboard") + 1
    except ValueError:
        reporter.fail("README.md is missing the Dashboard section")
        return {}
    end = next(
        (index for index in range(start, len(lines)) if lines[index].startswith("## ")),
        len(lines),
    )

    metrics: dict[str, int] = {}
    row = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([0-9]+)\s*\|\s*$")
    for line in lines[start:end]:
        match = row.fullmatch(line)
        if not match:
            continue
        name = " ".join(match.group(1).strip().lower().split())
        if name in metrics:
            reporter.fail(f"README.md dashboard repeats metric {name!r}")
        metrics[name] = int(match.group(2))
    return metrics


def validate_dashboard(
    catalog: list[dict[str, Any]],
    attacks: list[dict[str, Any]],
    reporter: Reporter,
) -> None:
    dashboard = parse_dashboard(reporter)
    attack_count = sum(item.get("status") in ATTACK_STATES for item in catalog)
    expected = {
        "schemes identified": len(catalog),
        "known attacks excluded": sum(
            item.get("status") == "KNOWN_ATTACK_EXCLUDED" for item in catalog
        ),
        "schemes audited": sum(item.get("status") in AUDITED_STATES for item in catalog),
        "no practical attack found": sum(
            item.get("status") == "AUDITED_NO_PRACTICAL_ATTACK" for item in catalog
        ),
        "practical design attacks": attack_count,
        "verified practical design attacks": sum(
            item.get("status") == "VERIFIED_ATTACK" for item in catalog
        ),
        "independently reproduced attacks": sum(
            item.get("independent_reproduction") is True for item in attacks
        ),
    }
    required = {
        "schemes identified",
        "known attacks excluded",
        "schemes audited",
        "no practical attack found",
        "independently reproduced attacks",
    }
    missing = sorted(required - dashboard.keys())
    if missing:
        reporter.fail(f"README.md dashboard is missing {', '.join(missing)}")
    if not (
        {"practical design attacks", "verified practical design attacks"}
        & dashboard.keys()
    ):
        reporter.fail("README.md dashboard is missing the practical-design-attack count")
    for name, actual in dashboard.items():
        if name in expected and actual != expected[name]:
            reporter.fail(
                f"README.md dashboard {name!r} is {actual}, expected {expected[name]}"
            )


def main() -> int:
    reporter = Reporter()
    catalog_value = load_json(CATALOG_JSON, reporter)
    if catalog_value is None:
        return 1
    if not isinstance(catalog_value, list):
        reporter.fail("catalog/schemes.json must contain a JSON array")
        return 1

    catalog: list[dict[str, Any]] = []
    seen_schemes: set[str] = set()
    for index, item in enumerate(catalog_value):
        identity = validate_catalog_entry(item, index, reporter)
        if isinstance(item, dict):
            catalog.append(item)
        if identity is None:
            continue
        scheme, eprint_id = identity
        if scheme in seen_schemes:
            reporter.fail(f"catalog/schemes.json has duplicate scheme {scheme!r}")
        seen_schemes.add(scheme)

    validate_catalog_csv(catalog_value, reporter)
    catalog_by_id: dict[str, list[dict[str, Any]]] = {}
    for item in catalog:
        eprint_id = item.get("eprint_id")
        if isinstance(eprint_id, str):
            catalog_by_id.setdefault(eprint_id, []).append(item)

    attack_records: list[dict[str, Any]] = []
    attacks_by_identity: dict[tuple[str, str], pathlib.Path] = {}
    if not ATTACKS.is_dir():
        reporter.fail("attacks/ directory is missing")
    else:
        for attack_dir in sorted(path for path in ATTACKS.iterdir() if path.is_dir()):
            eprint_id, attack = validate_attack(attack_dir, catalog_by_id, reporter)
            if attack is not None:
                attack_records.append(attack)
            if eprint_id is not None and attack is not None:
                identity = (eprint_id, str(attack.get("scheme")))
                if identity in attacks_by_identity:
                    reporter.fail(
                        f"multiple attack directories claim {identity!r}: "
                        f"{attacks_by_identity[identity].name!r} and {attack_dir.name!r}"
                    )
                attacks_by_identity[identity] = attack_dir

    for item in catalog:
        if (
            item.get("status") in ATTACK_STATES
            and (str(item.get("eprint_id")), str(item.get("scheme")))
            not in attacks_by_identity
        ):
            reporter.fail(
                f"catalog entry {item.get('scheme')!r} has attack status but no attack directory"
            )

    validate_dashboard(catalog, attack_records, reporter)

    if reporter.errors:
        print(
            f"Metadata validation failed with {len(reporter.errors)} error(s).",
            file=sys.stderr,
        )
        return 1
    print(
        f"Metadata validation passed: {len(catalog)} catalog entries, "
        f"{len(attack_records)} published attack(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
