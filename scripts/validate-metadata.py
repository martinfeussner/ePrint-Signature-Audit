#!/usr/bin/env python3
"""Validate the public catalog and published-attack metadata.

CI does not rerun full cryptanalytic experiments. This validator checks
exports, attack-to-catalog links, pinned artifacts, canonical reference
results, and the rendered README structure using a pinned Markdown parser.
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
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

try:
    from markdown_it import MarkdownIt, __version__ as MARKDOWN_IT_VERSION
    from mdurl import __version__ as MDURL_VERSION
except ModuleNotFoundError:  # reported cleanly by validate_readme_rendered_structure
    MarkdownIt = None  # type: ignore[assignment,misc]
    MARKDOWN_IT_VERSION = None
    MDURL_VERSION = None


ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG_JSON = ROOT / "catalog" / "schemes.json"
CATALOG_CSV = ROOT / "catalog" / "schemes.csv"
README = ROOT / "README.md"
ATTACKS = ROOT / "attacks"

README_HEADINGS = (
    "# ePrint Signature Audit",
    "## Dashboard",
    "## Practical design attacks",
    "## Known attack exclusions",
    "## Completed audits without a practical attack",
    "### Audit summaries",
    "## Verified attack summaries",
)
README_DASHBOARD_METRICS = (
    "Schemes identified",
    "Known attacks excluded",
    "Schemes audited",
    "No practical attack found",
    "Verified and independently reproduced practical design attacks",
)
README_ATTACK_ORDER = (
    "d-james",
    "miraidon-s",
    "bittersweet",
    "poulakis-rolland-v2",
    "yagisawa-order-four",
    "random-split-stgen",
    "glyph",
    "tot",
    "full-distance-syndrome-decoding",
    "higher-bit-approx-isis",
    "ssd",
    "hppk-ds",
    "jevil",
    "eaglesignv3",
    "dualms-2",
    "fabs",
)
README_EXCLUSION_ORDER = (
    "ATLAS",
    "CMSS",
    "Ye temporary-key lattice signature",
)
README_AUDIT_ORDER = (
    "ECLIPSE",
    "ASTRA-Sign",
    "miniMEDS",
    "Lithium",
    "UFOs",
    "FALCON++",
    "SOLMAE",
    "HFE-IP-minus",
    "Plover",
    "KuMQuat",
    "MandaRain",
    "SPECK",
    "Loquat",
    "BPORS-C+BFP",
    "CAPSS-Poseidon-3 Default",
    "NTRU+Sign-972",
    "NIC signature",
    "SPHINCS-PE",
    "MR-DSS",
    "CUTS",
    "K-LMS",
    "SigRPO-LDR",
    "ANSA-IBS",
    "Round-Optimal Pairing-Free Blind Signatures",
    "edaBitE Blind Signature",
    "ModFalcon",
    "Lattice SEP",
    "Aerie",
    "Robust ECDSA Threshold Signing at Scale",
    "Concurrently Secure Compact Blind Signatures from Module-SIS",
    "FALCON with message recovery, a specification",
    "smklhs: Succinct Multi key Linearly Homomorphic Signatures for Certified Statistics",
    "BRaccoon: Concurrently Secure Blind Lattice Signatures from Raccoon",
)
README_LABEL_OVERRIDES = {
    "Yagisawa quaternion signature": {"Yagisawa's quaternion signature"},
    "Random-split St-Gen signature": {"Random-split St-Gen"},
    "Full-Distance Syndrome Decoding signature": {
        "Full-Distance Syndrome Decoding"
    },
    "Signature from Syndrome Decoding (SSD), standard mode": {"SSD"},
    "Ye temporary-key lattice signature": {
        "Ye's temporary-key lattice signature"
    },
    "Loquat": {"Loquat / Loquat*", "Loquat and Loquat*"},
    "FALCON with message recovery, a specification": {
        "FALCON with message recovery",
        "FALCON with message recovery (FALCON-MRM)",
    },
    "FABS: Fast Attribute-Based Signatures": {"FABS"},
}
README_ATTACK_TABLE_HEADER = (
    "Scheme",
    "ePrint",
    "Family",
    "Result",
    "Technique",
    "Parameters",
    "Cost",
    "Status",
)
README_AUDIT_TABLE_HEADER = ("Scheme", "ePrint", "Scope", "Disposition")
README_FOOTER = (
    "See [methodology](METHODOLOGY.md), [attack-history methodology]"
    "(docs/attack-history-methodology.md), [publication policy]"
    "(docs/publication-policy.md), [reproducibility](REPRODUCIBILITY.md), "
    "and [AI disclosure](AI_DISCLOSURE.md)."
)

EPRINT = re.compile(r"^(?:19|20)[0-9]{2}/[0-9]+$")
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


def normalized_eprint(value: str) -> str:
    year, number = value.split("/", 1)
    return f"{year}/{int(number)}"


def readme_eprint_matches(displayed: str, catalog_value: str) -> bool:
    year, number = catalog_value.split("/", 1)
    canonical_archive_form = f"{year}/{int(number):03d}"
    return displayed in {catalog_value, canonical_archive_form}


def accepted_readme_labels(item: dict[str, Any]) -> set[str]:
    scheme = str(item.get("scheme", "")).strip()
    aliases = item.get("aliases")
    aliases = (
        [str(alias).strip() for alias in aliases if str(alias).strip()]
        if isinstance(aliases, list)
        else []
    )
    labels = {scheme, *aliases}
    labels.update(README_LABEL_OVERRIDES.get(scheme, set()))
    return labels


def readme_label_matches(label: str, accepted: set[str]) -> bool:
    return label in accepted


def parsed_attack_links(markdown: str) -> tuple[tuple[str, str] | None, list[str]]:
    """Return the leading attack link and every attack link in one paragraph."""
    if MarkdownIt is None:
        return None, []
    tokens = MarkdownIt("commonmark", {"html": True}).enable("table").parse(markdown)
    inline = next((token for token in tokens if token.type == "inline"), None)
    children = inline.children if inline is not None and inline.children else []
    valid_links: list[tuple[int, str, str]] = []
    attack_directories: list[str] = []
    active_start: int | None = None
    active_href: str | None = None
    label_parts: list[str] = []
    label_types: list[str] = []
    active_valid = False
    for index, child in enumerate(children):
        if child.type == "link_open":
            active_start = index
            active_href = child.attrGet("href")
            label_parts = []
            label_types = []
            active_valid = child.attrs == {"href": active_href}
        elif child.type == "link_close" and active_start is not None:
            match = re.fullmatch(r"attacks/([a-z0-9-]+)/", active_href or "")
            if match is not None:
                directory = match.group(1)
                attack_directories.append(directory)
                label = " ".join("".join(label_parts).split())
                if (
                    active_valid
                    and label_types
                    and label_types[0] == "text"
                    and label_types[-1] == "text"
                ):
                    valid_links.append((active_start, label, directory))
            active_start = None
            active_href = None
            label_parts = []
            label_types = []
            active_valid = False
        elif active_start is not None:
            label_types.append(child.type)
            if child.type == "softbreak":
                label_parts.append(" ")
            elif child.type == "text":
                label_parts.append(child.content)
            else:
                active_valid = False
    leading = (
        (valid_links[0][1], valid_links[0][2])
        if valid_links and valid_links[0][0] == 0
        else None
    )
    return leading, attack_directories


def require_markdown_parser(reporter: Reporter) -> bool:
    if MarkdownIt is None:
        reporter.fail(
            "README.md validation requires markdown-it-py==3.0.0 and "
            "mdurl==0.1.2; install the pinned validation dependencies"
        )
        return False
    if MARKDOWN_IT_VERSION != "3.0.0" or MDURL_VERSION != "0.1.2":
        reporter.fail(
            "README.md validation requires markdown-it-py==3.0.0 and "
            f"mdurl==0.1.2, got {MARKDOWN_IT_VERSION!r} and {MDURL_VERSION!r}"
        )
        return False
    return True


def validate_readme_rendered_structure(
    contents: str,
    negative_count: int,
    attack_count: int,
    exclusion_count: int,
    reporter: Reporter,
) -> None:
    """Check the rendered CommonMark/GFM block tree, not source heuristics."""
    if not require_markdown_parser(reporter):
        return

    environment: dict[str, Any] = {}
    parser = MarkdownIt("commonmark", {"html": True}).enable("table")
    tokens = parser.parse(contents, environment)
    if environment.get("references"):
        reporter.fail("README.md must not contain hidden link-reference definitions")

    if any(
        child.type == "html_inline"
        for token in tokens
        if token.type == "inline"
        for child in token.children or []
    ):
        reporter.fail("README.md prose must not contain active raw HTML")
    if any(
        child.type == "hardbreak"
        for token in tokens
        if token.type == "inline"
        for child in token.children or []
    ):
        reporter.fail(
            "README.md prose must use ordinary soft line wrapping, not rendered "
            "hard breaks"
        )

    blocks: list[tuple[str, str, str]] = []
    for index, token in enumerate(tokens):
        if token.level != 0 or token.nesting == -1:
            continue
        content = ""
        if token.type == "heading_open" and index + 1 < len(tokens):
            content = tokens[index + 1].content
        blocks.append((token.type, token.tag, content))

    heading = lambda tag, content: ("heading_open", tag, content)
    paragraph = ("paragraph_open", "p", "")
    table = ("table_open", "table", "")
    bullet_list = ("bullet_list_open", "ul", "")
    expected = [
        heading("h1", README_HEADINGS[0][2:]),
        paragraph,
        paragraph,
        heading("h2", README_HEADINGS[1][3:]),
        table,
        heading("h2", README_HEADINGS[2][3:]),
        table,
        heading("h2", README_HEADINGS[3][3:]),
        paragraph,
        bullet_list,
        heading("h2", README_HEADINGS[4][3:]),
        table,
        heading("h3", README_HEADINGS[5][4:]),
        *([paragraph] * negative_count),
        heading("h2", README_HEADINGS[6][3:]),
        *([paragraph] * (attack_count + 1)),
    ]
    if blocks != expected:
        reporter.fail(
            "README.md rendered block structure must preserve the established "
            "headings, prose blocks, tables, exclusion list, summaries, and footer"
        )

    try:
        list_start = next(
            index
            for index, token in enumerate(tokens)
            if token.level == 0 and token.type == "bullet_list_open"
        )
        list_end = next(
            index
            for index in range(list_start + 1, len(tokens))
            if tokens[index].level == 0 and tokens[index].type == "bullet_list_close"
        )
    except StopIteration:
        return
    observed_list_shape = [
        (token.type, token.level, token.hidden)
        for token in tokens[list_start : list_end + 1]
    ]
    item_shape = [
        ("list_item_open", 1, False),
        ("paragraph_open", 2, True),
        ("inline", 3, False),
        ("paragraph_close", 2, True),
        ("list_item_close", 1, False),
    ]
    expected_list_shape = [
        ("bullet_list_open", 0, False),
        *(item_shape * exclusion_count),
        ("bullet_list_close", 0, False),
    ]
    if observed_list_shape != expected_list_shape:
        reporter.fail(
            "README.md Known attack exclusions must render as one tight, unnested "
            "bullet list with one prose paragraph per exclusion"
        )


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


def validate_readme_layout(
    catalog: list[dict[str, Any]],
    attacks_by_identity: dict[tuple[str, str], pathlib.Path],
    reporter: Reporter,
) -> None:
    """Freeze the README's dashboard layout while allowing row content to evolve."""
    try:
        contents = README.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        reporter.fail(f"README.md: {exc}")
        return

    lines = contents.splitlines()
    if not lines or lines[0] != README_HEADINGS[0]:
        reporter.fail("README.md must begin with the exact established H1")
    validate_readme_rendered_structure(
        contents,
        sum(item.get("status") == "AUDITED_NO_PRACTICAL_ATTACK" for item in catalog),
        len(attacks_by_identity),
        sum(item.get("status") == "KNOWN_ATTACK_EXCLUDED" for item in catalog),
        reporter,
    )

    headings = [
        line for line in lines if re.match(r"^ {0,3}#{1,6}(?:[ \t]+|$)", line)
    ]
    if headings != list(README_HEADINGS):
        reporter.fail(
            "README.md headings must preserve the exact established order: "
            f"found {headings!r}, expected {list(README_HEADINGS)!r}"
        )
        return

    positions = {heading: lines.index(heading) for heading in README_HEADINGS}

    def section(start: str, end: str | None) -> list[str]:
        first = positions[start] + 1
        last = positions[end] if end is not None else len(lines)
        block = lines[first:last]
        while block and not block[0].strip():
            block.pop(0)
        while block and not block[-1].strip():
            block.pop()
        return block

    def paragraph_blocks(block: list[str]) -> list[str]:
        return [
            part.strip()
            for part in re.split(r"\n[ \t]*\n", "\n".join(block).strip())
            if part.strip()
        ]

    def table_cells(
        block: list[str],
        section_name: str,
        expected_header: tuple[str, ...],
    ) -> list[list[str]]:
        expected_header_line = "| " + " | ".join(expected_header) + " |"
        expected_separator = "|" + "|".join(
            "---:" if name == "Count" else "---" for name in expected_header
        ) + "|"
        if len(block) < 2 or block[:2] != [expected_header_line, expected_separator]:
            reporter.fail(
                f"README.md {section_name} table must retain header "
                f"{expected_header_line!r} and separator {expected_separator!r}"
            )
            return []
        rows: list[list[str]] = []
        for index, line in enumerate(block[2:], 1):
            if not line.startswith("|") or not line.endswith("|"):
                reporter.fail(
                    f"README.md {section_name} row {index} must remain a table row"
                )
                continue
            cells: list[str] = []
            current: list[str] = []
            inner = line[1:-1]
            cursor = 0
            while cursor < len(inner):
                character = inner[cursor]
                if character == "\\" and cursor + 1 < len(inner):
                    current.extend((character, inner[cursor + 1]))
                    cursor += 2
                    continue
                if character == "|":
                    cells.append("".join(current).strip())
                    current = []
                else:
                    current.append(character)
                cursor += 1
            cells.append("".join(current).strip())
            if len(cells) != len(expected_header):
                reporter.fail(
                    f"README.md {section_name} row {index} has {len(cells)} cells; "
                    f"expected {len(expected_header)}"
                )
                continue
            if any(not cell for cell in cells):
                reporter.fail(
                    f"README.md {section_name} row {index} contains an empty cell"
                )
            rows.append(cells)
        return rows

    intro = section(README_HEADINGS[0], README_HEADINGS[1])
    intro_paragraphs = paragraph_blocks(intro)
    if len(intro_paragraphs) != 2:
        reporter.fail(
            "README.md introduction must remain exactly two compact prose paragraphs"
        )
    dashboard_rows = table_cells(
        section(README_HEADINGS[1], README_HEADINGS[2]),
        "Dashboard",
        ("Metric", "Count"),
    )
    dashboard_names = [row[0] for row in dashboard_rows]
    if dashboard_names != list(README_DASHBOARD_METRICS):
        reporter.fail(
            "README.md Dashboard metrics must preserve their established order: "
            f"found {dashboard_names!r}, expected {list(README_DASHBOARD_METRICS)!r}"
        )
    for index, row in enumerate(dashboard_rows, 1):
        if re.fullmatch(r"[0-9]+", row[1]) is None:
            reporter.fail(f"README.md Dashboard row {index} count must be an integer")

    attack_rows = table_cells(
        section(README_HEADINGS[2], README_HEADINGS[3]),
        "Practical design attacks",
        README_ATTACK_TABLE_HEADER,
    )
    attack_link = re.compile(r"^\[[^\]\n]+\]\(attacks/([a-z0-9-]+)/\)$")
    expected_attack_ids = {
        path.name: identity[0]
        for identity, path in attacks_by_identity.items()
    }
    attack_catalog_by_dir = {
        path.name: next(
            (
                item
                for item in catalog
                if str(item.get("eprint_id")) == identity[0]
                and str(item.get("scheme")) == identity[1]
            ),
            None,
        )
        for identity, path in attacks_by_identity.items()
    }
    observed_attack_dirs: list[str] = []
    for index, row in enumerate(attack_rows, 1):
        match = attack_link.fullmatch(row[0])
        if match is None:
            reporter.fail(
                f"README.md Practical design attacks row {index} must begin with "
                "one linked attack directory"
            )
            continue
        directory = match.group(1)
        observed_attack_dirs.append(directory)
        display_label = row[0][1 : row[0].index("](")]
        catalog_item = attack_catalog_by_dir.get(directory)
        if catalog_item is None or not readme_label_matches(
            display_label, accepted_readme_labels(catalog_item)
        ):
            reporter.fail(
                f"README.md Practical design attacks row {index} label "
                f"{display_label!r} does not match attack {directory!r}"
            )
        eprint_match = re.match(r"^([0-9]{4}/[0-9]+)\b", row[1])
        expected_id = expected_attack_ids.get(directory)
        if (
            eprint_match is None
            or expected_id is None
            or not readme_eprint_matches(eprint_match.group(1), expected_id)
        ):
            reporter.fail(
                f"README.md Practical design attacks row {index} for {directory!r} "
                f"does not match catalog ePrint {expected_id!r}"
            )
        if row[7] != "Verified; independently AI-reproduced":
            reporter.fail(
                f"README.md Practical design attacks row {index} must retain the "
                "verified and independently reproduced status"
            )
    if len(observed_attack_dirs) != len(set(observed_attack_dirs)):
        reporter.fail("README.md Practical design attacks table repeats an attack directory")
    if set(observed_attack_dirs) != set(expected_attack_ids):
        reporter.fail(
            "README.md Practical design attacks table must contain every attack "
            f"directory exactly once: found {sorted(set(observed_attack_dirs))}, "
            f"expected {sorted(expected_attack_ids)}"
        )
    if observed_attack_dirs[: len(README_ATTACK_ORDER)] != list(README_ATTACK_ORDER):
        reporter.fail(
            "README.md Practical design attacks must preserve the established row "
            "order and append future attacks at the end"
        )

    verified_section = section(README_HEADINGS[6], None)
    if verified_section and verified_section[-1] == README_FOOTER:
        verified_section = verified_section[:-1]
        while verified_section and not verified_section[-1].strip():
            verified_section.pop()
    verified_blocks = paragraph_blocks(verified_section)
    verified_summary_dirs: list[str] = []
    for index, block in enumerate(verified_blocks, 1):
        lead, _ = parsed_attack_links(block)
        if lead is None:
            continue
        display_label, directory = lead
        verified_summary_dirs.append(directory)
        catalog_item = attack_catalog_by_dir.get(directory)
        if catalog_item is None or not readme_label_matches(
            display_label, accepted_readme_labels(catalog_item)
        ):
            reporter.fail(
                f"README.md Verified attack summary {index} label "
                f"{display_label!r} does not match attack {directory!r}"
            )
    if observed_attack_dirs != verified_summary_dirs:
        reporter.fail(
            "README.md Practical design attacks rows and Verified attack summaries "
            "must retain the same identity order"
        )

    exclusion_block = section(README_HEADINGS[3], README_HEADINGS[4])
    first_bullet = next(
        (index for index, line in enumerate(exclusion_block) if line.startswith("- ")),
        None,
    )
    if first_bullet is None:
        reporter.fail("README.md Known attack exclusions must retain its bulleted list")
        exclusion_intro: list[str] = exclusion_block
        exclusion_lines: list[str] = []
    else:
        exclusion_intro = exclusion_block[:first_bullet]
        exclusion_lines = exclusion_block[first_bullet:]
    while exclusion_intro and not exclusion_intro[-1].strip():
        exclusion_intro.pop()
    exclusion_intro_blocks = paragraph_blocks(exclusion_intro)
    if len(exclusion_intro_blocks) != 1:
        reporter.fail(
            "README.md Known attack exclusions must retain one lead paragraph"
        )
    exclusion_bullets: list[str] = []
    malformed_exclusion_line = False
    for line in exclusion_lines:
        if line.startswith("- "):
            exclusion_bullets.append(line[2:])
        elif line.strip() and exclusion_bullets:
            continuation = line.strip()
            exclusion_bullets[-1] += " " + continuation
        else:
            malformed_exclusion_line = True
    if malformed_exclusion_line:
        reporter.fail(
            "README.md Known attack exclusions must remain one contiguous bulleted list"
        )
    excluded_entries = [
        item for item in catalog if item.get("status") == "KNOWN_ATTACK_EXCLUDED"
    ]
    expected_exclusion_identities = Counter(
        (str(item.get("scheme")), normalized_eprint(str(item.get("eprint_id"))))
        for item in excluded_entries
    )
    observed_exclusion_identities: Counter[tuple[str, str]] = Counter()
    observed_exclusion_order: list[str] = []
    exclusion_lead = re.compile(
        r"^(?P<label>.+?)\s+\(ePrint\s+(?P<eprint>[0-9]{4}/[0-9]+)\b",
        re.DOTALL,
    )
    for index, bullet in enumerate(exclusion_bullets, 1):
        match = exclusion_lead.match(bullet)
        if match is None:
            reporter.fail(
                f"README.md Known attack exclusion {index} must begin with a scheme "
                "label and ePrint identifier"
            )
            continue
        label = " ".join(match.group("label").split())
        displayed_eprint = match.group("eprint")
        eprint_id = normalized_eprint(displayed_eprint)
        candidates = [
            item
            for item in excluded_entries
            if readme_eprint_matches(displayed_eprint, str(item.get("eprint_id")))
            and readme_label_matches(label, accepted_readme_labels(item))
        ]
        if len(candidates) != 1:
            reporter.fail(
                f"README.md Known attack exclusion {index} label {label!r} and "
                f"ePrint {match.group('eprint')} match {len(candidates)} catalog records"
            )
            continue
        observed_exclusion_identities[(str(candidates[0].get("scheme")), eprint_id)] += 1
        observed_exclusion_order.append(str(candidates[0].get("scheme")))
    if observed_exclusion_identities != expected_exclusion_identities:
        reporter.fail(
            "README.md Known attack exclusions must map one-to-one to excluded "
            f"catalog records: found {dict(observed_exclusion_identities)}, "
            f"expected {dict(expected_exclusion_identities)}"
        )
    if observed_exclusion_order[: len(README_EXCLUSION_ORDER)] != list(
        README_EXCLUSION_ORDER
    ):
        reporter.fail(
            "README.md Known attack exclusions must preserve the established order "
            "and append future exclusions at the end"
        )

    audit_rows = table_cells(
        section(README_HEADINGS[4], README_HEADINGS[5]),
        "Completed audits without a practical attack",
        README_AUDIT_TABLE_HEADER,
    )
    negative_entries = [
        item for item in catalog if item.get("status") == "AUDITED_NO_PRACTICAL_ATTACK"
    ]
    expected_negative_identities = Counter(
        (str(item.get("scheme")), normalized_eprint(str(item.get("eprint_id"))))
        for item in negative_entries
    )
    observed_negative_identities: Counter[tuple[str, str]] = Counter()
    observed_negative_order: list[tuple[str, str]] = []
    for index, row in enumerate(audit_rows, 1):
        match = re.match(r"^([0-9]{4}/[0-9]+)\b", row[1])
        if match is None:
            reporter.fail(
                f"README.md Completed audits row {index} must begin its ePrint cell "
                "with an identifier"
            )
            continue
        displayed_eprint = match.group(1)
        eprint_id = normalized_eprint(displayed_eprint)
        candidates = [
            item
            for item in negative_entries
            if readme_eprint_matches(displayed_eprint, str(item.get("eprint_id")))
            and readme_label_matches(row[0], accepted_readme_labels(item))
        ]
        if len(candidates) != 1:
            reporter.fail(
                f"README.md Completed audits row {index} label {row[0]!r} and "
                f"ePrint {match.group(1)} match {len(candidates)} catalog records"
            )
            continue
        candidate = candidates[0]
        identity = (
            str(candidate.get("scheme")),
            normalized_eprint(str(candidate.get("eprint_id"))),
        )
        observed_negative_identities[identity] += 1
        observed_negative_order.append(identity)
    if observed_negative_identities != expected_negative_identities:
        reporter.fail(
            "README.md Completed audits table must map one-to-one to bounded-audit "
            f"catalog records: found {dict(observed_negative_identities)}, "
            f"expected {dict(expected_negative_identities)}"
        )
    observed_negative_schemes = [scheme for scheme, _ in observed_negative_order]
    if observed_negative_schemes[: len(README_AUDIT_ORDER)] != list(
        README_AUDIT_ORDER
    ):
        reporter.fail(
            "README.md Completed audits must preserve the established row order and "
            "append future audits at the end"
        )

    audit_summary_blocks = paragraph_blocks(
        section(README_HEADINGS[5], README_HEADINGS[6])
    )
    audit_summary_lead = re.compile(
        r"^(?P<label>.+?)\s+\(ePrint\s+(?P<eprint>[0-9]{4}/[0-9]+)\b",
        re.DOTALL,
    )
    audit_summary_order: list[tuple[str, str]] = []
    for block in audit_summary_blocks:
        match = audit_summary_lead.match(block)
        if match is None:
            continue
        label = " ".join(match.group("label").split())
        displayed_eprint = match.group("eprint")
        eprint_id = normalized_eprint(displayed_eprint)
        candidates = [
            item
            for item in negative_entries
            if readme_eprint_matches(displayed_eprint, str(item.get("eprint_id")))
            and readme_label_matches(label, accepted_readme_labels(item))
        ]
        if len(candidates) == 1:
            audit_summary_order.append(
                (str(candidates[0].get("scheme")), eprint_id)
            )
    if observed_negative_order != audit_summary_order:
        reporter.fail(
            "README.md Completed audits rows and Audit summaries must retain the "
            "same identity order"
        )

    if (
        not lines
        or lines[-1] != README_FOOTER
        or contents.count(README_FOOTER) != 1
        or not contents.endswith("\n")
        or len(lines) < 3
        or lines[-2] != ""
        or lines[-3] == ""
    ):
        reporter.fail(
            "README.md must end with exactly one blank line followed by the single "
            "established methodology/resources footer"
        )


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
    expected = {
        "schemes identified": len(catalog),
        "known attacks excluded": sum(
            item.get("status") == "KNOWN_ATTACK_EXCLUDED" for item in catalog
        ),
        "schemes audited": sum(item.get("status") in AUDITED_STATES for item in catalog),
        "no practical attack found": sum(
            item.get("status") == "AUDITED_NO_PRACTICAL_ATTACK" for item in catalog
        ),
        "verified and independently reproduced practical design attacks": sum(
            item.get("independent_reproduction") is True for item in attacks
        ),
    }
    required = {
        "schemes identified",
        "known attacks excluded",
        "schemes audited",
        "no practical attack found",
        "verified and independently reproduced practical design attacks",
    }
    missing = sorted(required - dashboard.keys())
    if missing:
        reporter.fail(f"README.md dashboard is missing {', '.join(missing)}")
    for name, actual in dashboard.items():
        if name in expected and actual != expected[name]:
            reporter.fail(
                f"README.md dashboard {name!r} is {actual}, expected {expected[name]}"
            )


def validate_readme_summary_structure(
    catalog: list[dict[str, Any]],
    attacks_by_identity: dict[tuple[str, str], pathlib.Path],
    reporter: Reporter,
) -> None:
    """Keep both README summary sections complete and in their compact form."""
    try:
        contents = README.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        reporter.fail(f"README.md: {exc}")
        return

    audit_marker = "### Audit summaries\n"
    verified_marker = "\n## Verified attack summaries\n"
    footer_marker = "\nSee [methodology]"
    if contents.count(audit_marker) != 1:
        reporter.fail("README.md must contain exactly one Audit summaries heading")
        return
    if contents.count(verified_marker) != 1:
        reporter.fail("README.md must contain exactly one Verified attack summaries heading")
        return

    before_verified, verified_and_footer = contents.split(verified_marker, 1)
    audit_text = before_verified.split(audit_marker, 1)[1]
    if footer_marker not in verified_and_footer:
        reporter.fail("README.md is missing the methodology footer after attack summaries")
        return
    verified_text = verified_and_footer.split(footer_marker, 1)[0]

    def paragraphs(section: str) -> list[str]:
        return [part.strip() for part in re.split(r"\n[ \t]*\n", section.strip()) if part.strip()]

    def check_compact_blocks(
        blocks: list[str], section_name: str, minimum: int, maximum: int
    ) -> None:
        for index, block in enumerate(blocks, 1):
            words = len(re.findall(r"\S+", block))
            if not minimum <= words <= maximum:
                reporter.fail(
                    f"README.md {section_name} paragraph {index} has {words} words; "
                    f"expected {minimum}..{maximum}"
                )

    audit_blocks = paragraphs(audit_text)
    negative_entries = [
        item for item in catalog if item.get("status") == "AUDITED_NO_PRACTICAL_ATTACK"
    ]
    if len(audit_blocks) != len(negative_entries):
        reporter.fail(
            "README.md Audit summaries must contain exactly one paragraph per "
            f"bounded audit: found {len(audit_blocks)}, expected {len(negative_entries)}"
        )
    check_compact_blocks(audit_blocks, "Audit summaries", 40, 140)
    expected_negative_identities = Counter(
        (str(item.get("scheme")), normalized_eprint(str(item.get("eprint_id"))))
        for item in negative_entries
    )
    observed_negative_identities: Counter[tuple[str, str]] = Counter()
    audit_lead = re.compile(
        r"^(?P<label>.+?)\s+\(ePrint\s+(?P<eprint>[0-9]{4}/[0-9]+)\b",
        re.DOTALL,
    )
    for index, block in enumerate(audit_blocks, 1):
        lead = audit_lead.match(block)
        if lead is None:
            reporter.fail(
                f"README.md Audit summary {index} must begin with a scheme label "
                "and ePrint identifier"
            )
            continue
        label = " ".join(lead.group("label").split())
        displayed_eprint = lead.group("eprint")
        eprint_id = normalized_eprint(displayed_eprint)
        candidates = [
            item
            for item in negative_entries
            if readme_eprint_matches(displayed_eprint, str(item.get("eprint_id")))
            and readme_label_matches(label, accepted_readme_labels(item))
        ]
        if len(candidates) != 1:
            reporter.fail(
                f"README.md Audit summary {index} label {label!r} and ePrint "
                f"{lead.group('eprint')} match {len(candidates)} bounded-audit records"
            )
            continue
        candidate = candidates[0]
        observed_negative_identities[
            (str(candidate.get("scheme")), normalized_eprint(str(candidate.get("eprint_id"))))
        ] += 1
    if observed_negative_identities != expected_negative_identities:
        reporter.fail(
            "README.md Audit summaries do not map one-to-one to bounded-audit "
            f"catalog identities: found {dict(observed_negative_identities)}, "
            f"expected {dict(expected_negative_identities)}"
        )

    verified_blocks = paragraphs(verified_text)
    expected_dirs = {path.name for path in attacks_by_identity.values()}
    if len(verified_blocks) != len(expected_dirs):
        reporter.fail(
            "README.md Verified attack summaries must contain exactly one paragraph "
            f"per attack directory: found {len(verified_blocks)}, expected {len(expected_dirs)}"
        )
    check_compact_blocks(verified_blocks, "Verified attack summaries", 40, 180)

    observed_dirs: list[str] = []
    for index, block in enumerate(verified_blocks, 1):
        lead, links = parsed_attack_links(block)
        if lead is None:
            reporter.fail(
                f"README.md Verified attack summary {index} must begin with one "
                "attacks/<directory>/ link"
            )
        if len(links) != 1:
            reporter.fail(
                f"README.md Verified attack summary {index} must contain exactly "
                f"one attack-directory link; found {links}"
            )
        if lead is not None:
            observed_dirs.append(lead[1])
    if len(observed_dirs) != len(set(observed_dirs)):
        reporter.fail("README.md Verified attack summaries repeat an attack directory")
    if set(observed_dirs) != expected_dirs:
        reporter.fail(
            "README.md Verified attack summary directories differ from attacks/: "
            f"found {sorted(set(observed_dirs))}, expected {sorted(expected_dirs)}"
        )

    expected_id_by_dir = {
        path.name: identity[0] for identity, path in attacks_by_identity.items()
    }
    for index, (block, directory) in enumerate(zip(verified_blocks, observed_dirs), 1):
        eprint_ids = re.findall(r"\bePrint\s+([0-9]{4}/[0-9]+)\b", block)
        expected_id = expected_id_by_dir.get(directory)
        if (
            expected_id is None
            or not eprint_ids
            or any(readme_eprint_matches(value, expected_id) is False for value in eprint_ids)
        ):
            reporter.fail(
                f"README.md Verified attack summary {index} for {directory!r} must "
                f"refer only to ePrint {expected_id}; found {eprint_ids}"
            )


def main() -> int:
    reporter = Reporter()
    if not require_markdown_parser(reporter):
        return 1
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

    validate_readme_layout(catalog, attacks_by_identity, reporter)
    validate_dashboard(catalog, attack_records, reporter)
    validate_readme_summary_structure(catalog, attacks_by_identity, reporter)

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
