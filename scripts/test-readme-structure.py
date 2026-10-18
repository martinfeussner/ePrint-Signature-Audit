#!/usr/bin/env python3
"""Regression-test the README structure contract enforced by CI."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = "README.md"


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"expected one occurrence of {old!r}, found {text.count(old)}")
    return text.replace(old, new, 1)


def mutate_section_paragraphs(
    text: str,
    start: str,
    end: str,
    mutation: Callable[[list[str]], None],
) -> str:
    start_at = text.index(start) + len(start)
    end_at = text.index(end, start_at)
    section = text[start_at:end_at]
    leading = section[: len(section) - len(section.lstrip("\n"))]
    trailing = section[len(section.rstrip("\n")) :]
    paragraphs = re.split(r"\n[ \t]*\n", section.strip("\n"))
    mutation(paragraphs)
    return (
        text[:start_at]
        + leading
        + "\n\n".join(paragraphs)
        + trailing
        + text[end_at:]
    )


def mutate_section_paragraph(
    text: str,
    start: str,
    end: str,
    index: int,
    mutation: Callable[[str], str],
) -> str:
    def mutate(paragraphs: list[str]) -> None:
        if index >= len(paragraphs):
            raise ValueError(f"section has only {len(paragraphs)} paragraphs")
        paragraphs[index] = mutation(paragraphs[index])

    return mutate_section_paragraphs(text, start, end, mutate)


def replace_intro_paragraph(text: str, index: int, replacement: str) -> str:
    return mutate_section_paragraph(
        text,
        "# ePrint Signature Audit\n",
        "\n## Dashboard",
        index,
        lambda _paragraph: replacement,
    )


def append_intro(text: str, suffix: str, index: int = 0) -> str:
    return mutate_section_paragraph(
        text,
        "# ePrint Signature Audit\n",
        "\n## Dashboard",
        index,
        lambda paragraph: paragraph + suffix,
    )


def prefix_verified_summary(text: str, prefix: str) -> str:
    return mutate_section_paragraph(
        text,
        "## Verified attack summaries\n",
        "\nSee [methodology]",
        0,
        lambda paragraph: prefix + paragraph,
    )


def split_table_cells(line: str) -> list[str]:
    stripped = line.rstrip("\n")
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise ValueError("not an outer-pipe table row")
    cells: list[str] = []
    current: list[str] = []
    inner = stripped[1:-1]
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
    return cells


def format_table_cells(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |\n"


def section_bounds(lines: list[str], start: str, end: str) -> tuple[int, int]:
    return lines.index(start) + 1, lines.index(end)


def table_row_indices(lines: list[str], start: str, end: str) -> list[int]:
    first, last = section_bounds(lines, start, end)
    nonempty = [index for index in range(first, last) if lines[index].strip()]
    if len(nonempty) < 2:
        raise ValueError(f"table section {start!r} has no header and separator")
    rows = nonempty[2:]
    if any(not lines[index].startswith("|") or not lines[index].endswith("|") for index in rows):
        raise ValueError(f"table section {start!r} contains a non-row data line")
    return rows


def mutate_table_rows(
    text: str,
    start: str,
    end: str,
    mutation: Callable[[list[str], list[int]], None],
) -> str:
    lines = text.splitlines(keepends=True)
    plain = [line.rstrip("\n") for line in lines]
    indices = table_row_indices(plain, start, end)
    mutation(lines, indices)
    return "".join(lines)


def drop_last_table_row(text: str, start: str, end: str) -> str:
    def drop(lines: list[str], indices: list[int]) -> None:
        del lines[indices[-1]]

    return mutate_table_rows(text, start, end, drop)


def swap_first_table_rows(text: str, start: str, end: str) -> str:
    def swap(lines: list[str], indices: list[int]) -> None:
        lines[indices[0]], lines[indices[1]] = lines[indices[1]], lines[indices[0]]

    return mutate_table_rows(text, start, end, swap)


def swap_first_summary_paragraphs(text: str, start: str, end: str) -> str:
    def swap(paragraphs: list[str]) -> None:
        if len(paragraphs) < 2:
            raise ValueError("summary section has fewer than two paragraphs")
        paragraphs[0], paragraphs[1] = paragraphs[1], paragraphs[0]

    return mutate_section_paragraphs(text, start, end, swap)


def paired_attack_reorder(text: str) -> str:
    text = swap_first_table_rows(
        text, "## Practical design attacks", "## Known attack exclusions"
    )
    return swap_first_summary_paragraphs(
        text,
        "## Verified attack summaries\n",
        "\nSee [methodology]",
    )


def paired_audit_reorder(text: str) -> str:
    text = swap_first_table_rows(
        text,
        "## Completed audits without a practical attack",
        "### Audit summaries",
    )
    return swap_first_summary_paragraphs(
        text,
        "### Audit summaries\n",
        "\n## Verified attack summaries",
    )


def normalized_eprint(value: str) -> str:
    match = re.fullmatch(r"(?P<year>[0-9]{4})/(?P<number>[0-9]+)", value)
    if match is None:
        raise ValueError(f"invalid ePrint identifier {value!r}")
    return f"{match.group('year')}/{int(match.group('number'))}"


def table_eprint(cells: list[str]) -> str | None:
    if len(cells) < 2:
        return None
    match = re.match(r"^(?P<eprint>[0-9]{4}/[0-9]+)\b", cells[1])
    return normalized_eprint(match.group("eprint")) if match is not None else None


def transform_audit_table_labels(
    text: str,
    eprint: str,
    transform: Callable[[list[str]], list[str]],
    expected: int = 1,
) -> str:
    target = normalized_eprint(eprint)

    def edit(lines: list[str], indices: list[int]) -> None:
        matches = [
            (index, split_table_cells(lines[index]))
            for index in indices
            if table_eprint(split_table_cells(lines[index])) == target
        ]
        if len(matches) != expected:
            raise ValueError(
                f"expected {expected} audit table row(s) for {target}, found {len(matches)}"
            )
        replacements = transform([cells[0] for _, cells in matches])
        if len(replacements) != len(matches):
            raise ValueError("audit-label transform changed the number of labels")
        for (index, cells), replacement in zip(matches, replacements):
            cells[0] = replacement
            lines[index] = format_table_cells(cells)

    return mutate_table_rows(
        text,
        "## Completed audits without a practical attack",
        "### Audit summaries",
        edit,
    )


AUDIT_SUMMARY_LEAD = re.compile(
    r"^(?P<label>.+?)(?P<intro>\s+\(ePrint\s+)"
    r"(?P<eprint>[0-9]{4}/[0-9]+)\b",
    re.DOTALL,
)


def transform_audit_summary_labels(
    text: str,
    eprint: str,
    transform: Callable[[list[str]], list[str]],
    expected: int = 1,
) -> str:
    target = normalized_eprint(eprint)

    def edit(paragraphs: list[str]) -> None:
        matches: list[tuple[int, re.Match[str]]] = []
        for index, paragraph in enumerate(paragraphs):
            match = AUDIT_SUMMARY_LEAD.match(paragraph)
            if match is not None and normalized_eprint(match.group("eprint")) == target:
                matches.append((index, match))
        if len(matches) != expected:
            raise ValueError(
                f"expected {expected} audit summary(s) for {target}, found {len(matches)}"
            )
        replacements = transform(
            [match.group("label") for _, match in matches]
        )
        if len(replacements) != len(matches):
            raise ValueError("audit-summary transform changed the number of labels")
        for (index, match), replacement in zip(matches, replacements):
            paragraph = paragraphs[index]
            paragraphs[index] = (
                paragraph[: match.start("label")]
                + replacement
                + paragraph[match.end("label") :]
            )

    return mutate_section_paragraphs(
        text,
        "### Audit summaries\n",
        "\n## Verified attack summaries",
        edit,
    )


def wrap_first_multiword_audit_summary_label(text: str, hard: bool) -> str:
    def wrap(paragraphs: list[str]) -> None:
        for index, paragraph in enumerate(paragraphs):
            match = AUDIT_SUMMARY_LEAD.match(paragraph)
            if match is None:
                continue
            label = match.group("label")
            split_at = label.rfind(" ")
            if split_at < 0:
                continue
            separator = "  \n" if hard else "\n"
            wrapped = label[:split_at] + separator + label[split_at + 1 :]
            paragraphs[index] = (
                paragraph[: match.start("label")]
                + wrapped
                + paragraph[match.end("label") :]
            )
            return
        raise ValueError("no multiword audit-summary label was found")

    return mutate_section_paragraphs(
        text,
        "### Audit summaries\n",
        "\n## Verified attack summaries",
        wrap,
    )


def wrap_first_multiword_exclusion_label(text: str, hard: bool) -> str:
    start = text.index("## Known attack exclusions\n")
    end = text.index("\n## Completed audits without a practical attack", start)
    section = text[start:end]
    lead = re.compile(
        r"(?m)^- (?P<label>.+?)(?P<intro>[ \t]+\(ePrint[ \t]+[0-9]{4}/)"
    )
    for match in lead.finditer(section):
        label = match.group("label")
        split_at = label.rfind(" ")
        if split_at < 0:
            continue
        separator = "  \n" if hard else "\n"
        wrapped = label[:split_at] + separator + label[split_at + 1 :]
        label_start = start + match.start("label")
        label_end = start + match.end("label")
        return text[:label_start] + wrapped + text[label_end:]
    raise ValueError("no multiword exclusion label was found")


def replace_audit_label(text: str, eprint: str, replacement: str) -> str:
    replace = lambda _labels: [replacement]
    text = transform_audit_table_labels(text, eprint, replace)
    return transform_audit_summary_labels(text, eprint, replace)


def swap_shared_id_labels(text: str, include_summaries: bool) -> str:
    swap = lambda labels: list(reversed(labels))
    text = transform_audit_table_labels(text, "2024/490", swap, expected=2)
    if include_summaries:
        text = transform_audit_summary_labels(text, "2024/490", swap, expected=2)
    return text


def combine_shared_id_labels(text: str) -> str:
    def combine(labels: list[str]) -> list[str]:
        return [f"{labels[0]} {labels[1]}", labels[1]]

    text = transform_audit_table_labels(text, "2024/490", combine, expected=2)
    return transform_audit_summary_labels(text, "2024/490", combine, expected=2)


def capss_prefix_labels(text: str) -> str:
    return replace_audit_label(text, "2025/61", "CAPSS")


def nic_labels(text: str, replacement: str) -> str:
    return replace_audit_label(text, "2026/1573", replacement)


def braccoon_composite_labels(text: str) -> str:
    return replace_audit_label(text, "2026/1084", "BRaccoon / BRaccoon")


def falcon_mrm_composite_labels(text: str) -> str:
    replacement = "FALCON with message recovery, a specification / FALCON-MRM"
    return replace_audit_label(text, "2026/420", replacement)


ATTACK_TABLE_LINK = re.compile(
    r"^\[(?P<label>[^\]]+)\]\(attacks/(?P<directory>[a-z0-9-]+)/\)$"
)
VERIFIED_SUMMARY_LINK = re.compile(
    r"^\[(?P<label>[^\]]+)\]\(attacks/(?P<directory>[a-z0-9-]+)/\)"
)


def replace_attack_label(text: str, directory: str, replacement: str) -> str:
    def edit_table(lines: list[str], indices: list[int]) -> None:
        matches: list[tuple[int, list[str]]] = []
        for index in indices:
            cells = split_table_cells(lines[index])
            match = ATTACK_TABLE_LINK.fullmatch(cells[0]) if cells else None
            if match is not None and match.group("directory") == directory:
                matches.append((index, cells))
        if len(matches) != 1:
            raise ValueError(
                f"expected one attack table row for {directory!r}, found {len(matches)}"
            )
        index, cells = matches[0]
        cells[0] = f"[{replacement}](attacks/{directory}/)"
        lines[index] = format_table_cells(cells)

    text = mutate_table_rows(
        text, "## Practical design attacks", "## Known attack exclusions", edit_table
    )

    def edit_summary(paragraphs: list[str]) -> None:
        matches: list[tuple[int, re.Match[str]]] = []
        for index, paragraph in enumerate(paragraphs):
            match = VERIFIED_SUMMARY_LINK.match(paragraph)
            if match is not None and match.group("directory") == directory:
                matches.append((index, match))
        if len(matches) != 1:
            raise ValueError(
                f"expected one verified summary for {directory!r}, found {len(matches)}"
            )
        index, match = matches[0]
        paragraph = paragraphs[index]
        paragraphs[index] = (
            paragraph[: match.start("label")]
            + replacement
            + paragraph[match.end("label") :]
        )

    return mutate_section_paragraphs(
        text,
        "## Verified attack summaries\n",
        "\nSee [methodology]",
        edit_summary,
    )


def yagisawa_shifted_possessive(text: str) -> str:
    return replace_attack_label(
        text, "yagisawa-order-four", "Yagisawa quaternion's signature"
    )


def transform_audit_eprint(text: str, eprint: str, replacement: str) -> str:
    target = normalized_eprint(eprint)

    def edit_table(lines: list[str], indices: list[int]) -> None:
        matches: list[tuple[int, list[str], re.Match[str]]] = []
        for index in indices:
            cells = split_table_cells(lines[index])
            if len(cells) < 2:
                continue
            match = re.match(r"^(?P<eprint>[0-9]{4}/[0-9]+)\b", cells[1])
            if match is not None and normalized_eprint(match.group("eprint")) == target:
                matches.append((index, cells, match))
        if len(matches) != 1:
            raise ValueError(
                f"expected one audit table row for {target}, found {len(matches)}"
            )
        index, cells, match = matches[0]
        cells[1] = replacement + cells[1][match.end("eprint") :]
        lines[index] = format_table_cells(cells)

    text = mutate_table_rows(
        text,
        "## Completed audits without a practical attack",
        "### Audit summaries",
        edit_table,
    )

    def edit_summary(paragraphs: list[str]) -> None:
        matches: list[tuple[int, re.Match[str]]] = []
        for index, paragraph in enumerate(paragraphs):
            match = AUDIT_SUMMARY_LEAD.match(paragraph)
            if match is not None and normalized_eprint(match.group("eprint")) == target:
                matches.append((index, match))
        if len(matches) != 1:
            raise ValueError(
                f"expected one audit summary for {target}, found {len(matches)}"
            )
        index, match = matches[0]
        paragraph = paragraphs[index]
        paragraphs[index] = (
            paragraph[: match.start("eprint")]
            + replacement
            + paragraph[match.end("eprint") :]
        )

    return mutate_section_paragraphs(
        text,
        "### Audit summaries\n",
        "\n## Verified attack summaries",
        edit_summary,
    )


def replace_capss_eprint(text: str, replacement: str) -> str:
    return transform_audit_eprint(text, "2025/61", replacement)


def alternate_capss_eprint(text: str) -> str:
    lines = text.splitlines()
    first, last = section_bounds(
        lines,
        "## Completed audits without a practical attack",
        "### Audit summaries",
    )
    displays = []
    for index in range(first, last):
        if not lines[index].startswith("|") or not lines[index].endswith("|"):
            continue
        cells = split_table_cells(lines[index])
        match = re.match(r"^(?P<eprint>[0-9]{4}/[0-9]+)\b", cells[1]) if len(cells) > 1 else None
        if match is not None and normalized_eprint(match.group("eprint")) == "2025/61":
            displays.append(match.group("eprint"))
    if len(displays) != 1 or displays[0] not in {"2025/61", "2025/061"}:
        raise ValueError(f"unexpected CAPSS ePrint displays: {displays!r}")
    replacement = "2025/61" if displays[0] == "2025/061" else "2025/061"
    return replace_capss_eprint(text, replacement)


def wrap_first_exclusion_continuation(text: str, spaces: int) -> str:
    lines = text.splitlines(keepends=True)
    plain = [line.rstrip("\n") for line in lines]
    first, last = section_bounds(
        plain,
        "## Known attack exclusions",
        "## Completed audits without a practical attack",
    )
    bullet = next(index for index in range(first, last) if lines[index].startswith("- "))
    next_bullet = next(
        (
            index
            for index in range(bullet + 1, last)
            if lines[index].startswith("- ")
        ),
        last,
    )
    continuation = next(
        (index for index in range(bullet + 1, next_bullet) if lines[index].strip()),
        None,
    )
    if continuation is None:
        content = lines[bullet].rstrip("\r\n")[2:]
        split_at = content.rfind(" ", 0, max(len(content) // 2, 1))
        if split_at <= 0:
            split_at = content.find(" ")
        if split_at <= 0:
            raise ValueError("first exclusion bullet cannot be line-wrapped")
        newline = "\r\n" if lines[bullet].endswith("\r\n") else "\n"
        lines[bullet] = "- " + content[:split_at] + newline
        lines.insert(
            bullet + 1,
            (" " * spaces) + content[split_at + 1 :] + newline,
        )
    else:
        lines[continuation] = (" " * spaces) + lines[continuation].lstrip(" \t")
    return "".join(lines)


def add_attack_cell(text: str) -> str:
    def add(lines: list[str], indices: list[int]) -> None:
        line = lines[indices[0]].rstrip("\n")
        lines[indices[0]] = line[:-1] + "| Extra |\n"

    return mutate_table_rows(
        text, "## Practical design attacks", "## Known attack exclusions", add
    )


def edit_attack_detail(text: str, suffix: str) -> str:
    def edit(lines: list[str], indices: list[int]) -> None:
        cells = split_table_cells(lines[indices[0]])
        cells[4] = f"{cells[4]} {suffix}"
        lines[indices[0]] = format_table_cells(cells)

    return mutate_table_rows(
        text, "## Practical design attacks", "## Known attack exclusions", edit
    )


def edit_audit_scope(text: str, suffix: str) -> str:
    def edit(lines: list[str], indices: list[int]) -> None:
        cells = split_table_cells(lines[indices[0]])
        cells[2] = f"{cells[2]} {suffix}"
        lines[indices[0]] = format_table_cells(cells)

    return mutate_table_rows(
        text,
        "## Completed audits without a practical attack",
        "### Audit summaries",
        edit,
    )


def remove_first_exclusion(text: str) -> str:
    lines = text.splitlines(keepends=True)
    first, last = section_bounds(
        [line.rstrip("\n") for line in lines],
        "## Known attack exclusions",
        "## Completed audits without a practical attack",
    )
    bullet = next(index for index in range(first, last) if lines[index].startswith("- "))
    next_bullet = next(
        index
        for index in range(bullet + 1, last)
        if lines[index].startswith("- ")
    )
    del lines[bullet:next_bullet]
    return "".join(lines)


def change_first_exclusion_label(text: str) -> str:
    return re.sub(r"(?m)^- .+? \(ePrint", "- Wrong scheme (ePrint", text, count=1)


def add_nested_exclusion(text: str) -> str:
    return re.sub(
        r"(?m)^(- .+\n)", r"\1  - Nested exclusion.\n", text, count=1
    )


def add_tab_nested_exclusion(text: str) -> str:
    return re.sub(
        r"(?m)^(- .+\n)", r"\g<1> \t- Nested exclusion.\n", text, count=1
    )


def span_verified_paragraphs(text: str, middle: str) -> str:
    def span(paragraphs: list[str]) -> None:
        if len(paragraphs) < 2:
            raise ValueError("verified summaries need at least two paragraphs")
        paragraphs[0] += " `"
        paragraphs[1] = middle + "\n`" + paragraphs[1]

    return mutate_section_paragraphs(
        text,
        "## Verified attack summaries\n",
        "\nSee [methodology]",
        span,
    )


def transform_verified_lead_link(
    text: str,
    transform: Callable[[str, str], str],
    require_multiword: bool = False,
) -> str:
    def edit(paragraphs: list[str]) -> None:
        for index, paragraph in enumerate(paragraphs):
            match = VERIFIED_SUMMARY_LINK.match(paragraph)
            if match is None:
                continue
            label = match.group("label")
            if require_multiword and re.search(r"[ \t]", label) is None:
                continue
            directory = match.group("directory")
            paragraphs[index] = (
                transform(label, directory) + paragraph[match.end() :]
            )
            return
        qualifier = "multiword " if require_multiword else ""
        raise ValueError(f"no {qualifier}verified-summary lead link was found")

    return mutate_section_paragraphs(
        text,
        "## Verified attack summaries\n",
        "\nSee [methodology]",
        edit,
    )


def change_first_verified_label(text: str) -> str:
    return transform_verified_lead_link(
        text,
        lambda _label, directory: f"[Wrong](attacks/{directory}/)",
    )


def wrap_first_verified_line(text: str) -> str:
    def wrap(paragraphs: list[str]) -> None:
        if not paragraphs:
            raise ValueError("verified summaries are empty")
        paragraph = paragraphs[0]
        match = VERIFIED_SUMMARY_LINK.match(paragraph)
        if match is None:
            raise ValueError("first verified summary has no leading link")
        split_at = paragraph.find(" ", match.end())
        if split_at < 0:
            raise ValueError("first verified summary has no wrappable prose")
        paragraphs[0] = paragraph[:split_at] + "\n" + paragraph[split_at + 1 :]

    return mutate_section_paragraphs(
        text,
        "## Verified attack summaries\n",
        "\nSee [methodology]",
        wrap,
    )


def wrap_verified_link_label(text: str) -> str:
    def wrap(label: str, directory: str) -> str:
        split_at = label.rfind(" ")
        if split_at < 0:
            raise ValueError("verified-summary link label has no wrappable space")
        wrapped = label[:split_at] + "\n" + label[split_at + 1 :]
        return f"[{wrapped}](attacks/{directory}/)"

    return transform_verified_lead_link(text, wrap, require_multiword=True)


def emphasize_verified_link_label(text: str) -> str:
    return transform_verified_lead_link(
        text,
        lambda label, directory: f"[*{label}*](attacks/{directory}/)",
    )


def image_verified_link_label(text: str) -> str:
    return transform_verified_lead_link(
        text,
        lambda _label, directory: (
            f"[![scheme](docs/label.png)](attacks/{directory}/)"
        ),
    )


def hardbreak_verified_link_label(text: str) -> str:
    def hardbreak(label: str, directory: str) -> str:
        split_at = label.rfind(" ")
        if split_at < 0:
            raise ValueError("verified-summary link label has no hard-break position")
        broken = label[:split_at] + "  \n" + label[split_at + 1 :]
        return f"[{broken}](attacks/{directory}/)"

    return transform_verified_lead_link(text, hardbreak, require_multiword=True)


def title_verified_link(text: str) -> str:
    return transform_verified_lead_link(
        text,
        lambda label, directory: (
            f'[{label}](attacks/{directory}/ "injected title")'
        ),
    )


def run_validator(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", "-B", "scripts/validate-metadata.py"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def exercise_cases(
    root: Path,
    baseline: str,
    reject: dict[str, Callable[[str], str]],
    allow: dict[str, Callable[[str], str]],
    context: str,
) -> list[str]:
    readme = root / README
    failures: list[str] = []
    readme.write_text(baseline, encoding="utf-8")
    validation = run_validator(root)
    if validation.returncode != 0:
        detail = (validation.stdout + validation.stderr).strip()
        failures.append(
            f"{context}: baseline was rejected by the validator"
            + (f"\n{detail}" if detail else "")
        )
        return failures

    try:
        for name, mutation in reject.items():
            try:
                candidate = mutation(baseline)
            except Exception as exc:  # expose stale probe anchors as named failures
                failures.append(f"{context} / {name}: mutation failed: {exc}")
                continue
            if candidate == baseline:
                failures.append(f"{context} / {name}: mutation made no change")
                continue
            readme.write_text(candidate, encoding="utf-8")
            if run_validator(root).returncode == 0:
                failures.append(
                    f"{context} / {name}: structural drift was accepted"
                )

        for name, mutation in allow.items():
            try:
                candidate = mutation(baseline)
            except Exception as exc:  # expose stale probe anchors as named failures
                failures.append(f"{context} / {name}: mutation failed: {exc}")
                continue
            if candidate == baseline:
                failures.append(
                    f"{context} / {name}: allowed mutation made no change"
                )
                continue
            readme.write_text(candidate, encoding="utf-8")
            result = run_validator(root)
            if result.returncode != 0:
                detail = (result.stdout + result.stderr).strip()
                failures.append(
                    f"{context} / {name}: ordinary content edit was rejected"
                    + (f"\n{detail}" if detail else "")
                )
    finally:
        readme.write_text(baseline, encoding="utf-8")
    return failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="readme-structure-", dir="/tmp") as tmp:
        test_root = Path(tmp) / "repo"
        shutil.copytree(
            ROOT,
            test_root,
            ignore=shutil.ignore_patterns(".git", "__pycache__"),
        )
        readme = test_root / README
        baseline = readme.read_text(encoding="utf-8")

        reject: dict[str, Callable[[str], str]] = {
            "content before H1": lambda value: "Injected preface.\n\n" + value,
            "one-space ATX heading": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n ### Injected heading\n\n## Dashboard\n"
            ),
            "two-space ATX heading": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n  ### Injected heading\n\n## Dashboard\n"
            ),
            "three-space ATX heading": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n   ### Injected heading\n\n## Dashboard\n"
            ),
            "setext heading": lambda value: replace_once(
                value, "\n## Dashboard\n", "\nInjected heading\n---\n\n## Dashboard\n"
            ),
            "raw HTML heading": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n<h2>Injected</h2>\n\n## Dashboard\n"
            ),
            "mid-line raw HTML heading": lambda value: append_intro(
                value, " <h2>Injected</h2>"
            ),
            "mid-line raw HTML details": lambda value: append_intro(
                value, " <details>"
            ),
            "CommonMark declaration": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n<!X hidden>\n\n## Dashboard\n"
            ),
            "unclosed CommonMark declaration": lambda value: replace_once(
                value,
                "\nSee [methodology]",
                "\n<!X hidden footer\nSee [methodology]",
            ),
            "comment-hidden H1": lambda value: "<!--\n"
            + replace_once(value, "\n## Dashboard\n", "\n-->\n\n## Dashboard\n"),
            "comment-hidden footer": lambda value: replace_once(
                value, "\nSee [methodology]", "\n<!-- hidden footer\nSee [methodology]"
            ),
            "indented code block": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n    hidden code\n\n## Dashboard\n"
            ),
            "fenced code block": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n```\nhidden\n```\n\n## Dashboard\n"
            ),
            "asterisk thematic break": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n***\n\n## Dashboard\n"
            ),
            "underscore thematic break": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n ___ \n\n## Dashboard\n"
            ),
            "indented intro list": lambda value: replace_intro_paragraph(
                value, 1, "   - injected"
            ),
            "indented intro quote": lambda value: replace_intro_paragraph(
                value, 1, "  > injected"
            ),
            "indented intro table": lambda value: replace_intro_paragraph(
                value, 1, " | A | B |\n |---|---|"
            ),
            "parenthesized intro list": lambda value: replace_intro_paragraph(
                value, 1, "1) injected"
            ),
            "intro ordered list starting at 2": lambda value: mutate_section_paragraph(
                value,
                "# ePrint Signature Audit\n",
                "\n## Dashboard",
                1,
                lambda paragraph: "2. " + paragraph,
            ),
            "leading-zero ordered list": lambda value: mutate_section_paragraph(
                value,
                "# ePrint Signature Audit\n",
                "\n## Dashboard",
                1,
                lambda paragraph: "01. " + paragraph,
            ),
            "leading-zero list interrupting prose": lambda value: append_intro(
                value, "\n01. injected"
            ),
            "empty unordered list item": lambda value: replace_intro_paragraph(
                value, 1, "-"
            ),
            "empty ordered list item": lambda value: replace_intro_paragraph(
                value, 1, "1."
            ),
            "intro GFM table without outer pipes": lambda value: replace_intro_paragraph(
                value, 1, "A | B\n--- | ---\ncell | cell"
            ),
            "intro reference definition": lambda value: replace_intro_paragraph(
                value, 1, "[hidden]: https://example.com"
            ),
            "space-tab indented code": lambda value: replace_intro_paragraph(
                value, 1, " \tindented code block"
            ),
            "unclosed script HTML block": lambda value: prefix_verified_summary(
                value, "<script\n"
            ),
            "unclosed details HTML block": lambda value: prefix_verified_summary(
                value, "<details\n"
            ),
            "multiline details HTML start tag": lambda value: prefix_verified_summary(
                value, "<details\n open>\n"
            ),
            "multiline HTML start tag": lambda value: prefix_verified_summary(
                value, '<h2\nclass="injected">Injected\n'
            ),
            "escaped-backtick raw HTML": lambda value: append_intro(
                value, r" \`<h2>Injected</h2>`"
            ),
            "multiline code span interrupted by HTML block": lambda value: append_intro(
                value, " `\n<script\n`"
            ),
            "cross-paragraph code span hiding HTML": lambda value: span_verified_paragraphs(
                value, "<h2>Injected</h2>"
            ),
            "cross-paragraph code span hiding thematic break": lambda value: span_verified_paragraphs(
                value, "***"
            ),
            "missing H1": lambda value: replace_once(
                value, "# ePrint Signature Audit\n\n", ""
            ),
            "unexpected heading": lambda value: replace_once(
                value, "\n## Dashboard\n", "\n## Added section\n\n## Dashboard\n"
            ),
            "duplicate Dashboard": lambda value: replace_once(
                value,
                "\n## Practical design attacks\n",
                "\n## Dashboard\n\n## Practical design attacks\n",
            ),
            "extra Dashboard metric": lambda value: replace_once(
                value,
                "\n## Practical design attacks\n",
                "\n| Extra metric | 0 |\n\n## Practical design attacks\n",
            ),
            "Dashboard prose": lambda value: replace_once(
                value, "| Metric | Count |\n|---|---:|\n", "Metric: Count\n"
            ),
            "missing attack row": lambda value: drop_last_table_row(
                value, "## Practical design attacks", "## Known attack exclusions"
            ),
            "redirected attack link": lambda value: re.sub(
                r"\(attacks/[a-z0-9-]+/\)", "(attacks/not-real/)", value, count=1
            ),
            "attack status drift": lambda value: value.replace(
                "Verified; independently AI-reproduced", "Verified", 1
            ),
            "attack order drift": lambda value: swap_first_table_rows(
                value, "## Practical design attacks", "## Known attack exclusions"
            ),
            "paired attack order drift": paired_attack_reorder,
            "extra attack cell": add_attack_cell,
            "missing exclusion": remove_first_exclusion,
            "wrong exclusion label": change_first_exclusion_label,
            "nested exclusion": add_nested_exclusion,
            "tab-expanded nested exclusion": add_tab_nested_exclusion,
            "parenthesized exclusion list": lambda value: re.sub(
                r"(?m)^(- .+\n)", r"\g<1>1) Nested exclusion.\n", value, count=1
            ),
            "hard break in exclusion label": lambda value: wrap_first_multiword_exclusion_label(
                value, hard=True
            ),
            "missing audit row": lambda value: drop_last_table_row(
                value,
                "## Completed audits without a practical attack",
                "### Audit summaries",
            ),
            "audit order drift": lambda value: swap_first_table_rows(
                value,
                "## Completed audits without a practical attack",
                "### Audit summaries",
            ),
            "paired audit order drift": paired_audit_reorder,
            "shared-ID row-label-only swap": lambda value: swap_shared_id_labels(
                value, False
            ),
            "shared-ID synchronized swap": lambda value: swap_shared_id_labels(
                value, True
            ),
            "shared-ID combined label": combine_shared_id_labels,
            "truncated catalog identity": lambda value: replace_audit_label(
                value, "2026/2493", "Robust"
            ),
            "CAPSS alias prefix": capss_prefix_labels,
            "NIC implicit signature removal": lambda value: nic_labels(value, "NIC"),
            "NIC doubled signature suffix": lambda value: nic_labels(
                value, "NIC signature signature"
            ),
            "synthetic duplicated BRaccoon alias": braccoon_composite_labels,
            "synthetic FALCON-MRM alias composite": falcon_mrm_composite_labels,
            "shifted Yagisawa possessive": yagisawa_shifted_possessive,
            "hard break in audit-summary label": lambda value: wrap_first_multiword_audit_summary_label(
                value, hard=True
            ),
            "wrong verified-summary label": change_first_verified_label,
            "emphasis in verified-summary lead link": emphasize_verified_link_label,
            "image in verified-summary lead link": image_verified_link_label,
            "hard break in verified-summary lead link": hardbreak_verified_link_label,
            "title in verified-summary lead link": title_verified_link,
            "indented verified-summary list": lambda value: replace_once(
                value,
                "## Verified attack summaries\n\n",
                "## Verified attack summaries\n\n   - injected\n",
            ),
            "indented verified-summary quote": lambda value: replace_once(
                value,
                "## Verified attack summaries\n\n",
                "## Verified attack summaries\n\n  > injected\n",
            ),
            "indented verified-summary table": lambda value: replace_once(
                value,
                "## Verified attack summaries\n\n",
                "## Verified attack summaries\n\n | A | B |\n |---|---|\n",
            ),
            "parenthesized verified-summary list": lambda value: replace_once(
                value,
                "## Verified attack summaries\n\n",
                "## Verified attack summaries\n\n1) injected\n",
            ),
            "changed footer target": lambda value: value.replace(
                "[methodology](METHODOLOGY.md)",
                "[methodology](docs/other.md)",
                1,
            ),
            "content after footer": lambda value: value
            + "\nUnexpected trailing paragraph.\n",
            "missing blank before footer": lambda value: replace_once(
                value, "\n\nSee [methodology]", "\nSee [methodology]"
            ),
            "missing terminal newline": lambda value: value.rstrip("\n"),
            "overpadded ePrint ID": lambda value: replace_capss_eprint(
                value, "2025/0061"
            ),
            "wrong ePrint ID": lambda value: replace_capss_eprint(
                value, "2025/062"
            ),
        }
        allow: dict[str, Callable[[str], str]] = {
            "ordinary attack-cell prose": lambda value: edit_attack_detail(
                value, "reviewed"
            ),
            "escaped table-cell pipe": lambda value: edit_attack_detail(
                value, r"\| reviewed"
            ),
            "ordinary audit-cell prose": lambda value: edit_audit_scope(
                value, "reviewed"
            ),
            "summary line wrapping": wrap_first_verified_line,
            "verified-link-label soft wrap": wrap_verified_link_label,
            "audit-summary label soft wrap": lambda value: wrap_first_multiword_audit_summary_label(
                value, hard=False
            ),
            "exclusion label soft wrap": lambda value: wrap_first_multiword_exclusion_label(
                value, hard=False
            ),
            "alternate canonical ePrint display": alternate_capss_eprint,
            "ordinary Markdown autolink": lambda value: edit_audit_scope(
                value, "<https://example.com>"
            ),
            "zero-space lazy exclusion wrap": lambda value: wrap_first_exclusion_continuation(
                value, 0
            ),
            "one-space lazy exclusion wrap": lambda value: wrap_first_exclusion_continuation(
                value, 1
            ),
            "code-spanned comment token": lambda value: edit_audit_scope(
                value, "`<!--`"
            ),
            "code-spanned HTML token": lambda value: edit_audit_scope(
                value, "`<h2>`"
            ),
            "code span beside thematic punctuation": lambda value: replace_intro_paragraph(
                value, 1, "`ordinary text` ***"
            ),
            "escaped literal HTML": lambda value: append_intro(
                value, r" \<h2>literal\</h2>"
            ),
            "lowercase literal declaration": lambda value: append_intro(
                value, " <!x literal>"
            ),
            "angle-delimited relative link": lambda value: append_intro(
                value, " [scheme](<reference>)"
            ),
            "multiline inline code with indentation": lambda value: append_intro(
                value, " `line\n    code`"
            ),
            "noninterrupting parenthesized continuation": lambda value: append_intro(
                value, "\n2) continuation"
            ),
            "pipe-leading prose continuation": lambda value: append_intro(
                value, "\n| continuation"
            ),
            "four-space lazy continuation": lambda value: append_intro(
                value, "\n    continuation"
            ),
            "tab-indented lazy continuation": lambda value: append_intro(
                value, "\n\tcontinuation"
            ),
        }

        failures = exercise_cases(
            test_root, baseline, reject, allow, "current baseline"
        )
        meta: dict[str, Callable[[str], str]] = {
            "wholly reworded intro prose": lambda value: replace_intro_paragraph(
                value,
                0,
                (
                    "This replacement introduction deliberately uses unrelated "
                    "ordinary prose so regression probes cannot depend on the "
                    "campaign's current editorial wording."
                ),
            ),
            "alternate canonical ePrint display": alternate_capss_eprint,
            "pre-existing escaped table pipes": lambda value: edit_audit_scope(
                edit_attack_detail(value, r"\| baseline"), r"\| baseline"
            ),
            "explicit catalog alias": lambda value: replace_audit_label(
                value, "2025/61", "CAPSS-Poseidon"
            ),
        }
        meta_count = 0
        for name, mutation in meta.items():
            try:
                candidate = mutation(baseline)
            except Exception as exc:
                failures.append(f"{name}: future baseline mutation failed: {exc}")
                continue
            if candidate == baseline:
                failures.append(f"{name}: future baseline mutation made no change")
                continue
            failures.extend(
                exercise_cases(test_root, candidate, reject, allow, name)
            )
            meta_count += 1

        print(
            f"README structure regression: {len(reject)} drift mutations rejected; "
            f"{len(allow)} ordinary content mutations accepted; "
            f"{meta_count} future baselines exercised."
        )
        for failure in failures:
            print(f"ERROR: {failure}")
        return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
