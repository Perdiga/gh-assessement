#!/usr/bin/env python3
"""Generate versioned Docusaurus control references from catalog JSON files."""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from pathlib import Path
from textwrap import dedent
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CATALOG_ROOT = REPOSITORY_ROOT / "catalogs"
DOCS_ROOT = Path(__file__).resolve().parents[1] / "docs"


def text(value: Any, fallback: str = "Not specified in this catalog.") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value).replace("\r\n", "\n").replace("\r", "\n").replace("{", "&#123;").replace("}", "&#125;").strip()


def code(value: Any, fallback: str = "Not specified") -> str:
    value = text(value, fallback).replace("`", "&#96;").replace("\n", " ")
    return f"`{value}`"


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def table_cell(value: Any) -> str:
    return text(value, "—").replace("|", "\\|").replace("\n", " ")


def versioned_catalogs() -> list[tuple[str, Path]]:
    catalogs = []
    for directory in CATALOG_ROOT.iterdir():
        if not directory.is_dir() or directory.name == "latest":
            continue
        if not re.fullmatch(r"\d+(?:\.\d+)*", directory.name):
            continue
        catalog_path = directory / "github_controls.json"
        if catalog_path.is_file():
            catalogs.append((directory.name, catalog_path))
    return sorted(catalogs, key=lambda item: tuple(int(part) for part in item[0].split(".")))


def evidence_markdown(control: dict[str, Any]) -> str:
    evidence = control.get("evidence", [])
    if not evidence:
        return "No evidence sources are declared in this catalog entry."

    lines = []
    for source in evidence:
        lines.append(f"- **Source:** {code(source.get('source'))}")
        fields = source.get("field", source.get("fields"))
        if fields:
            lines.append(f"  - **Fields:** {code(fields)}")
        if source.get("key"):
            lines.append(f"  - **Evidence key:** {code(source['key'])}")
    return "\n".join(lines)


def automated_evaluation_example(control_id: str) -> str:
    """Return the actual assess() branch used to evaluate an automated control."""
    assessment_path = REPOSITORY_ROOT / "engine" / "assessment.py"
    source = assessment_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(assessment_path))
    assess_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "assess"
    )

    def matches_control(test: ast.expr) -> bool:
        for node in ast.walk(test):
            if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name):
                continue
            if node.left.id != "cid" or len(node.ops) != 1 or len(node.comparators) != 1:
                continue
            operator = node.ops[0]
            comparator = node.comparators[0]
            if isinstance(operator, ast.Eq):
                return isinstance(comparator, ast.Constant) and comparator.value == control_id
            if isinstance(operator, ast.In) and isinstance(comparator, (ast.Tuple, ast.List, ast.Set)):
                return any(
                    isinstance(item, ast.Constant) and item.value == control_id
                    for item in comparator.elts
                )
        return False

    for statement in assess_function.body:
        if isinstance(statement, ast.If) and matches_control(statement.test):
            branch = dedent(ast.get_source_segment(source, statement) or "").rstrip()
            return "\n".join(
                line[4:] if line.startswith("    ") else line
                for line in branch.splitlines()
            )

    raise ValueError(
        f"Automated control {control_id} has no matching branch in {assessment_path}."
    )


def control_page(version: str, control: dict[str, Any], position: int) -> str:
    control_id = control["control_id"]
    title = f"{control_id}: {control.get('title', control_id)}"
    domain = control.get("domain", "Uncategorized")
    automation = control.get("automation") or {}
    mappings = control.get("well_architected_mapping", [])
    mapping_text = ", ".join(text(item) for item in mappings) if mappings else "Not mapped in this catalog."
    page = [
        "---",
        f"id: {control_id}",
        f"title: {yaml_string(title)}",
        f"sidebar_label: {yaml_string(control_id)}",
        f"sidebar_position: {position}",
        "---",
        "",
        f"# {title}",
        "",
        f"**Catalog version:** {version}  ",
        f"**Domain:** {text(domain)}  ",
        f"**Severity:** {text(control.get('severity'))}  ",
        f"**Maturity stage:** {text(control.get('well_architected_stage'))}  ",
        f"**Well-Architected mapping:** {mapping_text}",
        "",
        "## Objective",
        "",
        text(control.get("objective")),
        "",
        "## Requirement",
        "",
        text(control.get("requirement")),
        "",
        "## Risk",
        "",
        text(control.get("risk")),
        "",
        "## Evidence sources",
        "",
        evidence_markdown(control),
        "",
        "## Evaluation logic",
        "",
        f"**Mode:** {code(automation.get('mode'))}",
        "",
        text(automation.get("logic")),
    ]

    if automation.get("mode") == "automated":
        page.extend(
            [
                "",
                "### Example evaluation",
                "",
                "This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.",
                "",
                "```python",
                automated_evaluation_example(control_id),
                "```",
            ]
        )

    page.extend(
        [
        "",
        "## Expected result",
        "",
        text(control.get("expected_result")),
        "",
        "## Exception criteria",
        "",
        text(control.get("exception_criteria")),
        "",
        "## Remediation guidance",
        "",
        text(control.get("remediation")),
        "",
        "## Maturity-stage basis",
        "",
        text(control.get("maturity_basis")),
        "",
        f"[Back to catalog version {version}](/controls/{version})",
        "",
        ]
    )
    return "\n".join(page)


def generate_version(version: str, catalog_path: Path) -> tuple[int, Path]:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog_version = str(catalog.get("version", ""))
    if catalog_version != version:
        raise ValueError(
            f"Catalog folder {version} contains catalog version {catalog_version!r}."
        )

    controls = catalog.get("controls")
    if not isinstance(controls, list):
        raise ValueError(f"Catalog {catalog_path} does not contain a controls list.")

    version_root = DOCS_ROOT / "controls" / version
    version_root.mkdir(parents=True, exist_ok=True)
    domain_counts = Counter(control.get("domain", "Uncategorized") for control in controls)
    control_links: dict[str, list[str]] = {}
    domain_positions: Counter[str] = Counter()

    for control in controls:
        control_id = control["control_id"]
        domain = control.get("domain", "Uncategorized")
        domain_slug = slugify(domain) or "uncategorized"
        domain_positions[domain] += 1
        page_path = version_root / domain_slug / f"{control_id}.md"
        page_path.parent.mkdir(parents=True, exist_ok=True)
        page_path.write_text(
            control_page(version, control, domain_positions[domain]),
            encoding="utf-8",
        )
        control_links.setdefault(domain, []).append(
            f"- [{control_id}: {text(control.get('title', control_id))}]"
            f"(./{domain_slug}/{control_id})"
        )

    index_lines = [
        "---",
        f"id: {version}",
        f"title: {yaml_string(f'Control catalog {version}')}",
        "sidebar_position: 1",
        "---",
        "",
        f"# Control catalog {version}",
        "",
        f"This reference contains {len(controls)} controls generated from `catalogs/{version}/github_controls.json`.",
        "",
        "Control content is generated from the versioned JSON catalog. After adding or updating a catalog, regenerate pages by running `npm run docs:generate` from the `docs/` directory.",
        "",
    ]
    for domain in sorted(control_links):
        index_lines.extend([f"## {text(domain)}", "", *control_links[domain], ""])

    index_path = version_root / "index.md"
    index_path.write_text("\n".join(index_lines), encoding="utf-8")
    return len(controls), index_path


def generate_latest_overview() -> tuple[str, int]:
    catalog_path = CATALOG_ROOT / "latest" / "github_controls.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    version = str(catalog.get("version", ""))
    controls = catalog.get("controls")
    if not isinstance(controls, list):
        raise ValueError(f"Catalog {catalog_path} does not contain a controls list.")

    mode_labels = {
        "automated": "Automated",
        "manual_or_hybrid": "Manual or hybrid",
    }
    mode_counts = Counter(
        control.get("automation", {}).get("mode", "unspecified")
        for control in controls
    )
    lines = [
        "---",
        'id: "latest"',
        'title: "Latest controls"',
        "sidebar_position: 1",
        "---",
        "",
        "# Latest controls",
        "",
        f"Current catalog version: **{version}** ({len(controls)} controls).",
        "",
        f"Automation coverage: **{mode_counts['automated']} automated** and **{mode_counts['manual_or_hybrid']} manual or hybrid**.",
        "",
        "Select a control ID to open its detailed, version-specific reference page.",
        "",
        "| Control ID | Domain | Name | Maturity state | Automation mode |",
        "| --- | --- | --- | --- | --- |",
    ]

    for control in controls:
        control_id = str(control["control_id"])
        domain = str(control.get("domain", "Uncategorized"))
        domain_slug = slugify(domain) or "uncategorized"
        title = table_cell(control.get("title", control_id))
        stage = table_cell(control.get("well_architected_stage", "Not assigned"))
        mode = control.get("automation", {}).get("mode", "unspecified")
        mode_label = mode_labels.get(mode, f"Unspecified ({mode})")
        lines.append(
            f"| [{table_cell(control_id)}](/controls/{version}/{domain_slug}/{control_id})"
            f" | {table_cell(domain)} | {title} | {stage} | {table_cell(mode_label)} |"
        )

    lines.append("")
    output_path = DOCS_ROOT / "controls" / "latest.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return version, len(controls)


def main() -> None:
    catalogs = versioned_catalogs()
    if not catalogs:
        raise SystemExit(f"No versioned catalogs found under {CATALOG_ROOT}.")

    versions = []
    for version, catalog_path in catalogs:
        count, _ = generate_version(version, catalog_path)
        versions.append((version, count))

    latest_version, latest_count = generate_latest_overview()
    index_lines = [
        "---",
        "id: controls",
        'title: "Versioned control catalog"',
        "sidebar_position: 4",
        "---",
        "",
        "# Versioned control catalog",
        "",
        "Browse controls by the catalog version used to define and evaluate them. Each version has its own reference pages; older definitions remain available when new catalog versions are added.",
        "",
        "`catalogs/latest/github_controls.json` is an alias to the current catalog and is not generated as a second documentation version.",
        "",
        f"- [Latest controls](/controls/latest) - version {latest_version}, {latest_count} controls",
    ]
    for version, count in versions:
        index_lines.append(f"- [Version {version}](/controls/{version}) - {count} controls")
    index_lines.append("")

    controls_index = DOCS_ROOT / "controls" / "index.md"
    controls_index.parent.mkdir(parents=True, exist_ok=True)
    controls_index.write_text("\n".join(index_lines), encoding="utf-8")

    total = sum(count for _, count in versions)
    print(f"Generated {total} control pages across {len(versions)} catalog version(s).")
    for version, count in versions:
        print(f"  {version}: {count} controls")


if __name__ == "__main__":
    main()
