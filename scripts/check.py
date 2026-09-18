#!/usr/bin/env python3
"""Run the small, repository-local checks used by zhbcn/Rules."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml


REPO_MARKERS = (
    "/zhbcn/Rules/main/",
    "/zhbcn/Rules/refs/heads/main/",
    "/zhbcn/Rules/raw/refs/heads/main/",
    "/zhbcn/Rules/raw/main/",
)


def repo_path_from_url(url: str) -> str | None:
    path = unquote(urlparse(url).path)
    for marker in REPO_MARKERS:
        if marker in path:
            return path.split(marker, 1)[1]
    return None


def duplicate_values(document: object) -> list[str]:
    duplicates: list[str] = []
    if not isinstance(document, dict):
        return ["top level is not a mapping"]
    for key, value in document.items():
        if not isinstance(value, list):
            continue
        seen: set[str] = set()
        for item in value:
            marker = str(item).strip().lower()
            if marker in seen:
                duplicates.append(f"{key}: {item}")
            seen.add(marker)
    return duplicates


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, action="append", default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    checked = 0

    for area in (root / "Ruleset" / "Mihomo", root / "Ruleset" / "Egern"):
        for path in sorted(area.rglob("*.yaml")):
            checked += 1
            try:
                document = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
            except Exception as exc:
                errors.append(f"YAML {path.relative_to(root)}: {exc}")
                continue
            for duplicate in duplicate_values(document):
                errors.append(f"DUPLICATE {path.relative_to(root)}: {duplicate}")

    url_pattern = re.compile(r"https://(?:raw\.githubusercontent\.com|github\.com)/zhbcn/Rules/[^\s\"']+")
    for config in args.config:
        try:
            text = config.read_text(encoding="utf-8-sig")
            yaml.safe_load(text)
        except Exception as exc:
            errors.append(f"CONFIG {config}: {exc}")
            continue
        for url in url_pattern.findall(text):
            relative = repo_path_from_url(url.rstrip("}),]"))
            if relative and not (root / relative).is_file():
                errors.append(f"MISSING {config.name}: {relative}")

    if errors:
        print("\n".join(errors))
        print(f"FAILED: {len(errors)} issue(s); checked {checked} rule files")
        return 1
    print(f"OK: checked {checked} rule files and {len(args.config)} config file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
