#!/usr/bin/env python3
"""Read V2Fly domain-list-community lists for scripts/sync_upstream.py.

The reader intentionally stays small: it expands includes and affiliations,
honours include attribute filters, strips rule metadata, detects include
cycles, and removes exact duplicates. Canonical output is written by
sync_upstream.py; this module has no CLI of its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


RULE_PREFIXES = {
    "domain": "DOMAIN-SUFFIX",
    "full": "DOMAIN",
    "keyword": "DOMAIN-KEYWORD",
    "regexp": "DOMAIN-REGEX",
}


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    attributes: frozenset[str]


class V2FlyConverter:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._affiliations: dict[str, list[Rule]] | None = None

    def read(self, list_name: str) -> list[Rule]:
        return self._read(list_name, ())

    def _read(self, list_name: str, stack: tuple[str, ...]) -> list[Rule]:
        if list_name in stack:
            chain = " -> ".join((*stack, list_name))
            raise ValueError(f"V2Fly include cycle: {chain}")

        source = self.data_dir / list_name
        affiliated = self._affiliated_rules().get(list_name.lower(), [])
        if not source.is_file() and not affiliated:
            raise FileNotFoundError(f"V2Fly list not found: {source}")

        rules: list[Rule] = list(affiliated)
        raw_lines = source.read_text(encoding="utf-8").splitlines() if source.is_file() else []
        for raw_line in raw_lines:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            body, attributes, _affiliations = _split_metadata(line)
            if body.startswith("include:"):
                included_name = body.removeprefix("include:").strip()
                included = self._read(included_name, (*stack, list_name))
                rules.extend(rule for rule in included if _matches(rule, attributes))
                continue

            prefix, separator, value = body.partition(":")
            if separator and prefix in RULE_PREFIXES:
                kind = prefix
            else:
                kind = "domain"
                value = body
            value = value.strip()
            if value:
                rules.append(Rule(kind, value, frozenset(attributes)))
        return dedupe(rules)

    def _affiliated_rules(self) -> dict[str, list[Rule]]:
        """Index direct rules added to other lists with V2Fly's ``&target``."""
        if self._affiliations is not None:
            return self._affiliations

        affiliations: dict[str, list[Rule]] = {}
        for source in sorted(path for path in self.data_dir.iterdir() if path.is_file()):
            for raw_line in source.read_text(encoding="utf-8").splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                body, attributes, targets = _split_metadata(line)
                if body.startswith("include:") or not targets:
                    continue

                prefix, separator, value = body.partition(":")
                if separator and prefix in RULE_PREFIXES:
                    kind = prefix
                else:
                    kind = "domain"
                    value = body
                value = value.strip()
                if not value:
                    continue

                rule = Rule(kind, value, frozenset(attributes))
                for target in targets:
                    affiliations.setdefault(target, []).append(rule)

        self._affiliations = {
            target: dedupe(rules) for target, rules in affiliations.items()
        }
        return self._affiliations


def _split_metadata(line: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    parts = line.split()
    body: list[str] = []
    attributes: list[str] = []
    affiliations: list[str] = []
    for part in parts:
        if part.startswith("@"):
            attributes.append(part[1:].lower())
        elif part.startswith("&"):
            affiliations.append(part[1:].lower())
        else:
            body.append(part)
    return " ".join(body), tuple(attributes), tuple(affiliations)


def _matches(rule: Rule, selectors: tuple[str, ...]) -> bool:
    for selector in selectors:
        if selector.startswith("-"):
            if selector[1:] in rule.attributes:
                return False
        elif selector not in rule.attributes:
            return False
    return True


def dedupe(rules: list[Rule]) -> list[Rule]:
    seen: set[tuple[str, str]] = set()
    result: list[Rule] = []
    for rule in rules:
        key = (rule.kind, rule.value.lower())
        if key not in seen:
            seen.add(key)
            result.append(rule)
    return result


def mihomo_lines(rules: list[Rule]) -> list[str]:
    return [f"{RULE_PREFIXES[rule.kind]},{rule.value}" for rule in rules]
