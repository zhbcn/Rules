#!/usr/bin/env python3
"""Convert V2Fly domain lists to Mihomo and Egern rule-set YAML.

The converter intentionally stays small: it expands includes recursively,
honours include attribute filters, strips rule attributes/affiliations from
the emitted rules, detects include cycles, and removes exact duplicates.
"""

from __future__ import annotations

import argparse
import re
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

    def read(self, list_name: str) -> list[Rule]:
        return self._read(list_name, ())

    def _read(self, list_name: str, stack: tuple[str, ...]) -> list[Rule]:
        if list_name in stack:
            chain = " -> ".join((*stack, list_name))
            raise ValueError(f"V2Fly include cycle: {chain}")

        source = self.data_dir / list_name
        if not source.is_file():
            raise FileNotFoundError(f"V2Fly list not found: {source}")

        rules: list[Rule] = []
        for raw_line in source.read_text(encoding="utf-8").splitlines():
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


def egern_sets(rules: list[Rule]) -> dict[str, list[str]]:
    keys = {
        "full": "domain_set",
        "keyword": "domain_keyword_set",
        "domain": "domain_suffix_set",
        "regexp": "domain_regex_set",
    }
    result: dict[str, list[str]] = {}
    for rule in rules:
        result.setdefault(keys[rule.kind], []).append(rule.value)
    return result


def _yaml_scalar(value: str) -> str:
    # YAML treats a leading '*', '&', '!' and several other characters as
    # syntax, so only emit an unquoted scalar when it begins alphanumerically.
    yaml_words = {"null", "true", "false", "yes", "no", "on", "off", "~"}
    if (
        value.lower() not in yaml_words
        and not re.fullmatch(r"[-+]?\d+(?:\.\d+)?", value)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._*+/@-]*", value)
    ):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_mihomo(name: str, rules: list[Rule], source_lists: list[str]) -> str:
    header = _header(name, "v2fly/domain-list-community", source_lists)
    lines = [*header, "", "payload:"]
    lines.extend(f"  - {_yaml_scalar(rule)}" for rule in mihomo_lines(rules))
    return "\n".join(lines) + "\n"


def render_egern(name: str, rules: list[Rule], source_lists: list[str]) -> str:
    lines = [*_header(name, "v2fly/domain-list-community", source_lists)]
    for key, values in egern_sets(rules).items():
        lines.extend(["", f"{key}:"])
        lines.extend(f"  - {_yaml_scalar(value)}" for value in values)
    return "\n".join(lines) + "\n"


def _header(name: str, source: str, source_lists: list[str]) -> list[str]:
    return [
        f"# NAME: {name}",
        f"# SOURCE: {source}",
        f"# SOURCE-LIST: {', '.join(source_lists)}",
        "# FALLBACK: blackmatrix7/ios_rule_script",
        "# MAINTAINED-BY: zhbcn/Rules",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="V2Fly data directory")
    parser.add_argument("--list", dest="lists", action="append", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--egern", type=Path, required=True)
    args = parser.parse_args()

    converter = V2FlyConverter(args.data)
    rules: list[Rule] = []
    for list_name in args.lists:
        rules.extend(converter.read(list_name))
    rules = dedupe(rules)

    args.mihomo.parent.mkdir(parents=True, exist_ok=True)
    args.egern.parent.mkdir(parents=True, exist_ok=True)
    args.mihomo.write_text(render_mihomo(args.name, rules, args.lists), encoding="utf-8")
    args.egern.write_text(render_egern(args.name, rules, args.lists), encoding="utf-8")
    print(f"{args.name}: {len(rules)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
