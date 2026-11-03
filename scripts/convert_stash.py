#!/usr/bin/env python3
"""Generate native Stash text rule sets from the maintained Mihomo rules."""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Callable

import yaml


GENERATED = "# GENERATED-BY: scripts/convert_stash.py"
CLASSICAL_TYPES = {
    "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD", "IP-ASN", "GEOIP",
    "NETWORK", "DST-PORT", "SRC-IP", "SRC-PORT", "AND", "OR", "NOT",
}
PROCESS_TYPES = {"PROCESS-NAME", "PROCESS-PATH"}
KINDS = {
    "Domain": ("domain", False),
    "IP": ("ipcidr", False),
    "IPNoResolve": ("ipcidr", True),
    "Classical": ("classical", False),
}


@dataclass(frozen=True)
class Part:
    name: str
    behavior: str
    no_resolve: bool
    payload: tuple[str, ...]

    @property
    def filename(self) -> str:
        return self.name + ".list"


def split_rules(rules: list[str]) -> tuple[list[Part], list[str]]:
    """Keep contiguous blocks in order, including DNS-resolution boundaries."""
    blocks: list[tuple[str, list[str]]] = []
    omitted: list[str] = []
    for rule in rules:
        kind, separator, value = rule.partition(",")
        if not separator or not value:
            raise ValueError(f"Malformed source rule: {rule}")
        if kind in PROCESS_TYPES:
            omitted.append(rule)
            continue
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            if "," in value or value.startswith((".", "*", "+")):
                raise ValueError(f"Unsupported domain expression: {rule}")
            target = "Domain"
            rendered = "+." + value if kind == "DOMAIN-SUFFIX" else value
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            fields = value.split(",")
            if len(fields) > 2 or (len(fields) == 2 and fields[1] != "no-resolve"):
                raise ValueError(f"Unsupported IP options: {rule}")
            network = ipaddress.ip_network(fields[0], strict=False)
            if network.version != (4 if kind == "IP-CIDR" else 6):
                raise ValueError(f"Wrong IP family: {rule}")
            target = "IPNoResolve" if len(fields) == 2 else "IP"
            rendered = str(network)
        elif kind in CLASSICAL_TYPES:
            nested = re.findall(r"\(\(?([A-Z][A-Z0-9-]*),", rule)
            allowed = CLASSICAL_TYPES | {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
            if any(child not in allowed for child in nested):
                raise ValueError(f"Unsupported nested Stash condition: {rule}")
            target, rendered = "Classical", rule
        else:
            raise ValueError(f"Unreviewed Stash rule type: {kind}")
        if not blocks or blocks[-1][0] != target:
            blocks.append((target, []))
        blocks[-1][1].append(rendered)

    counters: Counter[str] = Counter()
    parts = []
    for kind, values in blocks:
        counters[kind] += 1
        name = kind + (str(counters[kind]) if counters[kind] > 1 else "")
        behavior, no_resolve = KINDS[kind]
        parts.append(Part(name, behavior, no_resolve, tuple(values)))
    if not parts:
        raise ValueError("Source has no rules usable on Stash iOS")
    return parts, omitted


def provider_behavior(relative: Path) -> str:
    match = re.fullmatch(r"(Domain|IPNoResolve|IP|Classical)(?:[2-9]|[1-9][0-9]+)?", relative.stem)
    if relative.suffix != ".list" or not match:
        raise ValueError(f"Invalid native Stash component: {relative}")
    return KINDS[match[1]][0]


def render_service(text: str, relative: Path) -> tuple[dict[Path, str], list[Part]]:
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or set(document) != {"payload"} or not isinstance(document["payload"], list):
        raise ValueError(f"Expected a Mihomo payload list: {relative}")
    parts, omitted = split_rules(document["payload"])
    headers = []
    for line in text.splitlines():
        if line.startswith("#"):
            headers.append(line)
        elif line.strip():
            break
    common = [*headers, GENERATED, f"# SOURCE-RULESET: Ruleset/Mihomo/{relative.as_posix()}"]
    common.extend(f"# PLATFORM-OMITTED (iOS process matching unavailable): {rule}" for rule in omitted)
    output = {}
    for part in parts:
        flags = f"# STASH-BEHAVIOR: {part.behavior}; format=text; no-resolve={str(part.no_resolve).lower()}"
        output[relative.with_suffix("") / part.filename] = "\n".join([*common, flags, "", *part.payload, ""])
    return output, parts


def expected_files(root: Path) -> dict[Path, str]:
    source = root / "Ruleset" / "Mihomo"
    output = {}
    for path in sorted(source.rglob("*.yaml")):
        files, _ = render_service(path.read_text(encoding="utf-8-sig"), path.relative_to(source))
        output.update(files)
    return output


def validate_text(text: str, behavior: str) -> list[str]:
    errors = []
    payload = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if not payload:
        errors.append("empty native rule set")
    if len(payload) != len(set(payload)):
        errors.append("duplicate native rule")
    for line in payload:
        if behavior == "domain":
            value = line.removeprefix("+.")
            if not value or re.search(r"[\s,/:*?]", value) or value.startswith((".", "+")):
                errors.append(f"invalid exact/suffix domain: {line}")
        elif behavior == "ipcidr":
            try:
                ipaddress.ip_network(line, strict=True)
            except ValueError:
                errors.append(f"invalid canonical CIDR: {line}")
        elif behavior == "classical":
            if line.split(",", 1)[0] not in CLASSICAL_TYPES:
                errors.append(f"invalid native classical condition: {line}")
        else:
            errors.append(f"unknown native behavior: {behavior}")
    return errors


def check_stash_pairs(root: Path, errors: list[str]) -> int:
    target = root / "Ruleset" / "Stash"
    try:
        expected = expected_files(root)
    except (ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        errors.append(f"STASH GENERATION: {exc}")
        return 0
    actual = {path.relative_to(target) for path in target.rglob("*.list")}
    for relative in sorted(set(expected) - actual):
        errors.append(f"PAIR MISSING Stash/{relative.as_posix()}")
    for relative in sorted(actual - set(expected)):
        errors.append(f"PAIR EXTRA Stash/{relative.as_posix()}")
    for relative in sorted(actual & set(expected)):
        text = (target / relative).read_text(encoding="utf-8-sig")
        errors.extend(f"Stash/{relative.as_posix()}: {error}" for error in validate_text(text, provider_behavior(relative)))
        if text != expected[relative]:
            errors.append(f"PAIR MISMATCH Stash/{relative.as_posix()}: regenerate rules")
    return len(actual)


def _map_nested_rule_sets(rule: str, resolve: Callable[[str, list[str]], str]) -> str:
    """Refresh provider references inside logical client rules, preserving grouping."""
    if not rule.startswith(("AND,", "OR,", "NOT,")) or "RULE-SET," not in rule:
        return rule

    def children(value: str) -> list[str]:
        if not value.startswith("(") or not value.endswith(")"):
            raise ValueError(f"Malformed logical rule: {rule}")
        value = value[1:-1]
        rows = []
        start = depth = 0
        for index, char in enumerate(value):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "," and depth == 0:
                rows.append(value[start:index].strip()[1:-1])
                start = index + 1
        rows.append(value[start:].strip()[1:-1])
        return rows

    def visit(expression: str) -> str:
        kind, _, value = expression.partition(",")
        if kind == "RULE-SET":
            fields = value.split(",")
            return resolve(fields[0], fields[1:])
        if kind not in {"AND", "OR", "NOT"}:
            return expression
        rows = []
        for child in children(value):
            transformed = visit(child)
            if kind in {"AND", "OR"} and transformed.startswith(kind + ","):
                rows.extend(children(transformed.partition(",")[2]))
            else:
                rows.append(transformed)
        rows = list(dict.fromkeys(rows))
        if kind in {"AND", "OR"} and len(rows) == 1:
            return rows[0]
        return kind + ",((" + "),(".join(rows) + "))"

    expression, policy = rule.rsplit(",", 1)
    options = []
    while policy in {"no-resolve", "no-track"}:
        options.insert(0, policy)
        expression, policy = expression.rsplit(",", 1)
    return ",".join([visit(expression), policy, *options])


def _restore_native_references(document: dict) -> dict:
    """Recover service references so an already-native profile can be refreshed."""
    result = deepcopy(document)
    providers = {}
    aliases = {}
    for name, body in document.get("rule-providers", {}).items():
        url = body.get("url", "")
        marker = "/Ruleset/Stash/"
        if marker not in url:
            if name in providers:
                raise ValueError(f"Conflicting provider name: {name}")
            providers[name] = deepcopy(body)
            continue
        prefix, native_path = url.split(marker, 1)
        path = Path(native_path)
        provider_behavior(path)
        suffix = "-" + path.stem
        if not name.endswith(suffix):
            raise ValueError(f"Review custom native provider alias before updating: {name}")
        base = name[:-len(suffix)]
        source = path.parent.parent / (path.parent.name + ".yaml")
        restored = {"url": prefix + "/Ruleset/Mihomo/" + source.as_posix()}
        for key in ("interval", "headers"):
            if key in body:
                restored[key] = deepcopy(body[key])
        if "path" in body:
            restored["path"] = "./rules/" + source.as_posix()
        if base in providers and providers[base] != restored:
            raise ValueError(f"Conflicting native component settings: {base}")
        providers[base] = restored
        aliases[name] = (base, path.stem)
    result["rule-providers"] = providers

    def restore_reference(name: str, flags: list[str]) -> str:
        if name in aliases:
            base, part = aliases[name]
            if part.startswith("IPNoResolve"):
                flags = [flag for flag in flags if flag != "no-resolve"]
            name = base
        return ",".join(["RULE-SET", name, *flags])

    rules = []
    index = 0
    original = document.get("rules", [])
    while index < len(original):
        fields = original[index].split(",")
        if fields[0] != "RULE-SET" or fields[1] not in aliases:
            rules.append(_map_nested_rule_sets(original[index], restore_reference))
            index += 1
            continue
        base = aliases[fields[1]][0]
        policy = fields[2]
        flags = []
        while index < len(original):
            fields = original[index].split(",")
            if fields[0] != "RULE-SET" or fields[1] not in aliases or aliases[fields[1]][0] != base or fields[2] != policy:
                break
            part_name = aliases[fields[1]][1]
            for flag in fields[3:]:
                if flag == "no-resolve" and part_name.startswith("IPNoResolve"):
                    continue
                if flag not in flags:
                    flags.append(flag)
            index += 1
        rules.append(",".join(["RULE-SET", base, policy, *flags]))
    result["rules"] = rules

    dns = result.get("dns", {})
    policy = {}
    for key, value in dns.get("nameserver-policy", {}).items():
        alias = key.removeprefix("rule-set:")
        restored = "rule-set:" + aliases[alias][0] if key.startswith("rule-set:") and alias in aliases else key
        if restored in policy and policy[restored] != value:
            raise ValueError(f"Review differing native DNS component policies: {restored}")
        policy[restored] = value
    if "nameserver-policy" in dns:
        dns["nameserver-policy"] = policy
    return result


def adapt_config(document: dict, root: Path) -> dict:
    """Prepare a client configuration after the generated resources are published."""
    if any("/Ruleset/Stash/" in body.get("url", "") for body in document.get("rule-providers", {}).values()):
        document = _restore_native_references(document)
    result = deepcopy(document)
    providers = {}
    replacements = {}
    for name, provider in document.get("rule-providers", {}).items():
        url = provider.get("url", "")
        marker = "/Ruleset/Mihomo/"
        if marker not in url:
            providers[name] = deepcopy(provider)
            continue
        prefix, source_path = url.split(marker, 1)
        relative = Path(source_path)
        source = root / "Ruleset" / "Mihomo" / relative
        _, parts = render_service(source.read_text(encoding="utf-8-sig"), relative)
        replacements[name] = []
        for part in parts:
            target_name = name + "-" + part.name
            if target_name in document["rule-providers"] or target_name in providers:
                raise ValueError(f"Stash provider name collision: {target_name}")
            native = relative.with_suffix("") / part.filename
            body = {"behavior": part.behavior, "format": "text", "url": prefix + "/Ruleset/Stash/" + native.as_posix()}
            for key in ("interval", "headers"):
                if key in provider:
                    body[key] = deepcopy(provider[key])
            if "path" in provider:
                body["path"] = "./rules/stash/" + native.as_posix()
            providers[target_name] = body
            replacements[name].append((target_name, part))
    result["rule-providers"] = providers

    def expand_reference(name: str, flags: list[str]) -> str:
        if name not in replacements:
            return ",".join(["RULE-SET", name, *flags])
        rows = []
        for target, part in replacements[name]:
            options = [flag for flag in flags if flag != "no-resolve" or part.behavior != "domain"]
            if part.no_resolve and "no-resolve" not in options:
                options.append("no-resolve")
            rows.append(",".join(["RULE-SET", target, *options]))
        return rows[0] if len(rows) == 1 else "OR,((" + "),(".join(rows) + "))"

    rules = []
    for rule in document.get("rules", []):
        fields = rule.split(",")
        if fields[0] != "RULE-SET" or fields[1] not in replacements:
            rules.append(_map_nested_rule_sets(rule, expand_reference))
            continue
        if len(fields) < 3 or any(flag not in {"no-resolve", "no-track"} for flag in fields[3:]):
            raise ValueError(f"Unsupported RULE-SET options: {rule}")
        for name, part in replacements[fields[1]]:
            options = [flag for flag in fields[3:] if flag != "no-resolve" or part.behavior != "domain"]
            if part.no_resolve and "no-resolve" not in options:
                options.append("no-resolve")
            rules.append(",".join(["RULE-SET", name, fields[2], *options]))
    result["rules"] = rules

    dns = result.get("dns", {})
    policy = {}
    for key, value in dns.get("nameserver-policy", {}).items():
        source_name = key.removeprefix("rule-set:")
        if key.startswith("rule-set:") and source_name in replacements:
            for name, part in replacements[source_name]:
                if part.behavior == "domain" or any(re.search(r"(?:^|\()DOMAIN(?:-|,)", item) for item in part.payload):
                    policy["rule-set:" + name] = deepcopy(value)
        else:
            policy[key] = value
    if "nameserver-policy" in dns:
        dns["nameserver-policy"] = policy
    if any(value.startswith("rule-set:") and value[9:] in replacements for value in dns.get("fake-ip-filter", [])):
        raise ValueError("Review rule-set fake-ip-filter references before migrating this configuration")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Existing local Stash configuration to migrate")
    parser.add_argument("--output", type=Path, help="Separate candidate configuration; new URLs must be published before use")
    args = parser.parse_args()
    if bool(args.config) != bool(args.output):
        parser.error("--config and --output must be supplied together")
    root = Path(__file__).resolve().parents[1]
    target = root / "Ruleset" / "Stash"
    expected = expected_files(root)
    # Only remove stale files produced by this generator, never an unknown file.
    for path in sorted(target.rglob("*.list")):
        if path.relative_to(target) not in expected:
            if GENERATED not in path.read_text(encoding="utf-8-sig").splitlines():
                raise ValueError(f"Refusing to remove a non-generated file: {path}")
            path.unlink()
    for relative, text in expected.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text(encoding="utf-8-sig") != text:
            path.write_text(text, encoding="utf-8", newline="\n")
    if args.config:
        if args.config.resolve() == args.output.resolve():
            parser.error("Use a separate --output candidate; do not overwrite the active configuration")
        document = yaml.safe_load(args.config.read_text(encoding="utf-8-sig"))
        migrated = adapt_config(document, root)
        header = "# Stash native candidate: publish Ruleset/Stash resources before importing.\n"
        args.output.write_text(header + yaml.safe_dump(migrated, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")
    print(f"Generated {len(expected)} native Stash rule components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
