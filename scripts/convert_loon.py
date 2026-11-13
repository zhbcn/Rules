#!/usr/bin/env python3
"""Generate policy-free Loon routing subscriptions, offline, from reviewed Egern sources.

Syntax: https://nsloon.app/en/docs/Rule/ and Loon0x00/LoonExampleConfig.
The manifest contains public conditions only. It never contains subscriptions or policies.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import itertools
import json
from pathlib import Path
import re

import yaml

if __package__:
    from .convert_quantumultx import QX_REGEX_ADAPTATIONS
else:
    from convert_quantumultx import QX_REGEX_ADAPTATIONS


TYPES = {
    "domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX",
    "domain_keyword": "DOMAIN-KEYWORD", "domain_wildcard": "DOMAIN-WILDCARD",
    "domain_regex": "DOMAIN-REGEX", "ip_cidr": "IP-CIDR", "ip_cidr6": "IP-CIDR6",
    "asn": "IP-ASN", "protocol": "PROTOCOL", "geoip": "GEOIP",
    "dest_port": "DEST-PORT", "src_port": "SRC-PORT",
    "url_regex": "URL-REGEX", "user_agent": "USER-AGENT",
    "process_name": "PROCESS-NAME", "process_path": "PROCESS-PATH",
}
IP_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
PUBLIC_PREFIX = "https://raw.githubusercontent.com/zhbcn/Rules/main/Ruleset/Egern/"


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str = ""
    children: tuple[Rule, ...] = ()
    no_resolve: bool = False


class SourceLoader(yaml.SafeLoader):
    pass


def _tag(loader: SourceLoader, suffix: str, node: yaml.Node) -> dict:
    if not isinstance(node, yaml.MappingNode):
        raise ValueError("Egern logical child must be a tagged mapping")
    return {suffix: loader.construct_mapping(node)}


SourceLoader.add_multi_constructor("!", _tag)


def load_yaml(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8-sig"), Loader=SourceLoader)


def safe_relative(value: str, suffix: str) -> Path:
    path = Path(value)
    if path.anchor or ".." in path.parts or path.suffix != suffix or ":" in value:
        raise ValueError("Invalid relative resource path")
    return path


def source_expression(rule: dict) -> object:
    """Strip client-only metadata; callers choose which private conditions may be reviewed."""
    if len(rule) != 1:
        raise ValueError("Expected one Egern condition")
    kind, spec = next(iter(rule.items()))
    if spec.get("disabled"):
        raise ValueError("Disabled source requires manifest review")
    if kind in {"rule_set", "proxy_rule_set"}:
        url = spec["match"]
        if not url.startswith(PUBLIC_PREFIX) or "?" in url or "#" in url:
            raise ValueError("Only local maintained Egern resources are accepted")
        return safe_relative(url[len(PUBLIC_PREFIX):], ".yaml").as_posix()
    if kind in {"and", "or", "not"}:
        parts = [source_expression(x) for x in spec["match"]]
        return parts if kind == "or" else {kind: parts}
    if kind not in TYPES:
        raise ValueError("Unsupported source condition type: " + kind)
    result = {kind: spec["match"]}
    if spec.get("no_resolve"):
        result["no_resolve"] = True
    return result


class Converter:
    def __init__(self, root: Path):
        self.root = root
        self.cache: dict[str, Rule] = {}
        self.notes: list[str] = []

    def regex(self, pattern: str, suffixes: set[str]) -> Rule:
        covered = {
            r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$": "googlevideo.com",
            r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.xn--ngstr-lra8j\.com$": "xn--ngstr-lra8j.com",
        }
        if covered.get(pattern) in suffixes:
            self.notes.append("COVERED: same-source suffix covers " + pattern)
            return Rule("OR")
        if pattern == r"^speed\.(coe|open)\.ad\.[a-z]{2":
            # Actual Egern source is truncated. '{' cannot occur in an ASCII DNS name.
            self.notes.append("SOURCE-WARNING: truncated Speedtest source regex; no valid DNS-name match: " + pattern)
            return Rule("OR")
        if pattern in QX_REGEX_ADAPTATIONS:
            self.notes.append("LOON-ADAPTED: reuse approved dynamic-ID wildcard scope; non-digits/dots allowed: " + pattern)
            globs = QX_REGEX_ADAPTATIONS[pattern]
        elif pattern == r"^.+-mihayo\.akamaized\.net$":
            globs = ["?*-mihayo.akamaized.net"]
        elif pattern == r".+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$":
            globs = ["?*.awsdns-cn-[0-9][0-9]." + t for t in ("biz", "com", "net", "top")]
        elif pattern == r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$":
            globs = ["?*.awsdns-cn-[0-9][a-e0-9].cn"]
        elif pattern == r"^hses[1-7]?\.akamaized\.net$":
            return Rule("OR", children=tuple(Rule("DOMAIN", "hses" + n + ".akamaized.net") for n in ("", *map(str, range(1, 8)))))
        elif pattern == r"^epicgames-download\d\.akamaized\.net$":
            return Rule("OR", children=tuple(Rule("DOMAIN", f"epicgames-download{i}.akamaized.net") for i in range(10)))
        else:
            for prefix in ("apiproxy-device-prod-nlb", "apiproxy-website-nlb-prod", r"dualstack\.apiproxy", r"dualstack\.ichnaea-web"):
                if pattern == r"(^|\.)" + prefix + r"-.+\.amazonaws\.com$":
                    host = prefix.replace(r"\.", ".") + "-?*.amazonaws.com"
                    globs = [host, "*." + host]
                    break
            else:
                raise ValueError("Unreviewed DOMAIN-REGEX; explicit adaptation required")
        return Rule("OR", children=tuple(Rule("DOMAIN-WILDCARD", x) for x in globs))

    def atom(self, kind: str, value: object, no_resolve: bool = False,
             suffixes: set[str] | None = None) -> Rule:
        if kind in {"and", "or", "not"}:
            if not isinstance(value, list):
                raise ValueError("Logical source must contain a list")
            children = tuple(self.expression(source_expression(x)) for x in value)
            def inherited(rule: Rule) -> Rule:
                return Rule(rule.kind, rule.value, tuple(inherited(x) for x in rule.children),
                            rule.no_resolve or (no_resolve and rule.kind in IP_TYPES))
            return inherited(Rule(kind.upper(), children=children))
        if kind == "domain_regex":
            return self.regex(str(value), suffixes or set())
        native = TYPES[kind]
        text = str(value)
        if native in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(text, strict=False)
            if network.version != (4 if native == "IP-CIDR" else 6):
                raise ValueError("Wrong IP family")
            text = str(network)
        if native in {"PROTOCOL", "GEOIP"}:
            text = text.upper()
        return Rule(native, text, no_resolve=no_resolve and native in IP_TYPES)

    def resource(self, relative: str) -> Rule:
        path = safe_relative(relative, ".yaml")
        if relative not in self.cache:
            document = load_yaml(self.root / "Ruleset" / "Egern" / path)
            children = []
            for kind, values in document.items():
                if kind == "no_resolve":
                    continue
                if not kind.endswith("_set") or kind[:-4] not in TYPES.keys() | {"and", "or", "not"}:
                    raise ValueError("Unreviewed Egern set type: " + kind)
                if kind == "url_regex_set":
                    self.notes.append("URL-SCOPE: path rules need a visible HTTP URL; HTTPS path matching is not verified without MITM, which this configuration does not enable")
                for value in values:
                    children.append(self.atom(kind[:-4], value, bool(document.get("no_resolve")), set(document.get("domain_suffix_set", []))))
            self.cache[relative] = Rule("OR", children=tuple(children))
        return self.cache[relative]

    def expression(self, expression: object) -> Rule:
        if isinstance(expression, str):
            return self.resource(expression)
        if isinstance(expression, list):
            return Rule("OR", children=tuple(self.expression(x) for x in expression))
        if not isinstance(expression, dict):
            raise ValueError("Invalid manifest expression")
        parts = set(expression) - {"no_resolve"}
        if len(parts) != 1:
            raise ValueError("Ambiguous manifest condition")
        kind = next(iter(parts))
        if kind in {"and", "or", "not"}:
            children = tuple(self.expression(x) for x in expression[kind])
            if not children or (kind == "not" and len(children) != 1):
                raise ValueError("Invalid logical arity")
            return Rule(kind.upper(), children=children)
        if kind not in TYPES:
            raise ValueError("Unreviewed manifest type: " + kind)
        return self.atom(kind, expression[kind], expression.get("no_resolve", False))


def disjuncts(rule: Rule) -> list[Rule]:
    """Distribute AND over OR, preserving protocol/domain conjunctions and source order."""
    if rule.kind == "OR":
        return [child for item in rule.children for child in disjuncts(item)]
    if rule.kind == "AND":
        return [Rule("AND", children=tuple(items)) for items in itertools.product(*(disjuncts(x) for x in rule.children))]
    return [rule]


def format_rule(rule: Rule) -> str:
    if rule.kind in {"AND", "OR", "NOT"}:
        return rule.kind + ",(" + ",".join("(" + format_rule(x) + ")" for x in rule.children) + ")"
    return rule.kind + "," + rule.value + (",no-resolve" if rule.no_resolve else "")


def split_fields(text: str) -> list[str]:
    fields, start, depth, quoted, escaped = [], 0, 0, False, False
    for i, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted:
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
        if quoted:
            continue
        depth += (char == "(") - (char == ")")
        if depth < 0:
            raise ValueError("Unbalanced logical rule")
        if char == "," and depth == 0:
            fields.append(text[start:i].strip())
            start = i + 1
    if depth or quoted:
        raise ValueError("Unterminated field")
    return fields + [text[start:].strip()]


def parse_native(text: str) -> Rule:
    parts = split_fields(text)
    kind = parts[0]
    if kind in {"AND", "OR", "NOT"}:
        if len(parts) != 2 or not parts[1].startswith("(") or not parts[1].endswith(")"):
            raise ValueError("Invalid logical rule")
        raw = split_fields(parts[1][1:-1])
        if not raw or any(not (x.startswith("(") and x.endswith(")")) for x in raw) or (kind == "NOT" and len(raw) != 1):
            raise ValueError("Invalid logical children")
        return Rule(kind, children=tuple(parse_native(x[1:-1]) for x in raw))
    if kind not in set(TYPES.values()) - {"DOMAIN-REGEX"} or len(parts) not in {2, 3} or not parts[1]:
        raise ValueError("Invalid native condition")
    nr = len(parts) == 3
    if nr and (parts[2] != "no-resolve" or kind not in IP_TYPES):
        raise ValueError("Invalid no-resolve option")
    if kind in {"IP-CIDR", "IP-CIDR6"}:
        network = ipaddress.ip_network(parts[1], strict=False)
        if network.version != (4 if kind == "IP-CIDR" else 6):
            raise ValueError("Wrong native IP family")
    if kind == "PROTOCOL" and parts[1] not in {"HTTP", "HTTPS", "TCP", "QUIC", "STUN", "UDP"}:
        raise ValueError("Unknown protocol")
    return Rule(kind, parts[1], no_resolve=nr)


def manifest(root: Path) -> list[dict]:
    document = json.loads((root / "scripts" / "loon_resources.json").read_text(encoding="utf-8"))
    if document["version"] != 1:
        raise ValueError("Unsupported manifest version")
    resources = document["resources"]
    indices = [x["source_index"] for x in resources]
    paths = [x["file"] for x in resources]
    if indices != sorted(set(indices)) or len(paths) != len(set(paths)):
        raise ValueError("Duplicate or unordered routing manifest")
    for resource in resources:
        safe_relative(resource["file"], ".list")
    return resources


def expected_files(root: Path) -> dict[Path, str]:
    output = {}
    for item in manifest(root):
        converter = Converter(root)
        rules = list(dict.fromkeys(format_rule(x) for x in disjuncts(converter.expression(item["expression"]))))
        if not rules:
            raise ValueError("Empty Loon resource")
        notes = list(dict.fromkeys(converter.notes))
        status = "ADAPTED" if any(x.startswith("LOON-ADAPTED") for x in notes) else "NATIVE-SYNTAX"
        headers = ["# GENERATED-BY: scripts/convert_loon.py", "# LOON-COMPAT: " + status,
                   "# Policy-free native Loon rules; bind policy in [Remote Rule]. Build 1008+.",
                   "# DOMAIN rules precede IP evaluation in Loon; not a runtime equivalence claim."]
        headers += ["# SOURCE-RULESET: Ruleset/Egern/" + x for x in sorted(converter.cache)]
        headers += ["# " + x for x in notes]
        output[Path(item["file"])] = "\n".join([*headers, "", *rules, ""])
    return output


def check_loon_pairs(root: Path, errors: list[str]) -> int:
    try:
        expected = expected_files(root)
    except (ValueError, KeyError, OSError) as exc:
        errors.append("LOON generation: " + str(exc))
        return 0
    area = root / "Ruleset" / "Loon"
    actual = {path.relative_to(area) for path in area.rglob("*.list")}
    for relative in sorted(actual | set(expected)):
        path = area / relative
        if relative not in expected or not path.is_file() or path.read_text(encoding="utf-8-sig") != expected[relative]:
            errors.append("LOON stale/missing/extra: " + relative.as_posix())
            continue
        for number, line in enumerate(expected[relative].splitlines(), 1):
            if line and not line.startswith("#"):
                try:
                    parse_native(line)
                except ValueError:
                    errors.append(f"LOON invalid native grammar: {relative}:{number}")
    return len(expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.check:
        errors: list[str] = []
        count = check_loon_pairs(root, errors)
        print("\n".join(errors) if errors else f"OK: checked {count} native Loon resources (offline)")
        return int(bool(errors))
    files = expected_files(root)
    for relative, text in files.items():
        path = root / "Ruleset" / "Loon" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"OK: generated {len(files)} native Loon resources; no network requests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
