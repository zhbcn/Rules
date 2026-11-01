#!/usr/bin/env python3
"""Generate native Quantumult X remote filters from the Mihomo rule sets.

Syntax: https://github.com/crossutility/Quantumult-X/blob/master/sample.conf
Unsupported conditions stay in comments rather than becoming broader matches.
The proxy policy is a placeholder; choose the actual policy via force-policy.
"""

from __future__ import annotations

from pathlib import Path

import yaml


RULE_TYPES = {
    "DOMAIN": "host",
    "DOMAIN-SUFFIX": "host-suffix",
    "DOMAIN-KEYWORD": "host-keyword",
    "DOMAIN-WILDCARD": "host-wildcard",
    "IP-CIDR": "ip-cidr",
    "IP-CIDR6": "ip6-cidr",
    "IP-ASN": "ip-asn",
}
UNSUPPORTED_TYPES = {"DOMAIN-REGEX", "PROCESS-NAME", "AND"}


def convert_rule(rule: str) -> str:
    kind, _, _ = rule.partition(",")
    if kind in UNSUPPORTED_TYPES:
        return f"# UNSUPPORTED (no native equivalent): {rule}"
    if kind not in RULE_TYPES:
        raise ValueError(f"Unreviewed Quantumult X rule type: {kind}")
    parts = rule.split(",")
    if len(parts) not in (2, 3) or not parts[1].strip():
        raise ValueError(f"Malformed rule: {rule}")
    options = parts[2:]
    if options and (options != ["no-resolve"] or kind not in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}):
        raise ValueError(f"Unsupported rule options: {rule}")
    return ",".join([RULE_TYPES[kind], parts[1], "proxy", *options])


def render_filter(text: str) -> str:
    document = yaml.safe_load(text)
    headers = []
    for line in text.splitlines():
        if line.startswith("#"):
            headers.append(line)
        elif line.strip():
            break
    rules = list(dict.fromkeys(convert_rule(rule) for rule in document["payload"]))
    return "\n".join([*headers, "", *rules, ""])


def check_quantumultx_pairs(root: Path, errors: list[str]) -> int:
    source = root / "Ruleset" / "Mihomo"
    target = root / "Ruleset" / "QuantumultX"
    sources = {path.relative_to(source) for path in source.rglob("*.yaml")}
    expected = {path.with_suffix(".list") for path in sources}
    actual = {path.relative_to(target) for path in target.rglob("*.list")}
    for relative in sorted(expected - actual):
        errors.append(f"PAIR MISSING QuantumultX/{relative.as_posix()}")
    for relative in sorted(actual - expected):
        errors.append(f"PAIR EXTRA QuantumultX/{relative.as_posix()}")
    for relative in sorted(sources):
        output = target / relative.with_suffix(".list")
        if not output.is_file():
            continue
        try:
            expected_text = render_filter((source / relative).read_text(encoding="utf-8-sig"))
            if output.read_text(encoding="utf-8-sig") != expected_text:
                errors.append(f"PAIR MISMATCH QuantumultX/{relative.with_suffix('.list').as_posix()}: regenerate filters")
        except (ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
            errors.append(f"QuantumultX/{relative.as_posix()}: {exc}")
    return len(actual)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "Ruleset" / "Mihomo"
    count = 0
    for path in sorted(source.rglob("*.yaml")):
        relative = path.relative_to(source)
        text = render_filter(path.read_text(encoding="utf-8-sig"))
        target = root / "Ruleset" / "QuantumultX" / relative.with_suffix(".list")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
        count += 1
    print(f"Generated {count} native Quantumult X filters")


if __name__ == "__main__":
    main()
