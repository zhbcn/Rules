#!/usr/bin/env python3
"""Generate native Quantumult X remote filters from the Mihomo rule sets.

Syntax: https://github.com/crossutility/Quantumult-X/blob/master/sample.conf
Reviewed QX-only adaptations are explicit; other unsupported conditions stay in comments.
The proxy policy is a placeholder; choose the actual policy via force-policy.
"""

from __future__ import annotations

from pathlib import Path
import ipaddress
import itertools
import re

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
DOMAIN_AND_RULES = {
    "AND,((DOMAIN-KEYWORD,-ad-),(DOMAIN-SUFFIX,byteimg.com))": ["*-ad-*.byteimg.com"],
    "AND,((DOMAIN-KEYWORD,ads),(DOMAIN-KEYWORD,-normal.zijieapi.com))": [
        "*ads*-normal.zijieapi.com*", "*-normal.zijieapi.com*ads*",
    ],
    "AND,((DOMAIN-KEYWORD,adash),(DOMAIN-SUFFIX,ut.taobao.com))": ["*adash*.ut.taobao.com"],
}

# QX-only adaptations approved by the owner. Keep the original regexes in
# Mihomo/Egern; these globs intentionally relax only the dynamic identifier.
# Native wildcard '*' may also match dots. Prefix/suffix restrictions are not
# proof of cloud tenant ownership, so do not label these mappings equivalent.
QX_REGEX_ADAPTATIONS = {
    r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$": [
        "chatgpt-async-webps-prod-?*-?*.webpubsub.azure.com",
    ],
    r"^cdn\d-epicgames-\d+\.file\.myqcloud\.com$": [
        f"cdn{i}-epicgames-?*.file.myqcloud.com" for i in range(10)
    ],
    r"^epicgames-download\d-\d+\.file\.myqcloud\.com$": [
        f"epicgames-download{i}-?*.file.myqcloud.com" for i in range(10)
    ],
}


def convert_regex(pattern: str, suffixes: set[str]) -> list[str] | None:
    """Only reviewed, exact conversions on valid DNS hostnames; never widen CDN scopes."""
    # Existing same-file suffixes already include every hostname matched here.
    covered_patterns = {
        r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$": "cn",
        r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.xn--ngstr-lra8j\.com$": "xn--ngstr-lra8j.com",
        r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$": "googlevideo.com",
        r"^speed\.(coe|open)\.ad\.[a-z]{2,6}\.prod\.hosts\.ooklaserver\.net$": "ooklaserver.net",
    }
    if covered_patterns.get(pattern) in suffixes:
        return []
    if pattern == r"^hses[1-7]?\.akamaized\.net$":
        return ["host," + "hses" + number + ".akamaized.net,proxy" for number in ["", *map(str, range(1, 8))]]
    if pattern == r"^epicgames-download\d\.akamaized\.net$":
        return [f"host,epicgames-download{i}.akamaized.net,proxy" for i in range(10)]
    if pattern == r"^.+-mihayo\.akamaized\.net$":
        return ["host-wildcard,?*-mihayo.akamaized.net,proxy"]
    if pattern == r".+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$":
        return [f"host-wildcard,*.awsdns-cn-{a}{b}.{tld},proxy"
                for a, b, tld in itertools.product("0123456789", "0123456789", ("biz", "com", "net", "top"))]
    if pattern == r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$":
        return [f"host-wildcard,*.awsdns-cn-{a}{b}.cn,proxy"
                for a, b in itertools.product("0123456789", "abcde0123456789")]
    netflix_prefixes = (
        "apiproxy-device-prod-nlb", "apiproxy-website-nlb-prod",
        r"dualstack\.apiproxy", r"dualstack\.ichnaea-web",
    )
    for prefix in netflix_prefixes:
        if pattern == r"(^|\.)" + prefix + r"-.+\.amazonaws\.com$":
            host = prefix.replace(r"\.", ".") + "-?*.amazonaws.com"
            return [f"host-wildcard,{host},proxy", f"host-wildcard,*.{host},proxy"]
    return None


def convert_rule(rule: str, suffixes: set[str] | None = None) -> str:
    kind, _, _ = rule.partition(",")
    if kind == "PROCESS-NAME":
        return f"# PLATFORM-OMITTED (iOS domain/IP filter scope): {rule}"
    if kind == "DOMAIN-REGEX":
        pattern = rule.split(",", 1)[1]
        converted = convert_regex(pattern, suffixes or set())
        if converted is None:
            if pattern in QX_REGEX_ADAPTATIONS:
                return "\n".join([
                    f"# QX-ADAPTED (approved wildcard approximation; dynamic identifiers may contain non-digits or dots): {rule}",
                    *(f"host-wildcard,{glob},proxy" for glob in QX_REGEX_ADAPTATIONS[pattern]),
                ])
            return f"# LIMITATION (unbounded character constraints cannot be expressed exactly): {rule}"
        return "\n".join(converted) if converted else f"# COVERED (same-file suffix already includes this pattern): {rule}"
    if kind == "AND":
        if rule in DOMAIN_AND_RULES:
            return "\n".join(f"host-wildcard,{pattern},proxy" for pattern in DOMAIN_AND_RULES[rule])
        return f"# LIMITATION (no exact native protocol/domain conjunction): {rule}"
    if kind not in RULE_TYPES:
        raise ValueError(f"Unreviewed Quantumult X rule type: {kind}")
    parts = rule.split(",")
    if len(parts) not in (2, 3) or not parts[1].strip():
        raise ValueError(f"Malformed rule: {rule}")
    options = parts[2:]
    if options and (options != ["no-resolve"] or kind not in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}):
        raise ValueError(f"Unsupported rule options: {rule}")
    value = parts[1]
    if kind in {"IP-CIDR", "IP-CIDR6"}:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != (4 if kind == "IP-CIDR" else 6):
            raise ValueError(f"Wrong IP family: {rule}")
        value = str(network)
    # QX native filters use three fields; do not export Mihomo DNS evaluation flags.
    return ",".join([RULE_TYPES[kind], value, "proxy"])


def render_filter(text: str, url_only_rules: tuple[str, ...] = ()) -> str:
    document = yaml.safe_load(text)
    headers = []
    for line in text.splitlines():
        if line.startswith("#"):
            headers.append(line)
        elif line.strip():
            break
    suffixes = {rule.split(",")[1] for rule in document["payload"] if rule.startswith("DOMAIN-SUFFIX,")}
    rules = list(dict.fromkeys(line for rule in document["payload"] for line in convert_rule(rule, suffixes).splitlines()))
    status = ("PARTIAL" if any(line.startswith("# LIMITATION") for line in rules)
              else "ADAPTED-DOMAIN-IP" if any(line.startswith("# QX-ADAPTED") for line in rules)
              else "COMPLETE-DOMAIN-IP")
    notes = [f"# QX-COMPAT: {status}; proxy is a placeholder; use force-policy and opt-parser=false."]
    if any(rule.endswith(",no-resolve") for rule in document["payload"]):
        notes.append("# QX-DNS: source no-resolve is not exported; native QX DNS evaluation is not equivalent to Mihomo.")
    notes.extend(f"# SCOPE-EXCLUDED (Egern URL matching; not a native domain/IP filter): {rule}" for rule in url_only_rules)
    return "\n".join([*headers, *notes, "", *rules, ""])


def egern_url_rules(root: Path, relative: Path) -> tuple[str, ...]:
    path = root / "Ruleset" / "Egern" / relative
    if not path.is_file():
        return ()
    # Inspect the YAML tree without discarding Egern's typed logical tags.
    node = yaml.compose(path.read_text(encoding="utf-8-sig"))
    for key, value in node.value:
        if key.value == "url_regex_set":
            return tuple(item.value for item in value.value)
    return ()


def validate_filter(text: str) -> list[str]:
    """Independent native grammar checks, in addition to regeneration consistency."""
    errors = []
    seen = set()
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) != 3 or parts[0] not in RULE_TYPES.values() or parts[2] != "proxy" or not parts[1]:
            errors.append(f"line {number}: invalid native three-field filter")
            continue
        kind, value, _ = parts
        if line in seen:
            errors.append(f"line {number}: duplicate filter")
        seen.add(line)
        if kind in {"ip-cidr", "ip6-cidr"}:
            try:
                network = ipaddress.ip_network(value, strict=True)
                if network.version != (4 if kind == "ip-cidr" else 6):
                    raise ValueError("wrong family")
            except ValueError:
                errors.append(f"line {number}: invalid or noncanonical CIDR")
        elif kind == "ip-asn":
            if not value.isdecimal() or not 0 < int(value) < 2**32:
                errors.append(f"line {number}: invalid ASN")
        elif re.search(r"\s|://|/", value):
            errors.append(f"line {number}: invalid hostname filter")
    return errors


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
            expected_text = render_filter((source / relative).read_text(encoding="utf-8-sig"), egern_url_rules(root, relative))
            actual_text = output.read_text(encoding="utf-8-sig")
            errors.extend(f"QuantumultX/{relative.with_suffix('.list').as_posix()}: {error}" for error in validate_filter(actual_text))
            if actual_text != expected_text:
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
        text = render_filter(path.read_text(encoding="utf-8-sig"), egern_url_rules(root, relative))
        target = root / "Ruleset" / "QuantumultX" / relative.with_suffix(".list")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.is_file() or target.read_text(encoding="utf-8-sig") != text:
            target.write_text(text, encoding="utf-8", newline="\n")
        count += 1
    print(f"Generated {count} native Quantumult X filters")


if __name__ == "__main__":
    main()
