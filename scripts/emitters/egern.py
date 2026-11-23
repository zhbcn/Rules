#!/usr/bin/env python3
"""Egern native YAML rule-set emitter (with pure-domain DNS split)."""
from __future__ import annotations

from pathlib import Path
import yaml

from .common import CompiledBundle, EmitStats, write_text_lf


ATOM_TO_EGERN_TAG: dict[str, str] = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-WILDCARD": "domain_wildcard",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr6",
    "IP-ASN": "asn",
    "PROTOCOL": "protocol",
    "URL-REGEX": "url_regex",
}


def _split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for idx, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise ValueError(f"Unbalanced parentheses in AND expression: {text!r}")
        elif ch == "," and depth == 0:
            parts.append(text[start:idx].strip())
            start = idx + 1
    if depth != 0:
        raise ValueError(f"Unterminated parentheses in AND expression: {text!r}")
    parts.append(text[start:].strip())
    return parts


def _parse_and_children(expr: str) -> list[tuple[str, str]]:
    """Parse canonical '((TYPE,VAL),(TYPE,VAL))' into [(egern_tag, match_val), ...]."""
    raw = expr.strip()
    if raw.upper().startswith("AND,"):
        raw = raw[4:].strip()
    if not (raw.startswith("(") and raw.endswith(")")):
        raise ValueError(f"Malformed AND expression: {expr!r}")
    inner = raw[1:-1].strip()
    items = _split_top_level(inner)
    children: list[tuple[str, str]] = []
    for item in items:
        if not (item.startswith("(") and item.endswith(")")):
            raise ValueError(f"Malformed AND child: {item!r}")
        atom = item[1:-1].strip()
        kind, sep, val = atom.partition(",")
        if not sep or kind.upper() not in ATOM_TO_EGERN_TAG:
            raise ValueError(f"Unsupported Egern AND child atom: {atom!r}")
        children.append((ATOM_TO_EGERN_TAG[kind.upper()], val.strip()))
    return children


def _yaml_scalar(value: str) -> str:
    dumped = yaml.safe_dump(value, allow_unicode=True, default_flow_style=True, width=1000).strip()
    if dumped.endswith("..."):
        dumped = dumped[:-3].strip()
    return dumped


def _render_egern_yaml(
    bundle_id: str,
    *,
    domain: list[str],
    domain_suffix: list[str],
    domain_keyword: list[str],
    domain_wildcard: list[str],
    domain_regex: list[str],
    ip_cidr: list[str],
    ip_cidr6: list[str],
    ip_asn: list[str],
    and_rules: list[str],
    url_regex: list[str],
    pure_domain_note: bool = False,
) -> tuple[str, int]:
    lines: list[str] = [
        f"# BUNDLE: {bundle_id}",
        f"# FORMAT: egern-yaml ({'pure-domain DNS subset' if pure_domain_note else 'native'})",
        "",
    ]
    has_ip = bool(ip_cidr or ip_cidr6 or ip_asn)
    if has_ip:
        lines.append("no_resolve: true")

    count = 0

    def _emit_list(key: str, vals: list[str]) -> None:
        nonlocal count
        if not vals:
            return
        lines.append(f"{key}:")
        for v in vals:
            lines.append(f"- {_yaml_scalar(v)}")
        count += len(vals)

    _emit_list("domain_set", domain)
    _emit_list("domain_suffix_set", domain_suffix)
    _emit_list("domain_keyword_set", domain_keyword)
    _emit_list("domain_wildcard_set", domain_wildcard)
    _emit_list("domain_regex_set", domain_regex)
    _emit_list("ip_cidr_set", ip_cidr)
    _emit_list("ip_cidr6_set", ip_cidr6)
    _emit_list("asn_set", ip_asn)

    if and_rules:
        lines.append("and_set:")
        for expr in and_rules:
            children = _parse_and_children(expr)
            for idx, (tag, val) in enumerate(children):
                prefix = "- - " if idx == 0 else "  - "
                lines.append(f"{prefix}!{tag}")
                lines.append(f"    match: {_yaml_scalar(val)}")
        count += len(and_rules)

    _emit_list("url_regex_set", url_regex)

    return "\n".join(lines) + "\n", count


def emit_egern(bundle: CompiledBundle, dist_dir: Path) -> EmitStats:
    """Emit native Egern YAML and, when needed for dns_bound, pure-domain DNS YAML."""
    rs = bundle.ruleset
    stats = EmitStats()

    full_text, count = _render_egern_yaml(
        bundle.id,
        domain=rs.domain,
        domain_suffix=rs.domain_suffix,
        domain_keyword=rs.domain_keyword,
        domain_wildcard=rs.domain_wildcard,
        domain_regex=rs.domain_regex,
        ip_cidr=rs.ip_cidr,
        ip_cidr6=rs.ip_cidr6,
        ip_asn=rs.ip_asn,
        and_rules=rs.and_rules,
        url_regex=rs.url_regex,
    )
    rel_full = f"dist/egern/{bundle.id}.yaml"
    write_text_lf(dist_dir / "egern" / f"{bundle.id}.yaml", full_text)
    stats.artifacts["yaml"] = rel_full
    stats.emitted = count

    if bundle.meta.get("dns_bound"):
        has_non_domain = bool(rs.has_ip_or_asn() or rs.url_regex or rs.and_rules)
        if has_non_domain:
            dns_text, _ = _render_egern_yaml(
                bundle.id,
                domain=rs.domain,
                domain_suffix=rs.domain_suffix,
                domain_keyword=rs.domain_keyword,
                domain_wildcard=rs.domain_wildcard,
                domain_regex=rs.domain_regex,
                ip_cidr=[],
                ip_cidr6=[],
                ip_asn=[],
                and_rules=[],
                url_regex=[],
                pure_domain_note=True,
            )
            rel_dns = f"dist/egern/{bundle.id}_domain.yaml"
            write_text_lf(dist_dir / "egern" / f"{bundle.id}_domain.yaml", dns_text)
            stats.artifacts["dns_yaml"] = rel_dns
        else:
            stats.artifacts["dns_yaml"] = rel_full

    return stats
