#!/usr/bin/env python3
"""Quantumult X native 3-field remote filter emitter."""
from __future__ import annotations

import itertools
from pathlib import Path

from .common import (
    APPROVED_WILDCARD_REGEX_ADAPTATIONS,
    COVERED_REGEX_SUFFIXES,
    DOMAIN_AND_RULES,
    NETFLIX_REGEX_PREFIXES,
    QX_SUFFIX_ADAPTATIONS,
    CompiledBundle,
    EmitStats,
    write_text_lf,
)


def _adapt_qx_regex(pattern: str, suffixes: set[str], stats: EmitStats) -> list[str]:
    if COVERED_REGEX_SUFFIXES.get(pattern) in suffixes:
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "covered_by_same_bundle_suffix", 0)
        return [f"# COVERED (same-bundle suffix): DOMAIN-REGEX,{pattern}"]

    if pattern == r"^hses[1-7]?\.akamaized\.net$":
        out = [f"host,hses{n}.akamaized.net,proxy" for n in ("", *map(str, range(1, 8)))]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "qx_exact_host_enumeration", len(out))
        return out

    if pattern == r"^epicgames-download\d\.akamaized\.net$":
        out = [f"host,epicgames-download{i}.akamaized.net,proxy" for i in range(10)]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "qx_exact_host_enumeration", len(out))
        return out

    if pattern == r"^.+-mihayo\.akamaized\.net$":
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "qx_wildcard_equivalent", 1)
        return ["host-wildcard,?*-mihayo.akamaized.net,proxy"]

    if pattern == r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$":
        out = [
            f"host-wildcard,*.awsdns-cn-{a}{b}.cn,proxy"
            for a, b in itertools.product("0123456789", "abcde0123456789")
        ]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "qx_wildcard_enumeration", len(out))
        return out

    for prefix in NETFLIX_REGEX_PREFIXES:
        if pattern == r"(^|\.)" + prefix + r"-.+\.amazonaws\.com$":
            host = prefix.replace(r"\.", ".") + "-?*.amazonaws.com"
            out = [f"host-wildcard,{host},proxy", f"host-wildcard,*.{host},proxy"]
            stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "qx_wildcard_equivalent", len(out))
            return out

    if pattern in QX_SUFFIX_ADAPTATIONS:
        sufs = QX_SUFFIX_ADAPTATIONS[pattern]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "qx_approved_suffix_optimization", len(sufs))
        return [
            f"# QX-ADAPTED (approved suffix optimization): DOMAIN-REGEX,{pattern}",
            *(f"host-suffix,{s},proxy" for s in sufs),
        ]

    if pattern in APPROVED_WILDCARD_REGEX_ADAPTATIONS:
        globs = APPROVED_WILDCARD_REGEX_ADAPTATIONS[pattern]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "qx_approved_wildcard_adaptation", len(globs))
        return [
            f"# QX-ADAPTED (approved wildcard approximation): DOMAIN-REGEX,{pattern}",
            *(f"host-wildcard,{g},proxy" for g in globs),
        ]

    raise ValueError(f"Unreviewed DOMAIN-REGEX for Quantumult X: {pattern!r}")


def emit_quantumultx(bundle: CompiledBundle, dist_dir: Path) -> EmitStats:
    """Emit native 3-field Quantumult X remote filter (.list)."""
    rs = bundle.ruleset
    stats = EmitStats()
    suffixes = set(rs.domain_suffix)
    lines: list[str] = []

    lines.extend(f"host,{v},proxy" for v in rs.domain)
    lines.extend(f"host-suffix,{v},proxy" for v in rs.domain_suffix)
    lines.extend(f"host-keyword,{v},proxy" for v in rs.domain_keyword)
    lines.extend(f"host-wildcard,{v},proxy" for v in rs.domain_wildcard)

    for pat in rs.domain_regex:
        lines.extend(_adapt_qx_regex(pat, suffixes, stats))

    lines.extend(f"ip-cidr,{v},proxy" for v in rs.ip_cidr)
    lines.extend(f"ip6-cidr,{v},proxy" for v in rs.ip_cidr6)
    lines.extend(f"ip-asn,{v},proxy" for v in rs.ip_asn)

    for expr in rs.and_rules:
        full_key = f"AND,{expr}"
        if full_key in DOMAIN_AND_RULES:
            globs = DOMAIN_AND_RULES[full_key]
            stats.add_adapted(full_key, "qx_approved_and_to_wildcard", len(globs))
            lines.append(f"# QX-ADAPTED (approved domain AND): {full_key}")
            lines.extend(f"host-wildcard,{g},proxy" for g in globs)
        else:
            raise ValueError(f"Unreviewed AND rule for Quantumult X: {full_key!r}")

    for pat in rs.url_regex:
        stats.add_skipped(f"URL-REGEX,{pat}", "unsupported_url_regex_in_qx")
        lines.append(f"# SKIPPED (unsupported URL-REGEX in QX filter): URL-REGEX,{pat}")

    deduped = list(dict.fromkeys(lines))
    stats.emitted = sum(1 for line in deduped if line and not line.startswith("#"))

    status = "ADAPTED-DOMAIN-IP" if stats.adapted else "COMPLETE-DOMAIN-IP"
    header = [
        f"# BUNDLE: {bundle.id}",
        f"# QX-COMPAT: {status}; proxy is a placeholder; use force-policy and opt-parser=false.",
    ]
    if rs.has_ip_or_asn():
        header.append("# QX-DNS: native 3-field format; source no-resolve is not exported.")
    header.append("")

    text = "\n".join([*header, *deduped]) + "\n"
    rel = f"dist/quantumultx/{bundle.id}.list"
    write_text_lf(dist_dir / "quantumultx" / f"{bundle.id}.list", text)
    stats.artifacts["list"] = rel
    return stats
