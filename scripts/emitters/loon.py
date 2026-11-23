#!/usr/bin/env python3
"""Loon native policy-free .list emitter (including compiled AI STUN list)."""
from __future__ import annotations

from pathlib import Path
import sys

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from schema import RuleSet  # noqa: E402
from .common import (  # noqa: E402
    APPROVED_WILDCARD_REGEX_ADAPTATIONS,
    COVERED_REGEX_SUFFIXES,
    NETFLIX_REGEX_PREFIXES,
    CompiledBundle,
    EmitStats,
    write_text_lf,
)


def _adapt_loon_regex(pattern: str, suffixes: set[str], stats: EmitStats) -> list[str]:
    """Convert reviewed DOMAIN-REGEX to native Loon DOMAIN / DOMAIN-WILDCARD rules."""
    if COVERED_REGEX_SUFFIXES.get(pattern) in suffixes:
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "covered_by_same_bundle_suffix", 0)
        return [f"# COVERED (same-bundle suffix): DOMAIN-REGEX,{pattern}"]

    if pattern in APPROVED_WILDCARD_REGEX_ADAPTATIONS:
        globs = APPROVED_WILDCARD_REGEX_ADAPTATIONS[pattern]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "loon_approved_wildcard_adaptation", len(globs))
        return [
            f"# LOON-ADAPTED: DOMAIN-REGEX,{pattern}",
            *(f"DOMAIN-WILDCARD,{g}" for g in globs),
        ]

    if pattern == r"^.+-mihayo\.akamaized\.net$":
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "loon_wildcard_equivalent", 1)
        return ["DOMAIN-WILDCARD,?*-mihayo.akamaized.net"]

    if pattern == r".+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$":
        globs = ["?*.awsdns-cn-[0-9][0-9]." + t for t in ("biz", "com", "net", "top")]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "loon_wildcard_equivalent", len(globs))
        return [f"DOMAIN-WILDCARD,{g}" for g in globs]

    if pattern == r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$":
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "loon_wildcard_equivalent", 1)
        return ["DOMAIN-WILDCARD,?*.awsdns-cn-[0-9][a-e0-9].cn"]

    if pattern == r"^hses[1-7]?\.akamaized\.net$":
        out = [f"DOMAIN,hses{n}.akamaized.net" for n in ("", *map(str, range(1, 8)))]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "loon_exact_domain_enumeration", len(out))
        return out

    if pattern == r"^epicgames-download\d\.akamaized\.net$":
        out = [f"DOMAIN,epicgames-download{i}.akamaized.net" for i in range(10)]
        stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "loon_exact_domain_enumeration", len(out))
        return out

    for prefix in NETFLIX_REGEX_PREFIXES:
        if pattern == r"(^|\.)" + prefix + r"-.+\.amazonaws\.com$":
            host = prefix.replace(r"\.", ".") + "-?*.amazonaws.com"
            out = [f"DOMAIN-WILDCARD,{host}", f"DOMAIN-WILDCARD,*.{host}"]
            stats.add_adapted(f"DOMAIN-REGEX,{pattern}", "loon_wildcard_equivalent", len(out))
            return out

    raise ValueError(f"Unreviewed DOMAIN-REGEX for Loon: {pattern!r}")


def _render_loon_rules(rs: RuleSet, stats: EmitStats) -> list[str]:
    suffixes = set(rs.domain_suffix)
    out: list[str] = []
    out.extend(f"DOMAIN,{v}" for v in rs.domain)
    out.extend(f"DOMAIN-SUFFIX,{v}" for v in rs.domain_suffix)
    out.extend(f"DOMAIN-KEYWORD,{v}" for v in rs.domain_keyword)
    out.extend(f"DOMAIN-WILDCARD,{v}" for v in rs.domain_wildcard)
    for pat in rs.domain_regex:
        out.extend(_adapt_loon_regex(pat, suffixes, stats))
    out.extend(f"IP-CIDR,{v},no-resolve" for v in rs.ip_cidr)
    out.extend(f"IP-CIDR6,{v},no-resolve" for v in rs.ip_cidr6)
    out.extend(f"IP-ASN,{v},no-resolve" for v in rs.ip_asn)
    out.extend(f"AND,{v}" for v in rs.and_rules)
    if rs.url_regex:
        out.append("# URL-SCOPE: HTTPS path matching requires MITM; retained as native URL-REGEX.")
        out.extend(f"URL-REGEX,{v}" for v in rs.url_regex)
    return list(dict.fromkeys(out))


def emit_loon(bundle: CompiledBundle, dist_dir: Path) -> EmitStats:
    """Emit policy-free Loon .list (and compiled STUN list when emit_loon_stun is true)."""
    stats = EmitStats()
    rule_lines = _render_loon_rules(bundle.ruleset, stats)
    active_count = sum(1 for line in rule_lines if line and not line.startswith("#"))
    stats.emitted = active_count

    header = [
        f"# BUNDLE: {bundle.id}",
        "# FORMAT: loon-list (policy-free; bind via [Remote Rule] policy=...)",
        "",
    ]
    text = "\n".join([*header, *rule_lines]) + "\n"
    rel = f"dist/loon/{bundle.id}.list"
    write_text_lf(dist_dir / "loon" / f"{bundle.id}.list", text)
    stats.artifacts["list"] = rel

    if bundle.meta.get("emit_loon_stun"):
        stun_rs = RuleSet()
        for src in bundle.meta.get("loon_stun_sources") or []:
            norm_src = src.replace("\\", "/")
            if norm_src not in bundle.source_rulesets:
                raise KeyError(f"Bundle '{bundle.id}' loon_stun_sources entry not in sources: {norm_src}")
            stun_rs.merge(bundle.source_rulesets[norm_src])
        stun_rs.dedupe_and_sort()

        stun_dummy_stats = EmitStats()
        atoms = [
            line for line in _render_loon_rules(stun_rs, stun_dummy_stats)
            if line and not line.startswith("#") and not line.startswith("URL-REGEX,")
        ]
        stun_lines: list[str] = []
        for atom in atoms:
            if atom.startswith("AND,(") and atom.endswith(")"):
                inner = atom[5:-1]
                stun_lines.append(f"AND,((PROTOCOL,STUN),{inner})")
            else:
                stun_lines.append(f"AND,((PROTOCOL,STUN),({atom}))")
        stun_lines = list(dict.fromkeys(stun_lines))
        stun_header = [
            f"# BUNDLE: {bundle.id}_stun",
            "# FORMAT: loon-list (compiled STUN conjunction because Loon [Rule] has no RULE-SET)",
            f"# SOURCES: {', '.join(bundle.meta.get('loon_stun_sources') or [])}",
            "",
        ]
        stun_text = "\n".join([*stun_header, *stun_lines]) + "\n"
        rel_stun = f"dist/loon/{bundle.id}_stun.list"
        write_text_lf(dist_dir / "loon" / f"{bundle.id}_stun.list", stun_text)
        stats.artifacts["stun_list"] = rel_stun

    return stats
