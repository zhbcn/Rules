#!/usr/bin/env python3
"""Mihomo + Stash native emitter (.mrs binary + minimal classical patches)."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .common import CompiledBundle, EmitStats, write_bytes_if_changed, write_text_lf


def find_mihomo_bin(explicit: str | None = None) -> Path:
    """Locate mihomo CLI binary in deterministic priority order."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_bin = os.environ.get("MIHOMO_BIN")
    if env_bin:
        candidates.append(Path(env_bin))

    # Known local Clash Verge Rev install paths on Windows
    candidates.append(Path(r"D:\Clash Verge\verge-mihomo.exe"))
    if prog_files := os.environ.get("ProgramFiles"):
        candidates.append(Path(prog_files) / "Clash Verge" / "verge-mihomo.exe")
    if local_app := os.environ.get("LOCALAPPDATA"):
        candidates.append(Path(local_app) / "Clash Verge" / "verge-mihomo.exe")

    for name in ("mihomo", "verge-mihomo"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))

    for cand in candidates:
        if cand.is_file():
            return cand

    raise FileNotFoundError(
        "Mihomo CLI binary not found. Pass --mihomo-bin, set MIHOMO_BIN, "
        "or install Clash Verge Rev / mihomo in PATH."
    )


def _compile_mrs(mihomo_bin: Path, behavior: str, lines: list[str]) -> bytes:
    with tempfile.TemporaryDirectory(prefix="zhbcn_mrs_") as tmp:
        tmp_dir = Path(tmp)
        src = tmp_dir / f"in_{behavior}.txt"
        out = tmp_dir / f"out_{behavior}.mrs"
        src.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [str(mihomo_bin), "convert-ruleset", behavior, "text", str(src), str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not out.is_file():
            raise RuntimeError(
                f"mihomo convert-ruleset {behavior} failed (rc={proc.returncode}): "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return out.read_bytes()


def emit_mihomo_stash(
    bundle: CompiledBundle,
    dist_dir: Path,
    mihomo_bin: Path,
) -> tuple[EmitStats, EmitStats]:
    """Emit shared .mrs artifacts and minimal classical patches for Mihomo & Stash."""
    rs = bundle.ruleset
    mihomo_stats = EmitStats()
    stash_stats = EmitStats()

    # 1. Domain .mrs (DOMAIN + DOMAIN-SUFFIX only -> 100% shared Mihomo/Stash)
    domain_lines: list[str] = []
    domain_lines.extend(rs.domain)
    domain_lines.extend(f"+.{s}" for s in rs.domain_suffix)
    if domain_lines:
        mrs_bytes = _compile_mrs(mihomo_bin, "domain", domain_lines)
        rel = f"dist/mihomo-stash/{bundle.id}_domain.mrs"
        write_bytes_if_changed(dist_dir / "mihomo-stash" / f"{bundle.id}_domain.mrs", mrs_bytes)
        mihomo_stats.artifacts["domain_mrs"] = rel
        stash_stats.artifacts["domain_mrs"] = rel
        mihomo_stats.emitted += len(domain_lines)
        stash_stats.emitted += len(domain_lines)

    # 2. IP CIDR .mrs (IP-CIDR + IP-CIDR6; no-resolve is configured in RULE-SET)
    ip_lines: list[str] = [*rs.ip_cidr, *rs.ip_cidr6]
    if ip_lines:
        mrs_bytes = _compile_mrs(mihomo_bin, "ipcidr", ip_lines)
        rel = f"dist/mihomo-stash/{bundle.id}_ipcidr.mrs"
        write_bytes_if_changed(dist_dir / "mihomo-stash" / f"{bundle.id}_ipcidr.mrs", mrs_bytes)
        mihomo_stats.artifacts["ipcidr_mrs"] = rel
        stash_stats.artifacts["ipcidr_mrs"] = rel
        mihomo_stats.emitted += len(ip_lines)
        stash_stats.emitted += len(ip_lines)

    # 3. Minimal classical patch (only non-MRS rule types)
    classical_lines: list[str] = []
    classical_lines.extend(f"DOMAIN-KEYWORD,{v}" for v in rs.domain_keyword)
    classical_lines.extend(f"DOMAIN-WILDCARD,{v}" for v in rs.domain_wildcard)
    classical_lines.extend(f"DOMAIN-REGEX,{v}" for v in rs.domain_regex)
    classical_lines.extend(f"IP-ASN,{v},no-resolve" for v in rs.ip_asn)
    classical_lines.extend(f"AND,{v}" for v in rs.and_rules)

    if classical_lines:
        # Mihomo classical YAML
        yaml_lines = [
            f"# BUNDLE: {bundle.id}",
            "# FORMAT: mihomo-classical (non-MRS remainder only)",
            "payload:",
        ]
        for line in classical_lines:
            escaped = line.replace("'", "''")
            yaml_lines.append(f"  - '{escaped}'")
        yaml_text = "\n".join(yaml_lines) + "\n"
        rel_m = f"dist/mihomo-classical/{bundle.id}_classical.yaml"
        write_text_lf(dist_dir / "mihomo-classical" / f"{bundle.id}_classical.yaml", yaml_text)
        mihomo_stats.artifacts["classical_yaml"] = rel_m
        mihomo_stats.emitted += len(classical_lines)

        # Stash classical plain text (.list)
        stash_lines = [
            f"# BUNDLE: {bundle.id}",
            "# FORMAT: stash-classical (non-MRS remainder only)",
            *classical_lines,
        ]
        stash_text = "\n".join(stash_lines) + "\n"
        rel_s = f"dist/stash-classical/{bundle.id}_classical.list"
        write_text_lf(dist_dir / "stash-classical" / f"{bundle.id}_classical.list", stash_text)
        stash_stats.artifacts["classical_list"] = rel_s
        stash_stats.emitted += len(classical_lines)

    # 4. Explicit accounting for URL-REGEX (unsupported in Mihomo & Stash)
    for pat in rs.url_regex:
        mihomo_stats.add_skipped(f"URL-REGEX,{pat}", "unsupported_url_regex_in_mihomo")
        stash_stats.add_skipped(f"URL-REGEX,{pat}", "unsupported_url_regex_in_stash")

    # DNS artifact pointer for dns_bound bundles
    if bundle.meta.get("dns_bound") and "domain_mrs" in mihomo_stats.artifacts:
        mihomo_stats.artifacts["dns_mrs"] = mihomo_stats.artifacts["domain_mrs"]
        stash_stats.artifacts["dns_mrs"] = stash_stats.artifacts["domain_mrs"]

    return mihomo_stats, stash_stats
