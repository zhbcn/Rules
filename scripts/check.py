#!/usr/bin/env python3
"""Pure self-contained repository checks for zhbcn/Rules.

Zero reverse dependency on any private client configuration repository.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys

import yaml

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build import check_dist_up_to_date  # noqa: E402
from emitters import find_mihomo_bin  # noqa: E402
from schema import (  # noqa: E402
    PROCESS_TYPES,
    RULE_FIELDS,
    load_patch_file,
    load_source_file,
)


ROOT = SCRIPTS_DIR.parent

QX_VALID_TYPES = frozenset({
    "host", "host-suffix", "host-keyword", "host-wildcard",
    "ip-cidr", "ip6-cidr", "ip-asn",
})
IP_RULE_PREFIXES = ("IP-CIDR,", "IP-CIDR6,", "IP-ASN,")

# Generic public-repo decoupling tokens (never store real personal secrets here;
# real private-keyword scanning belongs in the local private config repo).
FORBIDDEN_COUPLING_TOKENS: tuple[str, ...] = (
    "wife_profile",
    "wife profile",
    "\u8001\u5a46",
    "ca_p12",
    "passphrase",
    "proxy-providers",
)

# Explicit allowlist of upstream bulk files permitted to contain /32 IPv4 entries.
# custom/services/ and custom/patches/ allowlist is intentionally empty to prevent
# personal server /32 IPs from ever leaking into the public repository.
ALLOWED_UPSTREAM_HOST_CIDR_FILES: frozenset[str] = frozenset({
    "upstream/direct/cnip.yaml",
    "upstream/entertainment/global_media.yaml",
    "upstream/system/advertising.yaml",
    "upstream/system/httpdns.yaml",
    "upstream/system/lan.yaml",
    "upstream/system/reject.yaml",
    "upstream/technology/global.yaml",
})
ALLOWED_CUSTOM_HOST_CIDRS: frozenset[str] = frozenset()


class EgernSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that accepts Egern's rule-type tags."""


def _construct_egern_tag(loader: EgernSafeLoader, _suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


EgernSafeLoader.add_multi_constructor("!", _construct_egern_tag)


def load_egern_yaml(text: str) -> object:
    return yaml.load(text, Loader=EgernSafeLoader)


def check_sources_and_bundles(root: Path, errors: list[str]) -> tuple[int, int]:
    """Validate sources.json, bundles.json, upstream/, custom/services/, and custom/patches/."""
    sources_path = root / "sources.json"
    bundles_path = root / "bundles.json"

    sources_doc = json.loads(sources_path.read_text(encoding="utf-8-sig"))
    bundles_doc = json.loads(bundles_path.read_text(encoding="utf-8-sig"))

    # 1. Check sources.json targets exist
    declared_upstream: set[str] = set()
    for entry in sources_doc.get("sources") or []:
        rel = entry["target"].replace("\\", "/")
        if rel in declared_upstream:
            errors.append(f"sources.json duplicate target: {rel}")
        declared_upstream.add(rel)
        if not (root / rel).is_file():
            errors.append(f"sources.json missing target file: {rel}")

    # 2. Validate every canonical source file under upstream/ and custom/services/
    actual_sources: set[str] = set()
    for base_rel in ("upstream", "custom/services"):
        base_dir = root / base_rel
        if not base_dir.is_dir():
            errors.append(f"Missing directory: {base_rel}")
            continue
        for path in sorted(base_dir.rglob("*.yaml")):
            rel = path.relative_to(root).as_posix()
            actual_sources.add(rel)
            raw_text = path.read_text(encoding="utf-8-sig")
            for proc_kw in PROCESS_TYPES:
                if proc_kw in raw_text:
                    errors.append(f"{rel}: forbidden process rule token {proc_kw}")
            try:
                doc, rs = load_source_file(path)
            except (ValueError, yaml.YAMLError) as exc:
                errors.append(f"{rel}: {exc}")
                continue
            expected_kind = "upstream" if rel.startswith("upstream/") else "custom"
            if doc.get("kind") != expected_kind:
                errors.append(f"{rel}: expected kind={expected_kind!r}, got {doc.get('kind')!r}")
            if rs.count() == 0:
                errors.append(f"{rel}: canonical source has 0 rules (empty ruleset)")
            # Duplicate check per field
            for fname in RULE_FIELDS:
                vals = rs.get_field(fname)
                seen: set[str] = set()
                for v in vals:
                    k = v.lower() if fname not in {"domain_regex", "url_regex"} else v
                    if k in seen:
                        errors.append(f"{rel}: duplicate {fname} entry {v!r}")
                    seen.add(k)

    # Check upstream files vs sources.json
    actual_upstream = {p for p in actual_sources if p.startswith("upstream/")}
    for rel in sorted(actual_upstream - declared_upstream):
        errors.append(f"Unregistered upstream file (not in sources.json): {rel}")

    # 3. Validate custom/patches/*.patch.yaml
    patches_dir = root / "custom" / "patches"
    if patches_dir.is_dir():
        for ppath in sorted(patches_dir.rglob("*.patch.yaml")):
            rel = ppath.relative_to(root).as_posix()
            try:
                pdoc = load_patch_file(ppath)
                target = pdoc["target"].replace("\\", "/")
                if target not in actual_sources:
                    errors.append(f"{rel}: patch target not found: {target}")
            except (ValueError, yaml.YAMLError) as exc:
                errors.append(f"{rel}: {exc}")

    # 4. Validate bundles.json coverage (zero missing, zero orphan)
    referenced: set[str] = set()
    seen_ids: set[str] = set()
    bundles = bundles_doc.get("bundles") or []
    for b in bundles:
        bid = b.get("id")
        if not bid or bid in seen_ids:
            errors.append(f"bundles.json invalid or duplicate id: {bid!r}")
            continue
        seen_ids.add(bid)
        srcs = b.get("sources") or []
        if not srcs:
            errors.append(f"bundles.json bundle '{bid}' has no sources")
        for s in srcs:
            ns = s.replace("\\", "/")
            referenced.add(ns)
            if ns not in actual_sources:
                errors.append(f"bundles.json bundle '{bid}' missing source: {ns}")

    for orphan in sorted(actual_sources - referenced):
        errors.append(f"Orphan canonical source not referenced by any bundle: {orphan}")

    return len(actual_sources), len(bundles)


def check_privacy_and_coupling(root: Path, errors: list[str]) -> None:
    """Enforce public-repo decoupling tokens and explicit /32 host-IP allowlist."""
    # 1. Scan metadata, docs, scripts, manifests, and custom/ (never upstream/ or dist/ rule bodies)
    scan_paths: list[Path] = []
    for name in ("README.md", "AGENTS.md", "bundles.json", "sources.json", "dist/manifest.json"):
        p = root / name
        if p.is_file():
            scan_paths.append(p)
    for sub in ("docs", "scripts", "custom"):
        sub_dir = root / sub
        if sub_dir.is_dir():
            for p in sorted(sub_dir.rglob("*")):
                if p.is_file() and "__pycache__" not in p.parts:
                    scan_paths.append(p)

    for path in sorted(set(scan_paths)):
        rel = path.relative_to(root).as_posix()
        # Skip the token-definition table itself in scripts/check.py
        if rel == "scripts/check.py":
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            for tok in FORBIDDEN_COUPLING_TOKENS:
                if tok in low:
                    errors.append(f"PRIVACY/COUPLING {rel}:{lineno}: forbidden token {tok!r}")

    # 2. Enforce /32 (and /128) host-IP allowlist across canonical sources & patches
    for base_rel in ("upstream", "custom/services"):
        base_dir = root / base_rel
        if not base_dir.is_dir():
            continue
        for path in sorted(base_dir.rglob("*.yaml")):
            rel = path.relative_to(root).as_posix()
            try:
                _, rs = load_source_file(path)
            except (ValueError, yaml.YAMLError):
                continue
            host_ips = [ip for ip in rs.ip_cidr if ip.endswith("/32")] + [
                ip for ip in rs.ip_cidr6 if ip.endswith("/128")
            ]
            if not host_ips:
                continue
            if rel.startswith("upstream/"):
                if rel not in ALLOWED_UPSTREAM_HOST_CIDR_FILES:
                    errors.append(
                        f"HOST-IP-ALLOWLIST {rel}: unexpected /32 or /128 entries ({len(host_ips)}): {host_ips[:3]}"
                    )
            else:
                disallowed = [ip for ip in host_ips if ip not in ALLOWED_CUSTOM_HOST_CIDRS]
                if disallowed:
                    errors.append(
                        f"HOST-IP-ALLOWLIST {rel}: unallowlisted custom host IP(s): {disallowed}"
                    )

    patches_dir = root / "custom" / "patches"
    if patches_dir.is_dir():
        for ppath in sorted(patches_dir.rglob("*.patch.yaml")):
            rel = ppath.relative_to(root).as_posix()
            try:
                pdoc = load_patch_file(ppath)
            except (ValueError, yaml.YAMLError):
                continue
            added = pdoc.get("add") or {}
            for ip in [*(added.get("ip_cidr") or []), *(added.get("ip_cidr6") or [])]:
                s = str(ip).strip()
                if (s.endswith("/32") or s.endswith("/128")) and s not in ALLOWED_CUSTOM_HOST_CIDRS:
                    errors.append(f"HOST-IP-ALLOWLIST {rel}: unallowlisted patch host IP: {s}")


def _validate_qx_file(path: Path, errors: list[str]) -> None:
    rel = path.relative_to(ROOT).as_posix()
    seen: set[str] = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) != 3 or parts[0] not in QX_VALID_TYPES or parts[2] != "proxy" or not parts[1]:
            errors.append(f"{rel}:{lineno}: invalid 3-field QX rule: {line!r}")
            continue
        if line in seen:
            errors.append(f"{rel}:{lineno}: duplicate QX rule: {line!r}")
        seen.add(line)
        kind, val, _ = parts
        if kind in {"ip-cidr", "ip6-cidr"}:
            try:
                net = ipaddress.ip_network(val, strict=True)
                if net.version != (4 if kind == "ip-cidr" else 6):
                    raise ValueError("wrong family")
            except ValueError:
                errors.append(f"{rel}:{lineno}: invalid CIDR: {val!r}")
        elif kind == "ip-asn":
            if not val.isdecimal() or not 0 < int(val) < 2**32:
                errors.append(f"{rel}:{lineno}: invalid ASN: {val!r}")
        elif re.search(r"\s|://|/", val):
            errors.append(f"{rel}:{lineno}: invalid hostname filter: {val!r}")


def _validate_loon_file(path: Path, errors: list[str]) -> None:
    rel = path.relative_to(ROOT).as_posix()
    seen: set[str] = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        if line in seen:
            errors.append(f"{rel}:{lineno}: duplicate Loon rule: {line!r}")
        seen.add(line)
        if line.startswith("DOMAIN-REGEX,"):
            errors.append(f"{rel}:{lineno}: forbidden DOMAIN-REGEX in Loon output")
        if line.startswith(IP_RULE_PREFIXES) and not line.endswith(",no-resolve"):
            errors.append(f"{rel}:{lineno}: missing ,no-resolve on Loon IP/ASN rule: {line!r}")
        if line.startswith("AND,") and any(tok in line for tok in ("(IP-CIDR,", "(IP-CIDR6,", "(IP-ASN,")):
            if ",no-resolve)" not in line:
                errors.append(f"{rel}:{lineno}: missing ,no-resolve inside Loon AND IP/ASN rule")


def check_dist_invariants(root: Path, errors: list[str], *, require_complete_qx: bool = False) -> None:
    """Verify dist/ manifest, build-report, DNS purity, no-resolve, and native grammars."""
    dist_dir = root / "dist"
    manifest_path = dist_dir / "manifest.json"
    report_path = dist_dir / "build-report.json"
    if not manifest_path.is_file() or not report_path.is_file():
        errors.append("Missing dist/manifest.json or dist/build-report.json (run python scripts/build.py)")
        return

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))

    for bid, bmeta in (manifest.get("bundles") or {}).items():
        arts = bmeta.get("artifacts") or {}
        # Check every declared artifact exists
        for cname, cart in arts.items():
            for akey, arel in cart.items():
                if not (root / arel).is_file():
                    errors.append(f"manifest.json missing artifact for {bid}.{cname}.{akey}: {arel}")

        # DNS purity invariant for dns_bound bundles
        if bmeta.get("dns_bound"):
            egern_dns_rel = arts.get("egern", {}).get("dns_yaml")
            if not egern_dns_rel:
                errors.append(f"dns_bound bundle '{bid}' missing egern dns_yaml artifact")
            else:
                doc = load_egern_yaml((root / egern_dns_rel).read_text(encoding="utf-8-sig"))
                if isinstance(doc, dict):
                    forbidden_dns_keys = {"ip_cidr_set", "ip_cidr6_set", "asn_set", "url_regex_set", "and_set", "no_resolve"}
                    bad = sorted(forbidden_dns_keys & set(doc.keys()))
                    if bad:
                        errors.append(f"{egern_dns_rel}: dns_bound artifact contains non-domain keys: {bad}")

            mihomo_dns_rel = arts.get("mihomo", {}).get("dns_mrs")
            if mihomo_dns_rel and not mihomo_dns_rel.endswith("_domain.mrs"):
                errors.append(f"{bid}: mihomo dns_mrs must be *_domain.mrs, got {mihomo_dns_rel}")

        # Egern no_resolve invariant
        egern_rel = arts.get("egern", {}).get("yaml")
        if egern_rel and (root / egern_rel).is_file():
            doc = load_egern_yaml((root / egern_rel).read_text(encoding="utf-8-sig"))
            if isinstance(doc, dict):
                has_ip = any(k in doc for k in ("ip_cidr_set", "ip_cidr6_set", "asn_set"))
                if has_ip and doc.get("no_resolve") is not True:
                    errors.append(f"{egern_rel}: IP/ASN Egern rule-set missing no_resolve: true")

        # Mihomo / Stash classical no-resolve invariant
        m_cls = arts.get("mihomo", {}).get("classical_yaml")
        if m_cls and (root / m_cls).is_file():
            doc = yaml.safe_load((root / m_cls).read_text(encoding="utf-8-sig"))
            for item in (doc or {}).get("payload") or []:
                s = str(item)
                if s.startswith(IP_RULE_PREFIXES) and not s.endswith(",no-resolve"):
                    errors.append(f"{m_cls}: missing ,no-resolve on classical IP/ASN rule: {s!r}")

        s_cls = arts.get("stash", {}).get("classical_list")
        if s_cls and (root / s_cls).is_file():
            for line in (root / s_cls).read_text(encoding="utf-8-sig").splitlines():
                if line.startswith(IP_RULE_PREFIXES) and not line.endswith(",no-resolve"):
                    errors.append(f"{s_cls}: missing ,no-resolve on classical IP/ASN rule: {line!r}")

        # Loon & QX grammar checks
        loon_rel = arts.get("loon", {}).get("list")
        if loon_rel and (root / loon_rel).is_file():
            _validate_loon_file(root / loon_rel, errors)
        loon_stun_rel = arts.get("loon", {}).get("stun_list")
        if loon_stun_rel and (root / loon_stun_rel).is_file():
            _validate_loon_file(root / loon_stun_rel, errors)

        qx_rel = arts.get("quantumultx", {}).get("list")
        if qx_rel and (root / qx_rel).is_file():
            _validate_qx_file(root / qx_rel, errors)

    if require_complete_qx:
        qx_totals = (report.get("totals") or {}).get("quantumultx") or {}
        if qx_totals.get("adapted", 0) > 0 or qx_totals.get("skipped", 0) > 0:
            errors.append(
                f"QX strict completeness failed: adapted={qx_totals.get('adapted', 0)}, "
                f"skipped={qx_totals.get('skipped', 0)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-contained checks for zhbcn/Rules")
    parser.add_argument("--mihomo-bin", help="Explicit path to mihomo / verge-mihomo binary")
    parser.add_argument("--skip-dist-rebuild", action="store_true", help="Skip temp rebuild comparison of dist/")
    parser.add_argument(
        "--require-complete-qx",
        action="store_true",
        help="Fail if Quantumult X output contains any adapted or skipped rules",
    )
    args = parser.parse_args()

    errors: list[str] = []
    source_count, bundle_count = check_sources_and_bundles(ROOT, errors)
    check_privacy_and_coupling(ROOT, errors)
    check_dist_invariants(ROOT, errors, require_complete_qx=args.require_complete_qx)

    if not args.skip_dist_rebuild:
        mihomo_bin = find_mihomo_bin(args.mihomo_bin)
        errors.extend(check_dist_up_to_date(ROOT, mihomo_bin))

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        print(f"CHECK FAILED: {len(errors)} error(s)", file=sys.stderr)
        return 1

    print(f"OK: {source_count} canonical sources, {bundle_count} bundles, all 5-client dist/ checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
