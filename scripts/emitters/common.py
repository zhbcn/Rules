#!/usr/bin/env python3
"""Shared bundle loader, patch applier, and reviewed adaptation tables."""
from __future__ import annotations

from dataclasses import dataclass, field
import itertools
import json
from pathlib import Path
import sys

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from schema import RuleSet, load_patch_file, load_source_file  # noqa: E402


# Reviewed exact/approved regex & AND adaptation tables shared by Loon and QX.
# Never silently drop unreviewed patterns: emitters raise ValueError instead.
DOMAIN_AND_RULES: dict[str, list[str]] = {
    "AND,((DOMAIN-KEYWORD,-ad-),(DOMAIN-SUFFIX,byteimg.com))": ["*-ad-*.byteimg.com"],
    "AND,((DOMAIN-KEYWORD,ads),(DOMAIN-KEYWORD,-normal.zijieapi.com))": [
        "*ads*-normal.zijieapi.com*",
        "*-normal.zijieapi.com*ads*",
    ],
    "AND,((DOMAIN-KEYWORD,adash),(DOMAIN-SUFFIX,ut.taobao.com))": ["*adash*.ut.taobao.com"],
    "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,bytedance.com))": ["*tnc*.bytedance.com"],
    "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,capcutapi.com))": ["*tnc*.capcutapi.com"],
    "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,isnssdk.com))": ["*tnc*.isnssdk.com"],
    "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,sgsnssdk.com))": ["*tnc*.sgsnssdk.com"],
    "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,snssdk.com))": ["*tnc*.snssdk.com"],
    "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,toutiaoapi.com))": ["*tnc*.toutiaoapi.com"],
    "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,zijieapi.com))": ["*tnc*.zijieapi.com"],
}

APPROVED_WILDCARD_REGEX_ADAPTATIONS: dict[str, list[str]] = {
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

QX_SUFFIX_ADAPTATIONS: dict[str, list[str]] = {
    r".+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$": [
        f"awsdns-cn-{a}{b}.{tld}"
        for a, b, tld in itertools.product("0123456789", "0123456789", ("biz", "com", "net", "top"))
    ],
}

COVERED_REGEX_SUFFIXES: dict[str, str] = {
    r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$": "cn",
    r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.xn--ngstr-lra8j\.com$": "xn--ngstr-lra8j.com",
    r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$": "googlevideo.com",
    r"^speed\.(coe|open)\.ad\.[a-z]{2,6}\.prod\.hosts\.ooklaserver\.net$": "ooklaserver.net",
}

NETFLIX_REGEX_PREFIXES: tuple[str, ...] = (
    "apiproxy-device-prod-nlb",
    "apiproxy-website-nlb-prod",
    r"dualstack\.apiproxy",
    r"dualstack\.ichnaea-web",
)


@dataclass
class CompiledBundle:
    """Resolved, patched, deduplicated rule bundle ready for target emission."""

    id: str
    meta: dict
    ruleset: RuleSet
    source_rulesets: dict[str, RuleSet]
    patch_log: list[dict] = field(default_factory=list)
    excluded_count: int = 0


@dataclass
class EmitStats:
    """Per-bundle, per-client build accounting for build-report.json."""

    emitted: int = 0
    adapted: int = 0
    skipped: int = 0
    adapted_details: list[dict] = field(default_factory=list)
    skipped_details: list[dict] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)

    def add_adapted(self, rule: str, reason: str, output_count: int = 0) -> None:
        self.adapted += 1
        self.adapted_details.append({"rule": rule, "reason": reason, "output_count": output_count})

    def add_skipped(self, rule: str, reason: str) -> None:
        self.skipped += 1
        self.skipped_details.append({"rule": rule, "reason": reason})

    def to_dict(self) -> dict:
        out: dict = {
            "emitted": self.emitted,
            "adapted": self.adapted,
            "skipped": self.skipped,
            "artifacts": dict(self.artifacts),
        }
        if self.adapted_details:
            out["adapted_details"] = list(self.adapted_details)
        if self.skipped_details:
            out["skipped_details"] = list(self.skipped_details)
        return out


def load_bundles(root: Path) -> dict:
    path = root / "bundles.json"
    doc = json.loads(path.read_text(encoding="utf-8-sig"))
    if doc.get("schema") != "zhbcn-bundles/v1" or not isinstance(doc.get("bundles"), list):
        raise ValueError(f"{path}: invalid bundles.json schema")
    return doc


def load_patches(root: Path) -> dict[str, list[dict]]:
    patches_dir = root / "custom" / "patches"
    by_target: dict[str, list[dict]] = {}
    if not patches_dir.is_dir():
        return by_target
    for path in sorted(patches_dir.rglob("*.patch.yaml")):
        doc = load_patch_file(path)
        target = doc["target"].replace("\\", "/").strip()
        entry = dict(doc)
        entry["_file"] = path.relative_to(root).as_posix()
        by_target.setdefault(target, []).append(entry)
    return by_target


def compile_bundles(root: Path) -> tuple[dict, list[CompiledBundle]]:
    bundles_doc = load_bundles(root)
    patches_by_target = load_patches(root)
    compiled: list[CompiledBundle] = []
    seen_ids: set[str] = set()

    for meta in bundles_doc["bundles"]:
        bid = meta["id"]
        if bid in seen_ids:
            raise ValueError(f"Duplicate bundle id: {bid}")
        seen_ids.add(bid)

        merged = RuleSet()
        source_rulesets: dict[str, RuleSet] = {}
        patch_log: list[dict] = []

        for rel_src in meta.get("sources") or []:
            norm_src = rel_src.replace("\\", "/")
            src_path = root / norm_src
            if not src_path.is_file():
                raise FileNotFoundError(f"Bundle '{bid}' references missing source: {norm_src}")
            _, rs = load_source_file(src_path)
            for pdoc in patches_by_target.get(norm_src, []):
                added, removed = rs.apply_patch(pdoc)
                patch_log.append({
                    "patch": pdoc["_file"],
                    "target": norm_src,
                    "added": added,
                    "removed": removed,
                })
            rs.dedupe_and_sort()
            source_rulesets[norm_src] = rs
            merged.merge(rs)

        excluded_count = 0
        exclude_domains = meta.get("exclude_domains") or []
        if exclude_domains:
            excluded_count = merged.exclude_domain_roots(exclude_domains)
        merged.dedupe_and_sort()

        compiled.append(
            CompiledBundle(
                id=bid,
                meta=meta,
                ruleset=merged,
                source_rulesets=source_rulesets,
                patch_log=patch_log,
                excluded_count=excluded_count,
            )
        )

    return bundles_doc, compiled


def write_text_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = text.replace("\r\n", "\n")
    if path.is_file() and path.read_text(encoding="utf-8") == normalized:
        return
    path.write_text(normalized, encoding="utf-8", newline="\n")


def write_bytes_if_changed(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_bytes() == data:
        return
    path.write_bytes(data)
