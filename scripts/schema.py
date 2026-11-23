#!/usr/bin/env python3
"""Canonical lossless rule-source and patch schema for zhbcn/Rules.

Every file under upstream/ and custom/services/ uses ``zhbcn-rules/v1``.
Every file under custom/patches/ uses ``zhbcn-patch/v1``.
Process rules (PROCESS-NAME / PROCESS-PATH) are intentionally excluded from
universal rule sources and belong to platform overlays in the config repo.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import re
from typing import Iterable

import yaml


RULE_SCHEMA_VERSION = "zhbcn-rules/v1"
PATCH_SCHEMA_VERSION = "zhbcn-patch/v1"

RULE_FIELDS: tuple[str, ...] = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_wildcard",
    "domain_regex",
    "ip_cidr",
    "ip_cidr6",
    "ip_asn",
    "and",
    "url_regex",
)

DOMAIN_ONLY_FIELDS: frozenset[str] = frozenset({
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_wildcard",
    "domain_regex",
})

MRS_DOMAIN_FIELDS: frozenset[str] = frozenset({"domain", "domain_suffix"})
MRS_IP_FIELDS: frozenset[str] = frozenset({"ip_cidr", "ip_cidr6"})
IP_FIELDS: frozenset[str] = frozenset({"ip_cidr", "ip_cidr6", "ip_asn"})

MIHOMO_TO_CANONICAL: dict[str, str] = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-WILDCARD": "domain_wildcard",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr6",
    "IP-ASN": "ip_asn",
    "AND": "and",
    "URL-REGEX": "url_regex",
}

CANONICAL_TO_MIHOMO: dict[str, str] = {v: k for k, v in MIHOMO_TO_CANONICAL.items()}

PROCESS_TYPES: frozenset[str] = frozenset({"PROCESS-NAME", "PROCESS-PATH"})


@dataclass
class RuleSet:
    """In-memory canonical rule collection preserving lossless rule categories."""

    domain: list[str] = field(default_factory=list)
    domain_suffix: list[str] = field(default_factory=list)
    domain_keyword: list[str] = field(default_factory=list)
    domain_wildcard: list[str] = field(default_factory=list)
    domain_regex: list[str] = field(default_factory=list)
    ip_cidr: list[str] = field(default_factory=list)
    ip_cidr6: list[str] = field(default_factory=list)
    ip_asn: list[str] = field(default_factory=list)
    and_rules: list[str] = field(default_factory=list)
    url_regex: list[str] = field(default_factory=list)

    def get_field(self, field_name: str) -> list[str]:
        if field_name == "and":
            return self.and_rules
        return getattr(self, field_name)

    def set_field(self, field_name: str, values: list[str]) -> None:
        if field_name == "and":
            self.and_rules = values
        else:
            setattr(self, field_name, values)

    def add(self, field_name: str, value: str) -> None:
        if field_name not in RULE_FIELDS:
            raise ValueError(f"Unsupported canonical rule field: {field_name}")
        normalized = normalize_value(field_name, value)
        self.get_field(field_name).append(normalized)

    def merge(self, other: "RuleSet") -> None:
        for fname in RULE_FIELDS:
            self.get_field(fname).extend(other.get_field(fname))

    def dedupe_and_sort(self) -> None:
        for fname in RULE_FIELDS:
            seen: dict[str, str] = {}
            for item in self.get_field(fname):
                norm = normalize_value(fname, item)
                key = norm.lower() if fname not in {"domain_regex", "url_regex"} else norm
                if key not in seen:
                    seen[key] = norm
            # Deterministic stable sort
            self.set_field(fname, sorted(seen.values(), key=lambda s: s.lower()))

    def exclude_domain_roots(self, roots: Iterable[str]) -> int:
        """Remove domain/domain_suffix entries owned by any root in ``roots``."""
        root_list = [r.strip().lower().lstrip(".") for r in roots if r.strip()]
        if not root_list:
            return 0
        removed = 0

        def _is_owned(val: str) -> bool:
            low = val.lower()
            return any(low == r or low.endswith("." + r) for r in root_list)

        for fname in ("domain", "domain_suffix"):
            before = self.get_field(fname)
            kept = [v for v in before if not _is_owned(v)]
            removed += len(before) - len(kept)
            self.set_field(fname, kept)
        return removed

    def apply_patch(self, patch_doc: dict) -> tuple[int, int]:
        """Apply a ``zhbcn-patch/v1`` document. Returns (added, removed)."""
        added = 0
        removed = 0
        for fname, items in (patch_doc.get("remove") or {}).items():
            if fname not in RULE_FIELDS:
                raise ValueError(f"Unsupported patch remove field: {fname}")
            targets = {
                normalize_value(fname, str(x)).lower()
                if fname not in {"domain_regex", "url_regex"}
                else normalize_value(fname, str(x))
                for x in (items or [])
            }
            before = self.get_field(fname)
            kept = [
                v for v in before
                if (v.lower() if fname not in {"domain_regex", "url_regex"} else v) not in targets
            ]
            removed += len(before) - len(kept)
            self.set_field(fname, kept)
        for fname, items in (patch_doc.get("add") or {}).items():
            if fname not in RULE_FIELDS:
                raise ValueError(f"Unsupported patch add field: {fname}")
            for x in (items or []):
                self.add(fname, str(x))
                added += 1
        self.dedupe_and_sort()
        return added, removed

    def count(self) -> int:
        return sum(len(self.get_field(f)) for f in RULE_FIELDS)

    def has_ip_or_asn(self) -> bool:
        return bool(self.ip_cidr or self.ip_cidr6 or self.ip_asn)

    def has_classical_only(self) -> bool:
        return bool(
            self.domain_keyword
            or self.domain_wildcard
            or self.domain_regex
            or self.ip_asn
            or self.and_rules
        )

    def to_dict(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for fname in RULE_FIELDS:
            vals = self.get_field(fname)
            if vals:
                out[fname] = list(vals)
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "RuleSet":
        rs = cls()
        if not isinstance(data, dict):
            raise ValueError("rules section must be a mapping")
        for fname, items in data.items():
            if fname not in RULE_FIELDS:
                raise ValueError(f"Unsupported canonical rule field: {fname}")
            if not isinstance(items, list):
                raise ValueError(f"rules.{fname} must be a list")
            for item in items:
                rs.add(fname, str(item))
        return rs


def normalize_value(field_name: str, value: str) -> str:
    val = value.strip()
    if not val:
        raise ValueError(f"Empty value for {field_name}")
    if field_name in {"domain", "domain_suffix", "domain_keyword", "domain_wildcard"}:
        val = val.lower()
        if field_name in {"domain", "domain_suffix"}:
            if val.startswith((".", "*", "+")) or "," in val or " " in val:
                raise ValueError(f"Invalid {field_name} value: {value!r}")
        return val
    if field_name == "ip_cidr":
        net = ipaddress.ip_network(val, strict=False)
        if net.version != 4:
            raise ValueError(f"Expected IPv4 CIDR, got: {value!r}")
        return str(net)
    if field_name == "ip_cidr6":
        net = ipaddress.ip_network(val, strict=False)
        if net.version != 6:
            raise ValueError(f"Expected IPv6 CIDR, got: {value!r}")
        return str(net)
    if field_name == "ip_asn":
        if not re.fullmatch(r"\d+", val):
            raise ValueError(f"Invalid ASN value: {value!r}")
        return val
    if field_name == "domain_regex":
        re.compile(val)
        return val
    if field_name == "url_regex":
        re.compile(val)
        return val
    if field_name == "and":
        if not val.startswith("((") or not val.endswith("))"):
            # Accept full "AND,((...))" by stripping leading "AND,"
            if val.upper().startswith("AND,"):
                val = val[4:].strip()
            else:
                raise ValueError(f"Invalid AND expression: {value!r}")
        return val
    raise ValueError(f"Unsupported field: {field_name}")


def load_source_file(path: Path) -> tuple[dict, RuleSet]:
    """Load and validate a ``zhbcn-rules/v1`` YAML file."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: expected top-level mapping")
    if doc.get("schema") != RULE_SCHEMA_VERSION:
        raise ValueError(f"{path}: expected schema={RULE_SCHEMA_VERSION!r}, got {doc.get('schema')!r}")
    if not isinstance(doc.get("name"), str) or not doc["name"].strip():
        raise ValueError(f"{path}: missing string 'name'")
    if doc.get("kind") not in {"upstream", "custom"}:
        raise ValueError(f"{path}: kind must be 'upstream' or 'custom'")
    rs = RuleSet.from_dict(doc.get("rules") or {})
    return doc, rs


def dump_source_file(
    path: Path,
    *,
    name: str,
    kind: str,
    source: dict,
    ruleset: RuleSet,
    notes: str | None = None,
) -> str:
    """Serialize a canonical ``zhbcn-rules/v1`` YAML document with LF endings."""
    ruleset.dedupe_and_sort()
    doc: dict = {
        "schema": RULE_SCHEMA_VERSION,
        "name": name,
        "kind": kind,
        "source": source,
    }
    if notes:
        doc["notes"] = notes
    doc["rules"] = ruleset.to_dict()
    text = yaml.safe_dump(
        doc,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=1000,
    )
    text = text.replace("\r\n", "\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return text


def load_patch_file(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(doc, dict) or doc.get("schema") != PATCH_SCHEMA_VERSION:
        raise ValueError(f"{path}: expected schema={PATCH_SCHEMA_VERSION!r}")
    if not isinstance(doc.get("target"), str) or not doc["target"].strip():
        raise ValueError(f"{path}: missing string 'target'")
    for section in ("add", "remove"):
        val = doc.get(section)
        if val is not None and not isinstance(val, dict):
            raise ValueError(f"{path}: '{section}' must be a mapping")
    return doc
