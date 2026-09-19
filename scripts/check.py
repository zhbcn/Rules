#!/usr/bin/env python3
"""Run the small, repository-local checks used by zhbcn/Rules."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml


REPO_MARKERS = (
    "/zhbcn/Rules/main/",
    "/zhbcn/Rules/refs/heads/main/",
    "/zhbcn/Rules/raw/refs/heads/main/",
    "/zhbcn/Rules/raw/main/",
)

MIHOMO_RULE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "DOMAIN-REGEX", "GEOSITE", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX",
    "IP-ASN", "GEOIP", "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR",
    "SRC-IP-SUFFIX", "DST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE",
    "IN-USER", "IN-NAME", "REMATCH-NAME", "PROCESS-PATH",
    "PROCESS-PATH-WILDCARD", "PROCESS-PATH-REGEX", "PROCESS-NAME",
    "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX", "UID", "NETWORK",
    "DSCP", "RULE-SET", "AND", "OR", "NOT", "SUB-RULE", "MATCH",
}

MIHOMO_BUILTIN_POLICIES = {
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL",
}

EGERN_BUILTIN_POLICIES = {
    "DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP",
}

EGERN_TO_MIHOMO_TYPES = {
    "domain_set": "DOMAIN",
    "domain_suffix_set": "DOMAIN-SUFFIX",
    "domain_keyword_set": "DOMAIN-KEYWORD",
    "domain_wildcard_set": "DOMAIN-WILDCARD",
    "domain_regex_set": "DOMAIN-REGEX",
    "ip_cidr_set": "IP-CIDR",
    "ip_cidr6_set": "IP-CIDR6",
    "asn_set": "IP-ASN",
}

EGERN_RULE_SET_TYPES = set(EGERN_TO_MIHOMO_TYPES) | {
    "url_regex_set", "user_agent_set", "process_name_set", "process_path_set",
    "geoip_set", "dest_port_set", "src_port_set", "protocol_set", "and_set",
    "or_set", "not_set",
}


class EgernSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that accepts Egern's rule-type tags."""


def _construct_egern_tag(loader: EgernSafeLoader, _suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


EgernSafeLoader.add_multi_constructor("!", _construct_egern_tag)


def load_yaml(text: str) -> object:
    return yaml.load(text, Loader=EgernSafeLoader)


def repo_path_from_url(url: str) -> str | None:
    path = unquote(urlparse(url).path)
    for marker in REPO_MARKERS:
        if marker in path:
            return path.split(marker, 1)[1]
    return None


def duplicate_values(document: object) -> list[str]:
    duplicates: list[str] = []
    if not isinstance(document, dict):
        return ["top level is not a mapping"]
    for key, value in document.items():
        if not isinstance(value, list):
            continue
        seen: set[str] = set()
        for item in value:
            marker = str(item).strip().lower()
            if marker in seen:
                duplicates.append(f"{key}: {item}")
            seen.add(marker)
    return duplicates


def check_mihomo_document(document: object, label: str, errors: list[str]) -> None:
    if not isinstance(document, dict) or set(document) != {"payload"}:
        errors.append(f"SCHEMA {label}: expected only a payload list")
        return
    payload = document.get("payload")
    if not isinstance(payload, list):
        errors.append(f"SCHEMA {label}: payload is not a list")
        return
    for item in payload:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"RULE {label}: payload item is not a non-empty string: {item!r}")
            continue
        rule_types = [item.split(",", 1)[0].strip().upper()]
        if rule_types[0] in {"AND", "OR", "NOT"}:
            rule_types.extend(
                match.group(1)
                for match in re.finditer(r"\(\(?([A-Z][A-Z0-9-]*),", item.upper())
            )
        for rule_type in rule_types:
            if rule_type not in MIHOMO_RULE_TYPES:
                errors.append(f"RULE-TYPE {label}: unsupported Mihomo rule type: {rule_type}")


def check_egern_document(document: object, label: str, errors: list[str]) -> None:
    if not isinstance(document, dict) or not document:
        errors.append(f"SCHEMA {label}: expected a non-empty mapping of Egern rule sets")
        return
    for key, value in document.items():
        if key not in EGERN_RULE_SET_TYPES:
            errors.append(f"RULE-TYPE {label}: unsupported Egern rule-set type: {key}")
        if not isinstance(value, list):
            errors.append(f"SCHEMA {label}: {key} is not a list")


def _unique_names(items: object, label: str, errors: list[str]) -> set[str]:
    names: set[str] = set()
    if not isinstance(items, list):
        errors.append(f"CONFIG {label}: expected a list")
        return names
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            errors.append(f"CONFIG {label}: item has no string name")
            continue
        name = item["name"]
        if name in names:
            errors.append(f"CONFIG {label}: duplicate name: {name}")
        names.add(name)
    return names


def check_mihomo_config(document: dict[str, object], label: str, errors: list[str]) -> None:
    groups = document.get("proxy-groups", [])
    group_names = _unique_names(groups, f"{label} proxy-groups", errors)
    proxy_providers = document.get("proxy-providers", {}) or {}
    rule_providers = document.get("rule-providers", {}) or {}
    if not isinstance(proxy_providers, dict) or not isinstance(rule_providers, dict):
        errors.append(f"CONFIG {label}: provider sections must be mappings")
        return

    provider_urls: set[str] = set()
    for name, provider in rule_providers.items():
        if not isinstance(provider, dict):
            errors.append(f"CONFIG {label}: rule provider {name} is not a mapping")
            continue
        url = provider.get("url")
        if isinstance(url, str):
            if url in provider_urls:
                errors.append(f"CONFIG {label}: duplicate rule provider URL for {name}")
            provider_urls.add(url)
            if repo_path_from_url(url):
                if provider.get("type") != "http":
                    errors.append(f"CONFIG {label}: repository rule provider {name} must use type http")
                if provider.get("behavior") != "classical":
                    errors.append(f"CONFIG {label}: repository rule provider {name} must use behavior classical")
                if provider.get("format") != "yaml":
                    errors.append(f"CONFIG {label}: repository rule provider {name} must use format yaml")

    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        for provider in group.get("use", []) or []:
            if provider not in proxy_providers:
                errors.append(f"CONFIG {label}: proxy group {group.get('name')} uses missing provider {provider}")

    rules = document.get("rules", [])
    if not isinstance(rules, list):
        errors.append(f"CONFIG {label}: rules is not a list")
        return
    allowed_policies = group_names | MIHOMO_BUILTIN_POLICIES
    for rule in rules:
        if not isinstance(rule, str):
            errors.append(f"CONFIG {label}: rule is not a string: {rule!r}")
            continue
        parts = [part.strip() for part in rule.split(",")]
        rule_type = parts[0].upper()
        if rule_type not in MIHOMO_RULE_TYPES and rule_type != "FINAL":
            errors.append(f"CONFIG {label}: unsupported Mihomo rule type {rule_type}")
            continue
        if rule_type == "RULE-SET" and len(parts) >= 3:
            if parts[1] not in rule_providers:
                errors.append(f"CONFIG {label}: RULE-SET references missing provider {parts[1]}")
            policy = parts[2]
        elif rule_type in {"MATCH", "FINAL"} and len(parts) >= 2:
            policy = parts[1]
        else:
            continue
        if policy not in allowed_policies:
            errors.append(f"CONFIG {label}: rule references missing policy {policy}")


def check_egern_config(document: dict[str, object], label: str, errors: list[str]) -> None:
    policy_groups = document.get("policy_groups", [])
    group_bodies: list[dict[str, object]] = []
    if not isinstance(policy_groups, list):
        errors.append(f"CONFIG {label}: policy_groups is not a list")
        return
    for tagged in policy_groups:
        if not isinstance(tagged, dict) or len(tagged) != 1:
            errors.append(f"CONFIG {label}: malformed policy group")
            continue
        body = next(iter(tagged.values()))
        if not isinstance(body, dict) or not isinstance(body.get("name"), str):
            errors.append(f"CONFIG {label}: policy group has no string name")
            continue
        group_bodies.append(body)
    group_names = _unique_names(group_bodies, f"{label} policy_groups", errors)
    allowed_policies = group_names | EGERN_BUILTIN_POLICIES
    for group in group_bodies:
        for policy in group.get("policies", []) or []:
            if policy not in allowed_policies:
                errors.append(f"CONFIG {label}: policy group {group['name']} references missing policy {policy}")

    rules = document.get("rules", [])
    if not isinstance(rules, list):
        errors.append(f"CONFIG {label}: rules is not a list")
        return
    rule_names: set[str] = set()
    for tagged in rules:
        if not isinstance(tagged, dict) or len(tagged) != 1:
            errors.append(f"CONFIG {label}: malformed Egern rule")
            continue
        body = next(iter(tagged.values()))
        if not isinstance(body, dict):
            errors.append(f"CONFIG {label}: malformed Egern rule body")
            continue
        name = body.get("name")
        if isinstance(name, str):
            if name in rule_names:
                errors.append(f"CONFIG {label}: duplicate rule name {name}")
            rule_names.add(name)
        policy = body.get("policy")
        if isinstance(policy, str) and policy not in allowed_policies:
            errors.append(f"CONFIG {label}: rule {name or '<unnamed>'} references missing policy {policy}")


def check_config_document(document: object, label: str, errors: list[str]) -> None:
    if not isinstance(document, dict):
        errors.append(f"CONFIG {label}: top level is not a mapping")
    elif "proxy-groups" in document or "rule-providers" in document:
        check_mihomo_config(document, label, errors)
    elif "policy_groups" in document:
        check_egern_config(document, label, errors)


def comparable_rules(document: object, area: str) -> set[tuple[str, str]]:
    if not isinstance(document, dict):
        return set()
    if area == "Mihomo":
        result: set[tuple[str, str]] = set()
        for item in document.get("payload", []):
            parts = str(item).split(",")
            if len(parts) >= 2 and parts[0] in EGERN_TO_MIHOMO_TYPES.values():
                result.add((parts[0], parts[1]))
        return result
    result: set[tuple[str, str]] = set()
    for egern_type, mihomo_type in EGERN_TO_MIHOMO_TYPES.items():
        values = document.get(egern_type, [])
        if isinstance(values, list):
            result.update((mihomo_type, str(value)) for value in values)
    return result


def check_mihomo_egern_pairs(root: Path, errors: list[str]) -> None:
    mihomo_root = root / "Ruleset" / "Mihomo"
    egern_root = root / "Ruleset" / "Egern"
    mihomo_paths = {path.relative_to(mihomo_root) for path in mihomo_root.rglob("*.yaml")}
    egern_paths = {path.relative_to(egern_root) for path in egern_root.rglob("*.yaml")}
    for path in sorted(mihomo_paths - egern_paths):
        errors.append(f"PAIR MISSING Egern/{path.as_posix()}")
    for path in sorted(egern_paths - mihomo_paths):
        errors.append(f"PAIR MISSING Mihomo/{path.as_posix()}")
    for relative in sorted(mihomo_paths & egern_paths):
        mihomo = load_yaml((mihomo_root / relative).read_text(encoding="utf-8-sig"))
        egern = load_yaml((egern_root / relative).read_text(encoding="utf-8-sig"))
        mihomo_rules = comparable_rules(mihomo, "Mihomo")
        egern_rules = comparable_rules(egern, "Egern")
        if mihomo_rules != egern_rules:
            errors.append(
                f"PAIR MISMATCH {relative.as_posix()}: "
                f"{len(mihomo_rules - egern_rules)} Mihomo-only, "
                f"{len(egern_rules - mihomo_rules)} Egern-only comparable rule(s)"
            )


# Aggregate rule sets: aggregate path -> independent member files whose rules
# must all be contained in the aggregate (union semantics, deduplicated).
# Aggregates may legitimately contain extra entries from upstream category lists.
AGGREGATES: dict[str, tuple[str, ...]] = {
    "Crypto/Crypto.yaml": (
        "Crypto/Aptos.yaml", "Crypto/AptosExplorer.yaml", "Crypto/Avalanche.yaml",
        "Crypto/Binance.yaml", "Crypto/Bitcoin.yaml", "Crypto/BitcoinCash.yaml",
        "Crypto/Bitget.yaml", "Crypto/Blockchair.yaml", "Crypto/Blockscout.yaml",
        "Crypto/BNBChain.yaml", "Crypto/Bybit.yaml", "Crypto/Cardano.yaml",
        "Crypto/Chainlink.yaml", "Crypto/Coinbase.yaml", "Crypto/CryptoCom.yaml",
        "Crypto/Dogecoin.yaml", "Crypto/Ethereum.yaml", "Crypto/EtherFi.yaml",
        "Crypto/Etherscan.yaml", "Crypto/Gate.yaml", "Crypto/HTX.yaml",
        "Crypto/Hyperliquid.yaml", "Crypto/Krak.yaml", "Crypto/Kraken.yaml",
        "Crypto/Mempool.yaml", "Crypto/MEXC.yaml", "Crypto/Monero.yaml",
        "Crypto/NEAR.yaml", "Crypto/OKX.yaml", "Crypto/PokePay.yaml",
        "Crypto/Polkadot.yaml", "Crypto/Polygon.yaml", "Crypto/SafePal.yaml",
        "Crypto/SAVO.yaml", "Crypto/Solana.yaml", "Crypto/Solscan.yaml",
        "Crypto/Starryblu.yaml", "Crypto/Stellar.yaml", "Crypto/Sui.yaml",
        "Crypto/SuiScan.yaml", "Crypto/Tether.yaml", "Crypto/TON.yaml",
        "Crypto/TONViewer.yaml", "Crypto/TRON.yaml", "Crypto/TRONSCAN.yaml",
        "Crypto/Uniswap.yaml", "Crypto/USDC.yaml", "Crypto/XRPL.yaml",
        "Crypto/XRPScan.yaml", "Crypto/Zcash.yaml",
    ),
    "Finance/Finance.yaml": (
        "Finance/MastercardCN.yaml", "Finance/N26.yaml",
        "Finance/PayPal.yaml", "Finance/Wise.yaml",
    ),
}


def rule_items(document: object) -> list[str]:
    """Flatten a Mihomo payload or Egern *_set document into 'TYPE,value' markers."""
    items: list[str] = []
    if not isinstance(document, dict):
        return items
    if isinstance(document.get("payload"), list):
        return [str(item) for item in document["payload"]]
    for key, value in document.items():
        if isinstance(key, str) and key.endswith("_set") and isinstance(value, list):
            for item in value:
                items.append(f"{key},{item}")
    return items


def check_aggregates(root: Path, errors: list[str]) -> None:
    for area in ("Mihomo", "Egern"):
        base = root / "Ruleset" / area
        for aggregate, members in AGGREGATES.items():
            aggregate_path = base / aggregate
            try:
                aggregate_rules = set(rule_items(load_yaml(aggregate_path.read_text(encoding="utf-8-sig"))))
            except Exception as exc:
                errors.append(f"AGGREGATE {area}/{aggregate}: {exc}")
                continue
            for member in members:
                try:
                    member_rules = set(rule_items(load_yaml((base / member).read_text(encoding="utf-8-sig"))))
                except Exception as exc:
                    errors.append(f"AGGREGATE {area}/{member}: {exc}")
                    continue
                for missing in sorted(member_rules - aggregate_rules):
                    errors.append(f"AGGREGATE-MISSING {area}/{aggregate}: member {member} rule not in aggregate: {missing}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, action="append", default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    checked = 0

    for area in (root / "Ruleset" / "Mihomo", root / "Ruleset" / "Egern"):
        for path in sorted(area.rglob("*.yaml")):
            checked += 1
            try:
                document = load_yaml(path.read_text(encoding="utf-8-sig"))
            except Exception as exc:
                errors.append(f"YAML {path.relative_to(root)}: {exc}")
                continue
            for duplicate in duplicate_values(document):
                errors.append(f"DUPLICATE {path.relative_to(root)}: {duplicate}")
            if area.name == "Mihomo":
                check_mihomo_document(document, str(path.relative_to(root)), errors)
            else:
                check_egern_document(document, str(path.relative_to(root)), errors)

    check_aggregates(root, errors)
    check_mihomo_egern_pairs(root, errors)

    url_pattern = re.compile(r"https://(?:raw\.githubusercontent\.com|github\.com)/zhbcn/Rules/[^\s\"']+")
    for config in args.config:
        try:
            text = config.read_text(encoding="utf-8-sig")
            document = load_yaml(text)
        except Exception as exc:
            errors.append(f"CONFIG {config}: {exc}")
            continue
        check_config_document(document, config.name, errors)
        for url in url_pattern.findall(text):
            relative = repo_path_from_url(url.rstrip("}),]"))
            if relative and not (root / relative).is_file():
                errors.append(f"MISSING {config.name}: {relative}")

    if errors:
        print("\n".join(errors))
        print(f"FAILED: {len(errors)} issue(s); checked {checked} rule files")
        return 1
    print(f"OK: checked {checked} rule files and {len(args.config)} config file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
