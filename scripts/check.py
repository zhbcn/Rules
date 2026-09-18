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

    check_aggregates(root, errors)

    url_pattern = re.compile(r"https://(?:raw\.githubusercontent\.com|github\.com)/zhbcn/Rules/[^\s\"']+")
    for config in args.config:
        try:
            text = config.read_text(encoding="utf-8-sig")
            load_yaml(text)
        except Exception as exc:
            errors.append(f"CONFIG {config}: {exc}")
            continue
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
