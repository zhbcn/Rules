#!/usr/bin/env python3
"""Sync reviewed Chinese AI services from a LOCAL V2Fly data snapshot.

No network requests, subscriptions, client reloads, or publication. Existing
service rules are retained as custom entries; removal needs an explicit review.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

if __package__:
    from .convert_v2fly import Rule, V2FlyConverter, dedupe, render_egern, render_mihomo
else:
    from convert_v2fly import Rule, V2FlyConverter, dedupe, render_egern, render_mihomo

MANIFEST = Path(__file__).with_name('ai_services.json')
KINDS = {'DOMAIN-SUFFIX': 'domain', 'DOMAIN': 'full', 'DOMAIN-KEYWORD': 'keyword', 'DOMAIN-REGEX': 'regexp'}


def load_manifest(path: Path = MANIFEST) -> dict:
    data = json.loads(path.read_text(encoding='utf-8'))
    names = [s['name'] for s in data['services']]
    if len(names) != len(set(names)) or any(not name.isalnum() for name in names):
        raise ValueError('Service names must be unique alphanumeric identifiers')
    for service in data['services']:
        if service['policy'] not in {'DIRECT', 'DIRECT_WITH_EXCEPTIONS'}:
            raise ValueError('Unexpected routing intent')
        if any(not root or '/' in root or root.startswith('.') for root in service['roots'] + service['custom']):
            raise ValueError('Expected explicit domain roots')
    return data


def owned(rule: Rule, roots: list[str]) -> bool:
    # Aggregates are filtered only by explicit domain ownership, never keyword
    # or regular-expression guesses. Independent service lists need no filter.
    return rule.kind in {'domain', 'full'} and any(rule.value == root or rule.value.endswith('.' + root) for root in roots)


def existing_rules(path: Path) -> list[Rule]:
    if not path.exists():
        return []
    document = yaml.safe_load(path.read_text(encoding='utf-8-sig'))
    rules = []
    for text in document['payload']:
        kind, value = text.split(',', 1)
        if kind not in KINDS:
            raise ValueError(f'{path.name}: unsupported existing rule {kind}; review instead of discarding')
        rules.append(Rule(KINDS[kind], value, frozenset()))
    return rules


def collect_service(converter: V2FlyConverter, service: dict, retained: list[Rule]) -> list[Rule]:
    incoming = []
    for name in service['lists']:
        rules = converter.read(name)
        if service['roots']:
            rules = [r for r in rules if owned(r, service['roots'])]
        incoming.extend(rules)
    incoming.extend(Rule('domain', domain, frozenset()) for domain in service['custom'])
    if not incoming:
        raise ValueError(f"{service['name']}: no upstream/custom rules; check the snapshot and selectors")
    return dedupe(retained + incoming)


def direct_rules(rules: list[Rule], exceptions: list[str]) -> list[Rule]:
    # Fail closed on non-domain conditions; never turn a keyword or shared
    # IP/CDN range into a company-wide DIRECT rule automatically.
    return [r for r in rules if r.kind in {'domain', 'full'} and not owned(r, exceptions)]


def append_cn(text: str, additions: list[Rule], egern: bool) -> str:
    document = yaml.safe_load(text)
    if egern:
        import re
        for kind, key in [('full', 'domain_set'), ('domain', 'domain_suffix_set')]:
            present = set(document.get(key, []))
            missing = list(dict.fromkeys(r.value for r in additions if r.kind == kind and r.value not in present))
            if not missing:
                continue
            extra = ''.join(f'  - {value}\n' for value in missing)
            section = re.search(r'^' + key + r':\n(?:(?!^[A-Za-z_]+:).)*', text, re.M | re.S)
            if section:
                replacement = section.group().rstrip('\n') + '\n' + extra + '\n'
                text = text[:section.start()] + replacement + text[section.end():]
            else:
                text = text.rstrip('\n') + '\n\n' + key + ':\n' + extra
        return text
    present = set(document['payload'])
    extra = ''.join(f'  - {"DOMAIN" if r.kind == "full" else "DOMAIN-SUFFIX"},{r.value}\n' for r in additions if r.kind in {'domain', 'full'} and f'{"DOMAIN" if r.kind == "full" else "DOMAIN-SUFFIX"},{r.value}' not in present)
    return text.rstrip('\n') + '\n' + extra if extra else text


def build_outputs(root: Path, data_dir: Path, manifest: dict) -> dict[Path, str]:
    converter = V2FlyConverter(data_dir)
    outputs = {}
    aggregate = list(converter.read('category-ai-cn'))
    for service in manifest['services']:
        relative = Path('AI') / (service['name'] + '.yaml')
        mihomo = root / 'Ruleset/Mihomo' / relative
        rules = collect_service(converter, service, existing_rules(mihomo))
        outputs[mihomo] = render_mihomo(service['name'], rules, service['lists'])
        outputs[root / 'Ruleset/Egern' / relative] = render_egern(service['name'], rules, service['lists'])
        aggregate.extend(rules)
    aggregate = direct_rules(dedupe(aggregate), manifest['proxy_exceptions'])
    for platform, render in [('Mihomo', render_mihomo), ('Egern', render_egern)]:
        outputs[root / f'Ruleset/{platform}/AI/ChinaAI.yaml'] = render('ChinaAI', aggregate, ['category-ai-cn', 'scripts/ai_services.json (reviewed global domains; proxy exceptions excluded)'])
        cn = root / f'Ruleset/{platform}/Direct/cn.yaml'
        outputs[cn] = append_cn(cn.read_text(encoding='utf-8-sig'), aggregate, platform == 'Egern')
    return outputs


def check_ai_resources(root: Path, errors: list[str]) -> None:
    """Check published-format invariants without needing an upstream checkout."""
    manifest_path = root / 'scripts/ai_services.json'
    if not manifest_path.exists():
        return  # Small standalone test fixtures need not contain the AI catalog.
    manifest = load_manifest(manifest_path)
    aggregate = root / 'Ruleset/Mihomo/AI/ChinaAI.yaml'
    if not aggregate.exists():
        errors.append('AI: missing ChinaAI aggregate')
        return
    rules = existing_rules(aggregate)
    for rule in rules:
        if rule not in direct_rules([rule], manifest['proxy_exceptions']):
            errors.append(f'AI: proxy exception or unsafe condition leaked into ChinaAI: {rule.value}')
    aggregate_keys = {(r.kind, r.value) for r in rules}
    cn_keys = {(r.kind, r.value) for r in existing_rules(root / 'Ruleset/Mihomo/Direct/cn.yaml')}
    for service in manifest['services']:
        path = root / 'Ruleset/Mihomo/AI' / (service['name'] + '.yaml')
        if not path.exists():
            errors.append(f"AI: missing service {service['name']}")
            continue
        expected = direct_rules(existing_rules(path), manifest['proxy_exceptions'])
        for rule in expected:
            if (rule.kind, rule.value) not in aggregate_keys:
                errors.append(f'AI: ChinaAI missing {service["name"]}: {rule.value}')
    for kind, value in aggregate_keys:
        if kind in {'domain', 'full'} and (kind, value) not in cn_keys:
            errors.append(f'AI: cn compatibility aggregate missing {value}')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True, help='Local V2Fly data directory; never fetched by this script')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check', action='store_true', help='Report stale outputs without writing')
    args = parser.parse_args()
    outputs = build_outputs(args.root, args.data, load_manifest())
    changed = []
    for path, text in outputs.items():
        previous = path.read_bytes() if path.exists() else b''
        newline = '\r\n' if b'\r\n' in previous else '\n'
        expected = text.replace('\r\n', '\n').replace('\n', newline).encode('utf-8')
        if previous != expected:
            changed.append(path)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(expected)
    for path in changed:
        print(('STALE' if args.check else 'UPDATED'), path.relative_to(args.root))
    print(f'AI sync: {len(outputs)} source outputs; {len(changed)} changed; no network operations')
    return int(args.check and bool(changed))


if __name__ == '__main__':
    raise SystemExit(main())
