import json
from pathlib import Path
import tempfile
import unittest

from scripts.convert_v2fly import Rule, V2FlyConverter
from scripts.sync_ai import append_cn, check_ai_resources, collect_service, direct_rules, load_manifest
import yaml


class ChineseAISyncTest(unittest.TestCase):
    def rule(self, value, kind='domain'):
        return Rule(kind, value, frozenset())

    def test_aggregate_filters_do_not_capture_unrelated_service(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'category').write_text('kimi.ai\nfull:api.moonshot.ai\nopenai.com\nregexp:.*kimi.*\n')
            service = {'name': 'Kimi', 'lists': ['category'], 'roots': ['kimi.ai', 'moonshot.ai'], 'custom': ['kimi.com']}
            result = collect_service(V2FlyConverter(root), service, [self.rule('retained.example')])
            self.assertEqual([(r.kind, r.value) for r in result], [('domain', 'retained.example'), ('domain', 'kimi.ai'), ('full', 'api.moonshot.ai'), ('domain', 'kimi.com')])

    def test_no_upstream_match_fails_instead_of_dropping_custom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'category').write_text('unrelated.example\n')
            service = {'name': 'Kimi', 'lists': ['category'], 'roots': ['kimi.ai'], 'custom': []}
            with self.assertRaises(ValueError):
                collect_service(V2FlyConverter(root), service, [self.rule('retained.example')])

    def test_proxy_exceptions_include_subdomains_and_preserve_neighbors(self):
        values = ['minimax.io', 'talkie-ai.com', 'api.talkie-ai.com', 'not-talkie-ai.com']
        result = direct_rules([self.rule(v) for v in values] + [self.rule('minimax', 'keyword')], ['talkie-ai.com'])
        self.assertEqual([r.value for r in result], ['minimax.io', 'not-talkie-ai.com'])

    def test_egern_cn_append_stays_in_correct_sections_and_is_idempotent(self):
        text = 'domain_set:\n  - old.example\n\ndomain_suffix_set:\n  - old.cn\n\ndomain_regex_set:\n  - regex\n'
        rules = [self.rule('api.kimi.ai', 'full'), self.rule('kimi.ai')]
        result = append_cn(text, rules, True)
        doc = yaml.safe_load(result)
        self.assertEqual(doc['domain_set'], ['old.example', 'api.kimi.ai'])
        self.assertEqual(doc['domain_suffix_set'], ['old.cn', 'kimi.ai'])
        self.assertEqual(doc['domain_regex_set'], ['regex'])
        self.assertEqual(append_cn(result, rules, True), result)

    def test_mihomo_cn_append_preserves_regex_and_full_boundary(self):
        text = 'payload:\n  - DOMAIN-REGEX,example.*\n'
        rules = [self.rule('kimi.ai'), self.rule('api.moonshot.ai', 'full')]
        result = append_cn(text, rules, False)
        self.assertEqual(yaml.safe_load(result)['payload'], ['DOMAIN-REGEX,example.*', 'DOMAIN-SUFFIX,kimi.ai', 'DOMAIN,api.moonshot.ai'])
        self.assertEqual(append_cn(result, rules, False), result)

    def test_manifest_rejects_duplicate_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manifest.json'
            path.write_text(json.dumps({'services': [{'name': 'Kimi'}, {'name': 'Kimi'}]}))
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_ai_check_only_requires_aggregate_for_catalog_repositories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            errors = []
            check_ai_resources(root, errors)
            self.assertEqual(errors, [])
            (root / 'scripts').mkdir()
            (root / 'scripts/ai_services.json').write_text(json.dumps({'services': [], 'proxy_exceptions': []}))
            check_ai_resources(root, errors)
            self.assertEqual(errors, ['AI: missing ChinaAI aggregate'])

    def test_ai_check_detects_proxy_leak_and_missing_compatibility_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'scripts/ai_services.json').write_text(json.dumps({'services': [], 'proxy_exceptions': ['talkie-ai.com']}))
            (root / 'Ruleset/Mihomo/AI').mkdir(parents=True)
            (root / 'Ruleset/Mihomo/Direct').mkdir()
            (root / 'Ruleset/Mihomo/AI/ChinaAI.yaml').write_text('payload:\n  - DOMAIN-SUFFIX,talkie-ai.com\n  - DOMAIN,api.kimi.ai\n')
            (root / 'Ruleset/Mihomo/Direct/cn.yaml').write_text('payload: []\n')
            errors = []
            check_ai_resources(root, errors)
            self.assertTrue(any('proxy exception' in e for e in errors))
            self.assertTrue(any('missing api.kimi.ai' in e for e in errors))

    def test_catalog_intent_is_distinct_from_public_compatibility_sets(self):
        data = load_manifest()
        names = {s['name'] for s in data['services']}
        self.assertTrue({'Qwen', 'MiniMax', 'Kimi', 'DeepSeek', 'Zhipu'} <= names)
        self.assertIn('talkie-ai.com', data['proxy_exceptions'])
        self.assertIn('trae.ai', data['proxy_exceptions'])
        self.assertNotIn('qwen.ai', data['proxy_exceptions'])


if __name__ == '__main__':
    unittest.main()
