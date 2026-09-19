import tempfile
import unittest
from pathlib import Path

from scripts.check import (
    check_config_document,
    check_egern_document,
    check_mihomo_document,
    check_mihomo_egern_pairs,
    load_yaml,
)


class EgernYamlTest(unittest.TestCase):
    def test_native_and_set_tags_parse_safely(self):
        document = load_yaml(
            """and_set:
  - - !protocol
      match: udp
    - !domain_suffix
      match: googlevideo.com
"""
        )

        self.assertEqual(
            document,
            {
                "and_set": [
                    [
                        {"match": "udp"},
                        {"match": "googlevideo.com"},
                    ]
                ]
            },
        )

    def test_rejects_unsupported_mihomo_rule_type(self):
        errors = []

        check_mihomo_document(
            {"payload": ["DOMAIN-SUFFIX,example.com", "URL-REGEX,/tracking"]},
            "rules.yaml",
            errors,
        )

        self.assertEqual(
            errors,
            ["RULE-TYPE rules.yaml: unsupported Mihomo rule type: URL-REGEX"],
        )

    def test_rejects_unsupported_nested_mihomo_rule_type(self):
        errors = []

        check_mihomo_document(
            {"payload": ["AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,example.com))"]},
            "rules.yaml",
            errors,
        )

        self.assertEqual(
            errors,
            ["RULE-TYPE rules.yaml: unsupported Mihomo rule type: PROTOCOL"],
        )

    def test_rejects_unsupported_egern_rule_set_type(self):
        errors = []

        check_egern_document({"url_path_regex_set": ["/tracking"]}, "rules.yaml", errors)

        self.assertEqual(
            errors,
            ["RULE-TYPE rules.yaml: unsupported Egern rule-set type: url_path_regex_set"],
        )

    def test_checks_mihomo_config_reference_closure(self):
        errors = []
        document = {
            "proxy-groups": [{"name": "Proxy", "use": ["missing-subscription"]}],
            "proxy-providers": {},
            "rule-providers": {},
            "rules": ["RULE-SET,missing-rules,Missing policy", "MATCH,Proxy"],
        }

        check_config_document(document, "config.yaml", errors)

        self.assertIn(
            "CONFIG config.yaml: proxy group Proxy uses missing provider missing-subscription",
            errors,
        )
        self.assertIn(
            "CONFIG config.yaml: RULE-SET references missing provider missing-rules",
            errors,
        )
        self.assertIn(
            "CONFIG config.yaml: rule references missing policy Missing policy",
            errors,
        )

    def test_checks_mihomo_config_rule_type(self):
        errors = []
        document = {
            "proxy-groups": [{"name": "Proxy"}],
            "rule-providers": {},
            "rules": ["URL-REGEX,/tracking,Proxy"],
        }

        check_config_document(document, "config.yaml", errors)

        self.assertEqual(
            errors,
            ["CONFIG config.yaml: unsupported Mihomo rule type URL-REGEX"],
        )

    def test_checks_mihomo_egern_pair_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mihomo = root / "Ruleset" / "Mihomo" / "Test.yaml"
            egern = root / "Ruleset" / "Egern" / "Test.yaml"
            mihomo.parent.mkdir(parents=True)
            egern.parent.mkdir(parents=True)
            mihomo.write_text("payload:\n  - DOMAIN-SUFFIX,example.com\n", encoding="utf-8")
            egern.write_text("domain_suffix_set:\n  - different.example\n", encoding="utf-8")
            errors = []

            check_mihomo_egern_pairs(root, errors)

            self.assertEqual(
                errors,
                ["PAIR MISMATCH Test.yaml: 1 Mihomo-only, 1 Egern-only comparable rule(s)"],
            )

if __name__ == "__main__":
    unittest.main()
