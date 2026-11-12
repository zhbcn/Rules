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

    def test_accepts_egern_no_resolve_metadata(self):
        for value in (True, False):
            with self.subTest(value=value):
                errors = []
                check_egern_document(
                    {"no_resolve": value, "ip_cidr_set": ["160.79.104.0/23"]},
                    "rules.yaml",
                    errors,
                )
                self.assertEqual(errors, [])

    def test_rejects_non_boolean_egern_no_resolve(self):
        for value in ("true", 1, None, []):
            with self.subTest(value=value):
                errors = []
                check_egern_document(
                    {"no_resolve": value, "ip_cidr_set": ["160.79.104.0/23"]},
                    "rules.yaml",
                    errors,
                )
                self.assertEqual(
                    errors, ["SCHEMA rules.yaml: no_resolve is not a boolean"]
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

    def test_egern_local_proxy_is_a_valid_group_and_rule_policy(self):
        document = {
            "proxies": [{"tailscale": {"name": "Local Tailnet"}}],
            "policy_groups": [{"select": {"name": "Proxy", "policies": ["Local Tailnet"]}}],
            "rules": [{"default": {"policy": "Local Tailnet"}}],
        }
        errors = []
        check_config_document(document, "Egern.yaml", errors)
        self.assertEqual(errors, [])

        document["proxies"] = []
        errors = []
        check_config_document(document, "Egern.yaml", errors)
        self.assertEqual(errors, [
            "CONFIG Egern.yaml: policy group Proxy references missing policy Local Tailnet",
            "CONFIG Egern.yaml: rule <unnamed> references missing policy Local Tailnet",
        ])

    def test_egern_rejects_malformed_and_duplicate_local_proxies(self):
        for proxies, expected in (
            ({}, "proxies is not a list"),
            ([{}], "malformed proxy"),
            ([{"tailscale": {}}], "proxy has no string name"),
            ([{"tailscale": {"name": "Local"}}] * 2, "duplicate name: Local"),
        ):
            with self.subTest(proxies=proxies):
                errors = []
                check_config_document({"proxies": proxies, "policy_groups": []}, "Egern.yaml", errors)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_egern_rejects_proxy_and_group_name_collision(self):
        errors = []
        check_config_document({
            "proxies": [{"tailscale": {"name": "Proxy"}}],
            "policy_groups": [{"select": {"name": "Proxy"}}],
        }, "Egern.yaml", errors)
        self.assertEqual(errors, ["CONFIG Egern.yaml: duplicate policy name: Proxy"])

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

    def test_stash_protocol_proxy_requires_explicit_stash_validation(self):
        document = {
            "proxy-groups": [{"name": "Public network", "type": "select"}],
            "rules": ["PROTOCOL,STUN,Public network", "MATCH,Public network"],
        }
        errors = []
        check_config_document(document, "Stash.yaml", errors, stash=True)
        self.assertEqual(errors, [])

        errors = []
        check_config_document(document, "Mihomo.yaml", errors)
        self.assertEqual(errors, ["CONFIG Mihomo.yaml: unsupported Mihomo rule type PROTOCOL"])

    def test_stash_protocol_rejects_invalid_protocol_and_missing_policy(self):
        for rule, expected in (
            ("PROTOCOL,UNKNOWN,DIRECT", "invalid Stash PROTOCOL rule"),
            ("PROTOCOL,STUN,Missing", "rule references missing policy Missing"),
            ("PROTOCOL,STUN", "invalid Stash PROTOCOL rule"),
            ("PROTOCOL,STUN,DIRECT,pre-matching", "invalid Stash PROTOCOL rule"),
        ):
            with self.subTest(rule=rule):
                errors = []
                check_config_document({"rules": [rule], "proxy-groups": []}, "Stash.yaml", errors, stash=True)
                self.assertEqual(errors, [f"CONFIG Stash.yaml: {expected}"])

    def test_stash_protocol_supports_no_track_but_rejects_mihomo_only_rules(self):
        errors = []
        check_config_document(
            {"proxy-groups": [], "rules": ["PROTOCOL,STUN,DIRECT,no-track", "DSCP,46,DIRECT"]},
            "Stash.yaml", errors, stash=True,
        )
        self.assertEqual(errors, ["CONFIG Stash.yaml: unsupported Stash rule type DSCP"])

    def test_stash_native_provider_behavior_and_format(self):
        url = "https://raw.githubusercontent.com/zhbcn/Rules/main/Ruleset/Stash/AI/Example/Domain.list"
        for behavior, format_, expected in (("domain", "text", False), ("classical", "yaml", True)):
            with self.subTest(behavior=behavior):
                document = {
                    "proxy-groups": [{"name": "Proxy"}],
                    "rule-providers": {"Example-Domain": {"url": url, "behavior": behavior, "format": format_}},
                    "rules": ["RULE-SET,Example-Domain,Proxy"],
                }
                errors = []
                check_config_document(document, "Stash.yaml", errors, stash=True)
                self.assertEqual(bool(errors), expected)

if __name__ == "__main__":
    unittest.main()
