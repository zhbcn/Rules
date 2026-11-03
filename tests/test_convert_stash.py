import tempfile
import unittest
from pathlib import Path

from scripts.convert_stash import (
    adapt_config,
    check_stash_pairs,
    render_service,
    split_rules,
    validate_text,
)


class StashConversionTest(unittest.TestCase):
    def test_exact_suffix_and_ip_resolution_boundaries(self):
        parts, omitted = split_rules([
            "DOMAIN,example.com", "DOMAIN-SUFFIX,example.org",
            "IP-CIDR,192.0.2.7/24,no-resolve", "DOMAIN,other.example",
            "IP-CIDR6,2001:db8::1/32", "DOMAIN-REGEX,^api[0-9]+\\.example$",
        ])
        self.assertEqual([part.name for part in parts], ["Domain", "IPNoResolve", "Domain2", "IP", "Classical"])
        self.assertEqual(parts[0].payload, ("example.com", "+.example.org"))
        self.assertEqual(parts[1].payload, ("192.0.2.0/24",))
        self.assertTrue(parts[1].no_resolve)
        self.assertEqual(parts[3].payload, ("2001:db8::/32",))
        self.assertFalse(parts[3].no_resolve)
        self.assertEqual(parts[4].payload, ("DOMAIN-REGEX,^api[0-9]+\\.example$",))
        self.assertEqual(omitted, [])

    def test_classical_logic_is_preserved_without_approximation(self):
        rule = "AND,((DOMAIN-KEYWORD,track),(DOMAIN-SUFFIX,example.com))"
        parts, _ = split_rules([rule, "DOMAIN-WILDCARD,*.example?.com", "IP-ASN,13335,no-resolve"])
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0].behavior, "classical")
        self.assertEqual(parts[0].payload[0], rule)

    def test_ios_process_omission_is_visible_and_unknown_conditions_fail(self):
        output, _ = render_service(
            "# SOURCE: test\npayload:\n  - DOMAIN,example.com\n  - PROCESS-NAME,example.exe\n",
            Path("Technology/Example.yaml"),
        )
        text = output[Path("Technology/Example/Domain.list")]
        self.assertIn("# SOURCE: test", text)
        self.assertIn("PLATFORM-OMITTED", text)
        self.assertNotIn("\nPROCESS-NAME,example.exe\n", text)
        for rule in ("UID,42", "AND,((DOMAIN,example.com),(PROCESS-NAME,example.exe))", "IP-CIDR6,192.0.2.0/24"):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                split_rules([rule])

    def test_independent_native_grammar_validation(self):
        self.assertEqual(validate_text("example.com\n+.example.org\n", "domain"), [])
        self.assertTrue(validate_text("DOMAIN,example.com\n", "domain"))
        self.assertTrue(validate_text("192.0.2.7/24\n", "ipcidr"))
        self.assertTrue(validate_text("192.0.2.0/24,no-resolve\n", "ipcidr"))
        self.assertTrue(validate_text("# comment only\n", "domain"))

    def test_generation_check_detects_missing_stale_and_modified_components(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "Ruleset/Mihomo/Example.yaml"
            source.parent.mkdir(parents=True)
            source.write_text("payload:\n  - DOMAIN,example.com\n", encoding="utf-8")
            errors = []
            check_stash_pairs(root, errors)
            self.assertTrue(any("PAIR MISSING" in item for item in errors))
            target = root / "Ruleset/Stash/Example/Domain.list"
            target.parent.mkdir(parents=True)
            target.write_text("wrong.example\n", encoding="utf-8")
            (target.parent / "Classical.list").write_text("DOMAIN-KEYWORD,ads\n", encoding="utf-8")
            errors = []
            check_stash_pairs(root, errors)
            self.assertTrue(any("PAIR MISMATCH" in item for item in errors))
            self.assertTrue(any("PAIR EXTRA" in item for item in errors))

    def test_config_migration_preserves_order_dns_and_rule_options(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "Ruleset/Mihomo/AI/Example.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                "payload:\n  - DOMAIN,example.com\n  - DOMAIN-REGEX,^api[0-9]+\\.example$\n"
                "  - IP-CIDR,192.0.2.0/24,no-resolve\n  - DOMAIN-SUFFIX,example.org\n",
                encoding="utf-8",
            )
            document = {
                "proxy-groups": [{"name": "AIGC", "type": "select"}],
                "rule-providers": {"Example": {
                    "type": "http", "behavior": "classical", "format": "yaml", "interval": 86400,
                    "url": "https://raw.githubusercontent.com/zhbcn/Rules/main/Ruleset/Mihomo/AI/Example.yaml",
                }},
                "dns": {"proxy-server-nameserver": ["https://dns.example/dns-query"], "nameserver-policy": {
                    "node.example": ["system"], "rule-set:Example": ["https://ai.example/dns-query"],
                }},
                "rules": ["PROTOCOL,STUN,AIGC", "RULE-SET,Example,AIGC,no-track", "MATCH,AIGC"],
            }
            migrated = adapt_config(document, root)
            self.assertEqual(migrated["rules"], [
                "PROTOCOL,STUN,AIGC", "RULE-SET,Example-Domain,AIGC,no-track",
                "RULE-SET,Example-Classical,AIGC,no-track", "RULE-SET,Example-IPNoResolve,AIGC,no-track,no-resolve",
                "RULE-SET,Example-Domain2,AIGC,no-track", "MATCH,AIGC",
            ])
            self.assertEqual(list(migrated["dns"]["nameserver-policy"]), [
                "node.example", "rule-set:Example-Domain", "rule-set:Example-Classical", "rule-set:Example-Domain2",
            ])
            self.assertEqual(migrated["dns"]["proxy-server-nameserver"], document["dns"]["proxy-server-nameserver"])
            self.assertIn("Example", document["rule-providers"])
            self.assertEqual(migrated["rule-providers"]["Example-Domain"]["behavior"], "domain")
            self.assertEqual(migrated["rule-providers"]["Example-IPNoResolve"]["format"], "text")
            self.assertEqual(adapt_config(migrated, root), migrated)

            # Upstream adds a new component; refreshing a native profile must wire it in.
            with source.open("a", encoding="utf-8") as output:
                output.write("  - DOMAIN-KEYWORD,new-service\n")
            refreshed = adapt_config(migrated, root)
            self.assertIn("Example-Classical2", refreshed["rule-providers"])
            self.assertIn("RULE-SET,Example-Classical2,AIGC,no-track", refreshed["rules"])
            self.assertIn("rule-set:Example-Classical2", refreshed["dns"]["nameserver-policy"])


if __name__ == "__main__":
    unittest.main()
