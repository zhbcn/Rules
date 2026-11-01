import tempfile
import unittest
from pathlib import Path

from scripts.convert_quantumultx import (
    check_quantumultx_pairs,
    convert_rule,
    render_filter,
)


class QuantumultXTest(unittest.TestCase):
    def test_native_rule_types_and_ip_options(self):
        cases = {
            "DOMAIN,api.example.com": "host,api.example.com,proxy",
            "DOMAIN-SUFFIX,example.com": "host-suffix,example.com,proxy",
            "DOMAIN-KEYWORD,example": "host-keyword,example,proxy",
            "DOMAIN-WILDCARD,*.example?.com": "host-wildcard,*.example?.com,proxy",
            "IP-CIDR,192.0.2.0/24": "ip-cidr,192.0.2.0/24,proxy",
            "IP-CIDR,192.0.2.0/24,no-resolve": "ip-cidr,192.0.2.0/24,proxy,no-resolve",
            "IP-CIDR6,2001:db8::/32,no-resolve": "ip6-cidr,2001:db8::/32,proxy,no-resolve",
            "IP-ASN,132203": "ip-asn,132203,proxy",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(convert_rule(source), expected)

    def test_unsupported_conditions_are_comments_without_broadening(self):
        for rule in (
            r"DOMAIN-REGEX,^cdn\d+\.example\.com$",
            "PROCESS-NAME,example.exe",
            "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,googlevideo.com))",
        ):
            with self.subTest(rule=rule):
                self.assertEqual(
                    convert_rule(rule), f"# UNSUPPORTED (no native equivalent): {rule}"
                )

    def test_unknown_rules_and_options_require_review(self):
        for rule in (
            "NEW-RULE,example.com", "DOMAIN,", "DOMAIN,example.com,no-resolve",
            "IP-CIDR,192.0.2.0/24,unknown-option",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                convert_rule(rule)

    def test_preserves_attribution_and_removes_exact_duplicates(self):
        text = "# NAME: Example\n# SOURCE: upstream\n\npayload:\n  - DOMAIN,example.com\n  - DOMAIN,example.com\n"
        rendered = render_filter(text, Path("Test/Example.yaml"))
        self.assertTrue(rendered.startswith("# NAME: Example\n# SOURCE: upstream\n"))
        self.assertIn("# GENERATED-FROM: Ruleset/Mihomo/Test/Example.yaml", rendered)
        self.assertEqual(rendered.count("host,example.com,proxy"), 1)
        self.assertNotIn("payload:", rendered)

    def test_checks_missing_stale_and_orphaned_filters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Ruleset/Mihomo/Example.yaml"
            target = root / "Ruleset/QuantumultX/Example.list"
            source.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            text = "payload:\n  - DOMAIN,example.com\n"
            source.write_text(text, encoding="utf-8")
            errors = []
            check_quantumultx_pairs(root, errors)
            self.assertEqual(errors, ["PAIR MISSING QuantumultX/Example.list"])
            target.write_text("host,wrong.example,proxy\n", encoding="utf-8")
            errors = []
            check_quantumultx_pairs(root, errors)
            self.assertTrue(errors[0].startswith("PAIR MISMATCH"))
            target.write_text(render_filter(text, Path("Example.yaml")), encoding="utf-8")
            errors = []
            self.assertEqual(check_quantumultx_pairs(root, errors), 1)
            self.assertEqual(errors, [])
            target.with_name("Orphan.list").write_text("host,example.com,proxy\n", encoding="utf-8")
            errors = []
            check_quantumultx_pairs(root, errors)
            self.assertEqual(errors, ["PAIR EXTRA QuantumultX/Orphan.list"])


if __name__ == "__main__":
    unittest.main()
