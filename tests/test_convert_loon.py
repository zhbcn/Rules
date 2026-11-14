import copy
import fnmatch
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from scripts.convert_loon import (Converter, Rule, check_loon_pairs, disjuncts,
                                 expected_files, format_rule, manifest, parse_native,
                                 safe_relative, source_expression)
from scripts.loon_config import (PRIVATE_LOCAL_INDICES, build_config, check_config,
                                combine_filter, sections, build_hosts)

ROOT = Path(__file__).resolve().parents[1]


def to_egern(expression):
    if isinstance(expression, str):
        return {"rule_set": {"match": "https://raw.githubusercontent.com/zhbcn/Rules/main/Ruleset/Egern/" + expression}}
    if isinstance(expression, list):
        return {"or": {"match": [to_egern(x) for x in expression]}}
    key = next(k for k in expression if k != "no_resolve")
    if key in {"and", "or", "not"}:
        return {key: {"match": [to_egern(x) for x in expression[key]]}}
    spec = {"match": expression[key]}
    if expression.get("no_resolve"):
        spec["no_resolve"] = True
    return {key: spec}


def example_config():
    rules = [{"domain": {"match": "private.example", "policy": "DIRECT"}} for _ in range(54)]
    for item in manifest(ROOT):
        rule = to_egern(item["expression"])
        next(iter(rule.values()))["policy"] = "DIRECT"
        rules[item["source_index"] - 1] = rule
    rules[-1] = {"default": {"policy": "Public network"}}
    return {
        "rules": rules, "ipv6": False, "http_port": 8899, "socks_port": 8898,
        "allow_external_connections": False, "close_connections_on_policy_change": False,
        "hijack_dns": ["*:53"], "bypass_tunnel_proxy": ["192.168.0.0/16"], "real_ip_domains": ["*.local"],
        "geoip_db_url": "https://example.com/country.mmdb", "asn_db_url": "https://example.com/asn.mmdb",
        "proxy_latency_test_url": "http://example.com/generate_204",
        "direct_latency_test_url": "http://example.com/direct_204",
        "dns": {"bootstrap": ["system"], "upstreams": {"Ash": ["https://example.com/dns-query"],
                "China": ["system", "https://223.5.5.5/dns-query"], "Global": ["https://1.1.1.1/dns-query"],
                "AIGC": ["https://1.0.0.1/dns-query"]},
                "forward": [{"domain_suffix": {"match": "example.com", "value": "China"}}]},
        "proxies": [{"tailscale": {"name": "Tailnet Example", "interactive_login": True}}],
        "policy_groups": [
            {"select": {"name": "AIGC", "flatten": True, "filter": r"(?i)(US|JP|美国|日本)"}},
            {"select": {"name": "Public network", "policies": ["Tailnet Example", "日本"]}},
            {"select": {"name": "日本", "flatten": True, "filter": r"(?i)(JP|日本)"}},
            {"external": {"name": "全部节点", "type": "select", "filter": r"(?i)^(?!.*流量).+$",
                          "urls": ["https://static01.flowaccess.org/signal/channel/receiver?" + "token" + "=EXAMPLE_NOT_REAL",
                                   "https://example.com/other?credential=EXAMPLE_NOT_REAL"]}},
        ],
    }


class LoonConversionTests(unittest.TestCase):
    def setUp(self):
        self.converter = Converter(ROOT)

    def test_stun_and_or_distribution_keeps_protocol_guard(self):
        tree = self.converter.expression({"and": [{"protocol": "stun"}, [{"domain_suffix": "a.example"}, {"domain": "b.example"}]]})
        lines = [format_rule(x) for x in disjuncts(tree)]
        self.assertEqual(lines, ["AND,((PROTOCOL,STUN),(DOMAIN-SUFFIX,a.example))", "AND,((PROTOCOL,STUN),(DOMAIN,b.example))"])
        self.assertTrue(all(parse_native(x).kind == "AND" for x in lines))

    def test_no_resolve_survives_native_round_trip(self):
        for line in ["IP-CIDR,192.0.2.0/24,no-resolve", "IP-CIDR6,2001:db8::/32", "IP-ASN,13335,no-resolve",
                     "AND,((PROTOCOL,STUN),(IP-CIDR,192.0.2.0/24,no-resolve))"]:
            self.assertEqual(format_rule(parse_native(line)), line)

    def test_global_no_resolve_is_inherited_by_tagged_logical_children(self):
        node = self.converter.atom("and", [{"protocol": {"match": "stun"}}, {"ip_cidr": {"match": "192.0.2.0/24"}}], True)
        self.assertEqual(format_rule(node), "AND,((PROTOCOL,STUN),(IP-CIDR,192.0.2.0/24,no-resolve))")

    def test_invalid_grammar_and_wrong_ip_families_fail(self):
        for line in ["IP-CIDR,2001:db8::/32", "IP-CIDR6,192.0.2.0/24", "DOMAIN,x.example,no-resolve",
                     "AND,((DOMAIN,x.example),invalid)", "NOT,((DOMAIN,a.example),(DOMAIN,b.example))", "PROTOCOL,UNKNOWN"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_native(line)

    def test_unknown_regex_is_not_silently_omitted(self):
        with self.assertRaises(ValueError):
            self.converter.regex(r"^unreviewed\d+\.example$", set())

    def test_digit_class_conversion_does_not_add_apex_or_alpha_ids(self):
        tree = self.converter.regex(r".+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$", set())
        patterns = [x.value for x in tree.children]
        for host, expected in [("a.awsdns-cn-01.com", True), ("a.b.awsdns-cn-99.net", True),
                               ("awsdns-cn-01.com", False), ("a.awsdns-cn-0a.com", False)]:
            self.assertEqual(any(fnmatch.fnmatchcase(host, p) for p in patterns), expected)

    def test_approved_openai_scope_is_explicit(self):
        tree = self.converter.regex(r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$", set())
        pattern = tree.children[0].value
        self.assertTrue(fnmatch.fnmatchcase("chatgpt-async-webps-prod-region-123.webpubsub.azure.com", pattern))
        self.assertFalse(fnmatch.fnmatchcase("other-123.webpubsub.azure.com", pattern))
        self.assertTrue(any(x.startswith("LOON-ADAPTED") for x in self.converter.notes))

    def test_netflix_nonempty_identifier_and_domain_boundary(self):
        tree = self.converter.regex(r"(^|\.)apiproxy-device-prod-nlb-.+\.amazonaws\.com$", set())
        patterns = [x.value for x in tree.children]
        self.assertTrue(any(fnmatch.fnmatchcase("apiproxy-device-prod-nlb-123.amazonaws.com", p) for p in patterns))
        self.assertFalse(any(fnmatch.fnmatchcase("apiproxy-device-prod-nlb-.amazonaws.com", p) for p in patterns))
        self.assertFalse(any(fnmatch.fnmatchcase("fakeapiproxy-device-prod-nlb-123.amazonaws.com", p) for p in patterns))

    def test_google_regex_is_only_covered_with_same_source_suffix(self):
        regex = r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$"
        self.assertEqual(self.converter.regex(regex, {"googlevideo.com"}), Rule("OR"))
        with self.assertRaises(ValueError):
            self.converter.regex(regex, set())

    def test_truncated_source_is_reported_instead_of_fabricating_repair(self):
        self.assertEqual(self.converter.regex(r"^speed\.(coe|open)\.ad\.[a-z]{2", set()), Rule("OR"))
        self.assertTrue(any(x.startswith("SOURCE-WARNING") for x in self.converter.notes))

    def test_subscription_urls_cannot_enter_public_manifest(self):
        private = "https://example.com/subscription?credential=PRIVATE_SENTINEL"
        with self.assertRaises(ValueError) as raised:
            source_expression({"rule_set": {"match": private}})
        self.assertNotIn("PRIVATE_SENTINEL", str(raised.exception))
        for path in ["../private.yaml", "C:/private.yaml", "/private.yaml"]:
            with self.assertRaises(ValueError):
                safe_relative(path, ".yaml")

    def test_no_resolve_from_actual_source_is_not_discarded(self):
        rules = disjuncts(self.converter.resource("AI/Anthropic.yaml"))
        ips = [r for r in rules if r.kind in {"IP-CIDR", "IP-CIDR6"}]
        self.assertTrue(ips)
        self.assertTrue(all(r.no_resolve for r in ips))

    def test_filter_combines_region_and_all_nodes_exclusions(self):
        pattern = combine_filter(r"(?i)^(?!.*(?:流量|到期)).+$", r"(?i)(?:美国|\bUS\b)")
        for label, expected in [("美国 01", True), ("Premium US 02", True), ("美国 剩余流量", False), ("日本 01", False), ("AUS 01", False)]:
            self.assertEqual(bool(re.search(pattern, label)), expected)

    def test_same_source_group_manifest_is_policy_free(self):
        data = (ROOT / "scripts" / "loon_resources.json").read_text(encoding="utf-8")
        self.assertNotIn('"policy"', data)
        self.assertNotIn("credential=", data)
        resources = manifest(ROOT)
        self.assertEqual(len(resources), 48)
        self.assertFalse({x["source_index"] for x in resources} & PRIVATE_LOCAL_INDICES)

    def test_candidate_has_native_subscriptions_without_cached_nodes(self):
        document = example_config()
        text, summary = build_config(document, ROOT)
        area = sections(text)
        self.assertEqual(summary["cached_provider_nodes"], 0)
        self.assertEqual(summary["omitted_local_proxies"], ["Tailnet Example"])
        self.assertNotIn("Proxy", area)
        self.assertNotIn("MitM", area)
        self.assertNotIn("Tailnet Example", text)
        self.assertEqual(len(area["Remote Proxy"]), 2)
        self.assertTrue(all("enabled=false" in x for x in area["Remote Proxy"] + area["Remote Rule"]))
        self.assertEqual(check_config(text, ROOT), [])
        actual_url = area["Remote Proxy"][0].split(" = ", 1)[1].split(",", 1)[0]
        self.assertEqual(actual_url, document["policy_groups"][-1]["external"]["urls"][0])
        self.assertNotIn("flag=", actual_url)

    def test_group_left_without_members_after_omitting_local_proxy_fails(self):
        document = example_config()
        document["policy_groups"].append({"select": {"name": "Tailnet only", "policies": ["Tailnet Example"]}})
        with self.assertRaises(ValueError):
            build_config(document, ROOT)

    def test_private_local_exceptions_do_not_mask_earlier_stun_rules(self):
        text, _ = build_config(example_config(), ROOT)
        for line in sections(text)["Rule"][:-1]:
            self.assertTrue(line.startswith("AND,((NOT,((PROTOCOL,STUN))),"))

    def test_dns_keeps_earlier_system_boundary_and_removes_only_redundancy(self):
        document = example_config()
        document["dns"]["forward"] = [
            {"domain_suffix": {"match": "apple.com", "value": "system"}},
            {"domain": {"match": "api.apple.com", "value": "AIGC"}},
            {"domain_suffix": {"match": "special.cn", "value": "AIGC"}},
            {"domain_suffix": {"match": "cn", "value": "China"}},
        ]
        hosts, gaps = build_hosts(document, ROOT)
        self.assertEqual(hosts["*.apple.com"], "system")
        self.assertNotIn("api.apple.com", hosts)
        self.assertEqual(hosts["special.cn"], "https://1.0.0.1/dns-query")
        self.assertEqual(hosts["*.special.cn"], "https://1.0.0.1/dns-query")
        self.assertEqual(hosts["*.cn"], "https://223.5.5.5/dns-query")
        self.assertEqual(gaps, [])

    def test_remote_order_or_private_policy_cycle_is_rejected(self):
        text, _ = build_config(example_config(), ROOT)
        area = sections(text)
        first, second = area["Remote Rule"][:2]
        self.assertTrue(check_config(text.replace(first + "\n" + second, second + "\n" + first), ROOT))
        self.assertTrue(check_config(text.replace("AIGC = select,筛选-AIGC", "AIGC = select,AIGC"), ROOT))

    def test_source_manifest_change_requires_review(self):
        document = example_config()
        next(iter(document["rules"][15].values()))["match"] = "different.example"
        with self.assertRaises(ValueError):
            build_config(document, ROOT)

    def test_generated_consistency_detects_stale_and_extra_resources(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            source = root / "Ruleset/Egern/Test.yaml"
            source.parent.mkdir(parents=True)
            source.write_text("domain_set:\n  - example.com\n", encoding="utf-8")
            (root / "scripts/loon_resources.json").write_text(json.dumps({"version": 1, "resources": [{"source_index": 1, "file": "Test.list", "expression": "Test.yaml"}]}), encoding="utf-8")
            area = root / "Ruleset/Loon"
            area.mkdir()
            for path, content in expected_files(root).items():
                (area / path).write_text(content, encoding="utf-8")
            errors = []
            self.assertEqual(check_loon_pairs(root, errors), 1)
            self.assertEqual(errors, [])
            (area / "Test.list").write_text("DOMAIN,stale.example\n", encoding="utf-8")
            (area / "Extra.list").write_text("DOMAIN,extra.example\n", encoding="utf-8")
            check_loon_pairs(root, errors)
            self.assertEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
