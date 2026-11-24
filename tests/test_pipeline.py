from pathlib import Path
import tempfile
import unittest

from scripts.emitters.common import CompiledBundle
from scripts.emitters.egern import emit_egern
from scripts.emitters.loon import emit_loon
from scripts.emitters.quantumultx import emit_quantumultx
from scripts.schema import RuleSet
from scripts.sync_upstream import _is_simple_ref, parse_clash_or_list_lines, parse_clash_yaml_text, sync_source_entry


class SchemaAndPipelineTest(unittest.TestCase):
    def test_ruleset_patch_and_exclude_domain_roots(self):
        rs = RuleSet(
            domain=["api.coze.com", "www.doubao.com"],
            domain_suffix=["coze.com", "doubao.com", "in.th"],
        )
        added, removed = rs.apply_patch({
            "schema": "zhbcn-patch/v1",
            "target": "dummy",
            "remove": {"domain_suffix": ["in.th"]},
            "add": {"domain_suffix": ["volcengine.com"]},
        })
        self.assertEqual((added, removed), (1, 1))
        self.assertNotIn("in.th", rs.domain_suffix)
        self.assertIn("volcengine.com", rs.domain_suffix)

        excluded = rs.exclude_domain_roots(["coze.com"])
        self.assertEqual(excluded, 2)
        self.assertEqual(rs.domain, ["www.doubao.com"])
        self.assertEqual(rs.domain_suffix, ["doubao.com", "volcengine.com"])

    def test_egern_dns_bound_splits_pure_domain_yaml(self):
        rs = RuleSet(
            domain_suffix=["example.com"],
            ip_cidr=["1.2.3.0/24"],
        )
        bundle = CompiledBundle(
            id="demo",
            meta={"id": "demo", "dns_bound": True},
            ruleset=rs,
            source_rulesets={},
        )
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            stats = emit_egern(bundle, dist)
            self.assertEqual(stats.artifacts["yaml"], "dist/egern/demo.yaml")
            self.assertEqual(stats.artifacts["dns_yaml"], "dist/egern/demo_domain.yaml")
            full = (dist / "egern" / "demo.yaml").read_text(encoding="utf-8")
            dns = (dist / "egern" / "demo_domain.yaml").read_text(encoding="utf-8")
            self.assertIn("no_resolve: true", full)
            self.assertIn("ip_cidr_set:", full)
            self.assertNotIn("ip_cidr_set:", dns)
            self.assertNotIn("no_resolve:", dns)

    def test_loon_emits_stun_list_and_rejects_unreviewed_regex(self):
        src_rs = RuleSet(domain_suffix=["openai.com"], ip_cidr=["160.79.104.0/23"])
        bundle = CompiledBundle(
            id="aigc",
            meta={
                "id": "aigc",
                "emit_loon_stun": True,
                "loon_stun_sources": ["upstream/ai/open_ai.yaml"],
            },
            ruleset=src_rs,
            source_rulesets={"upstream/ai/open_ai.yaml": src_rs},
        )
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            stats = emit_loon(bundle, dist)
            self.assertEqual(stats.artifacts["stun_list"], "dist/loon/aigc_stun.list")
            stun_text = (dist / "loon" / "aigc_stun.list").read_text(encoding="utf-8")
            self.assertIn("AND,((PROTOCOL,STUN),(DOMAIN-SUFFIX,openai.com))", stun_text)
            self.assertIn("AND,((PROTOCOL,STUN),(IP-CIDR,160.79.104.0/23,no-resolve))", stun_text)

        bad_bundle = CompiledBundle(
            id="bad",
            meta={"id": "bad"},
            ruleset=RuleSet(domain_regex=[r"^unreviewed-\d+\.example\.com$"]),
            source_rulesets={},
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                emit_loon(bad_bundle, Path(tmp))

    def test_qx_emits_three_field_and_tracks_skipped_url_regex(self):
        rs = RuleSet(
            domain_suffix=["example.com"],
            ip_cidr=["1.2.3.0/24"],
            url_regex=[r"/igd\.xml"],
        )
        bundle = CompiledBundle(id="demo", meta={"id": "demo"}, ruleset=rs, source_rulesets={})
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            stats = emit_quantumultx(bundle, dist)
            self.assertEqual(stats.adapted, 0)
            self.assertEqual(stats.skipped, 1)
            text = (dist / "quantumultx" / "demo.list").read_text(encoding="utf-8")
            self.assertIn("ip-cidr,1.2.3.0/24,proxy", text)
            self.assertNotIn("no-resolve", text.split("\n", 4)[-1])

        bad_and_bundle = CompiledBundle(
            id="bad_and",
            meta={"id": "bad_and"},
            ruleset=RuleSet(and_rules=["((DOMAIN-KEYWORD,foo),(DOMAIN-SUFFIX,example.com))"]),
            source_rulesets={},
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                emit_quantumultx(bad_and_bundle, Path(tmp))

    def test_sync_upstream_parsers_strip_process_rules(self):
        clash_yaml = """payload:
  - DOMAIN-SUFFIX,example.com
  - PROCESS-NAME,Thunder
  - IP-CIDR,10.0.0.0/8,no-resolve
"""
        rs, stripped = parse_clash_yaml_text(clash_yaml)
        self.assertEqual(rs.domain_suffix, ["example.com"])
        self.assertEqual(rs.ip_cidr, ["10.0.0.0/8"])
        self.assertEqual(stripped, ["PROCESS-NAME,Thunder"])

    def test_sync_upstream_skips_composite_refs_across_providers(self):
        self.assertTrue(_is_simple_ref("v2fly", "anthropic"))
        self.assertFalse(_is_simple_ref("v2fly", "category-cryptocurrency (Bitcoin subset)"))
        self.assertFalse(_is_simple_ref("blackmatrix7", "rule/Clash/Crypto/Crypto.yaml (Avalanche subset)"))
        self.assertFalse(_is_simple_ref("sukka", "non_ip/lan.conf, ip/lan.conf"))

        providers = {
            "blackmatrix7": {"commit": "deadbeef", "raw_base": "https://example.invalid/{commit}"},
            "sukka": {"commit": "deadbeef", "raw_base": "https://example.invalid/{commit}"},
        }
        for provider, ref in (
            ("blackmatrix7", "rule/Clash/Crypto/Crypto.yaml (Avalanche subset)"),
            ("sukka", "non_ip/lan.conf, ip/lan.conf"),
        ):
            status, count, stripped = sync_source_entry(
                Path("."),
                providers,
                {"provider": provider, "ref": ref, "target": "upstream/x.yaml", "name": "x"},
                remote=True,
            )
            self.assertEqual((status, count, stripped), ("skipped_composite_ref", 0, []))

    def test_sync_upstream_parses_bare_cidrs_and_rejects_zero_rules(self):
        rs, stripped = parse_clash_or_list_lines([
            "payload:",
            "  - '1.0.1.0/24'",
            "  - '2001:db8::/32'",
            "  - '+.example.com'",
        ])
        self.assertEqual(rs.ip_cidr, ["1.0.1.0/24"])
        self.assertEqual(rs.ip_cidr6, ["2001:db8::/32"])
        self.assertEqual(rs.domain_suffix, ["example.com"])
        self.assertEqual(stripped, [])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bm7_dir = root / "bm7"
            bm7_dir.mkdir()
            (bm7_dir / "empty.yaml").write_text("payload:\n  - '# only comment'\n", encoding="utf-8")
            providers = {"blackmatrix7": {"commit": "deadbeef", "raw_base": "https://example.invalid/{commit}"}}
            with self.assertRaises(ValueError):
                sync_source_entry(
                    root,
                    providers,
                    {"id": "direct/empty", "provider": "blackmatrix7", "ref": "empty.yaml", "target": "upstream/empty.yaml", "name": "Empty"},
                    bm7_dir=bm7_dir,
                )


if __name__ == "__main__":
    unittest.main()
