import json
from pathlib import Path
import tempfile
import unittest

from scripts.check import (
    check_dist_invariants,
    check_privacy_and_coupling,
    check_sources_and_bundles,
    load_egern_yaml,
)


class CheckSuiteTest(unittest.TestCase):
    def test_egern_yaml_parses_tagged_and_set(self):
        doc = load_egern_yaml(
            """no_resolve: true
and_set:
- - !domain_keyword
    match: -ad-
  - !domain_suffix
    match: byteimg.com
"""
        )
        self.assertEqual(
            doc,
            {
                "no_resolve": True,
                "and_set": [
                    [{"match": "-ad-"}, {"match": "byteimg.com"}],
                ],
            },
        )

    def test_rejects_process_rule_and_orphan_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "upstream" / "system").mkdir(parents=True)
            (root / "custom" / "services").mkdir(parents=True)
            (root / "upstream" / "system" / "bad.yaml").write_text(
                "schema: zhbcn-rules/v1\nname: Bad\nkind: upstream\nsource:\n  provider: test\n"
                "rules:\n  domain:\n  - PROCESS-NAME,foo.exe\n",
                encoding="utf-8",
            )
            (root / "sources.json").write_text(
                json.dumps({"version": 1, "providers": {}, "sources": [{"id": "s/b", "target": "upstream/system/bad.yaml"}]}),
                encoding="utf-8",
            )
            (root / "bundles.json").write_text(
                json.dumps({"version": 1, "schema": "zhbcn-bundles/v1", "raw_base": "https://example.com", "bundles": []}),
                encoding="utf-8",
            )
            errors: list[str] = []
            check_sources_and_bundles(root, errors)
            self.assertTrue(any("forbidden process rule token PROCESS-NAME" in e for e in errors))
            self.assertTrue(any("Orphan canonical source" in e for e in errors))

    def test_rejects_ip_in_dns_bound_egern_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dist" / "egern").mkdir(parents=True)
            (root / "dist" / "egern" / "demo_domain.yaml").write_text(
                "no_resolve: true\ndomain_suffix_set:\n- example.com\nip_cidr_set:\n- 1.2.3.0/24\n",
                encoding="utf-8",
            )
            (root / "dist" / "manifest.json").write_text(
                json.dumps({
                    "schema": "zhbcn-manifest/v1",
                    "bundles": {
                        "demo": {
                            "dns_bound": True,
                            "artifacts": {
                                "egern": {
                                    "yaml": "dist/egern/demo_domain.yaml",
                                    "dns_yaml": "dist/egern/demo_domain.yaml",
                                }
                            },
                        }
                    },
                }),
                encoding="utf-8",
            )
            (root / "dist" / "build-report.json").write_text(
                json.dumps({"schema": "zhbcn-build-report/v1", "totals": {"quantumultx": {"adapted": 0, "skipped": 0}}}),
                encoding="utf-8",
            )
            errors: list[str] = []
            check_dist_invariants(root, errors)
            self.assertTrue(any("dns_bound artifact contains non-domain keys" in e for e in errors))

    def test_privacy_and_host_ip_allowlist_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "custom" / "services" / "direct").mkdir(parents=True)
            (root / "upstream" / "direct").mkdir(parents=True)
            # Legitimate upstream domain containing 'wife' substring must NOT be flagged
            (root / "upstream" / "direct" / "ok.yaml").write_text(
                "schema: zhbcn-rules/v1\nname: Ok\nkind: upstream\nsource:\n  provider: test\n"
                "rules:\n  domain_suffix:\n  - midwifery.example.com\n",
                encoding="utf-8",
            )
            # Custom file with coupling token and unallowlisted /32 IP MUST be flagged
            (root / "custom" / "services" / "direct" / "bad.yaml").write_text(
                "schema: zhbcn-rules/v1\nname: Bad\nkind: custom\nsource:\n  provider: custom\n"
                "notes: copied from wife profile\n"
                "rules:\n  ip_cidr:\n  - 203.0.113.10/32\n",
                encoding="utf-8",
            )
            errors: list[str] = []
            check_privacy_and_coupling(root, errors)
            self.assertTrue(any("PRIVACY/COUPLING" in e and "bad.yaml" in e for e in errors))
            self.assertTrue(any("HOST-IP-ALLOWLIST" in e and "203.0.113.10/32" in e for e in errors))
            self.assertFalse(any("ok.yaml" in e for e in errors))

    def test_rejects_empty_canonical_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "upstream" / "direct").mkdir(parents=True)
            (root / "custom" / "services").mkdir(parents=True)
            (root / "upstream" / "direct" / "empty.yaml").write_text(
                "schema: zhbcn-rules/v1\nname: Empty\nkind: upstream\nsource:\n  provider: test\nrules: {}\n",
                encoding="utf-8",
            )
            (root / "sources.json").write_text(
                json.dumps({"version": 1, "providers": {}, "sources": [{"id": "d/e", "target": "upstream/direct/empty.yaml"}]}),
                encoding="utf-8",
            )
            (root / "bundles.json").write_text(
                json.dumps({"version": 1, "schema": "zhbcn-bundles/v1", "raw_base": "https://example.com", "bundles": []}),
                encoding="utf-8",
            )
            errors: list[str] = []
            check_sources_and_bundles(root, errors)
            self.assertTrue(any("canonical source has 0 rules" in e and "empty.yaml" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
