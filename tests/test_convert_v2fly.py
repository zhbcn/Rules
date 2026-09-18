import tempfile
import unittest
from pathlib import Path

from scripts.convert_v2fly import V2FlyConverter, mihomo_lines


class V2FlyConverterTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.data = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def write(self, name: str, text: str) -> None:
        (self.data / name).write_text(text, encoding="utf-8")

    def test_include_expansion_and_attribute_filter(self):
        self.write("child", "example.com\nfull:cn.example.com @cn\n")
        self.write("parent", "include:child @cn\nparent.example\n")

        rules = V2FlyConverter(self.data).read("parent")

        self.assertEqual(
            mihomo_lines(rules),
            ["DOMAIN,cn.example.com", "DOMAIN-SUFFIX,parent.example"],
        )

    def test_affiliation_adds_rule_to_existing_target(self):
        self.write("source", "example.com @cn &target\n")
        self.write("target", "target.example\n")

        converter = V2FlyConverter(self.data)
        rules = converter.read("target")

        self.assertEqual(
            mihomo_lines(rules),
            ["DOMAIN-SUFFIX,example.com", "DOMAIN-SUFFIX,target.example"],
        )
        self.assertEqual(
            converter.read("target")[0].attributes,
            frozenset({"cn"}),
        )
        self.assertEqual(
            mihomo_lines(converter.read("source")),
            ["DOMAIN-SUFFIX,example.com"],
        )

    def test_affiliation_creates_target_without_dedicated_file(self):
        self.write("source", "full:api.example.com &virtual-target\n")

        rules = V2FlyConverter(self.data).read("virtual-target")

        self.assertEqual(mihomo_lines(rules), ["DOMAIN,api.example.com"])

    def test_affiliated_rules_participate_in_filtered_include(self):
        self.write("source", "cn.example @cn &target\nother.example &target\n")
        self.write("parent", "include:target @cn\n")

        rules = V2FlyConverter(self.data).read("parent")

        self.assertEqual(mihomo_lines(rules), ["DOMAIN-SUFFIX,cn.example"])

    def test_include_cycle_is_rejected(self):
        self.write("one", "include:two\n")
        self.write("two", "include:one\n")

        with self.assertRaisesRegex(ValueError, "one -> two -> one"):
            V2FlyConverter(self.data).read("one")


if __name__ == "__main__":
    unittest.main()
