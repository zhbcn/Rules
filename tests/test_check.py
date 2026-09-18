import unittest

from scripts.check import load_yaml


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


if __name__ == "__main__":
    unittest.main()
