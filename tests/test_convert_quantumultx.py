import tempfile
import unittest
import fnmatch
import re
import io
import sys
from contextlib import redirect_stdout
from unittest.mock import patch
from scripts import check as check_module
from pathlib import Path

from scripts.convert_quantumultx import (
    check_quantumultx_pairs,
    convert_rule,
    render_filter,
    convert_regex,
    validate_filter,
    QX_REGEX_ADAPTATIONS,
)
from scripts.check import check_quantumultx_config


class QuantumultXTest(unittest.TestCase):
    def test_qx_only_adaptations_cover_numeric_hosts_and_document_broadening(self):
        cases = [
            (r'^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$',
             'chatgpt-async-webps-prod-eu-123.webpubsub.azure.com',
             'chatgpt-async-webps-prod-eu-abc.webpubsub.azure.com',
             ['other-eu-123.webpubsub.azure.com', 'chatgpt-async-webps-prod-eu-.webpubsub.azure.com',
              'chatgpt-async-webps-prod-eu-123.webpubsub.azure.com.evil']),
            (r'^cdn\d-epicgames-\d+\.file\.myqcloud\.com$',
             'cdn1-epicgames-123.file.myqcloud.com', 'cdn1-epicgames-abc.file.myqcloud.com',
             ['cdnx-epicgames-123.file.myqcloud.com', 'cdn11-epicgames-123.file.myqcloud.com',
              'cdn1-epicgames-.file.myqcloud.com', 'cdn1-other-123.file.myqcloud.com']),
            (r'^epicgames-download\d-\d+\.file\.myqcloud\.com$',
             'epicgames-download1-123.file.myqcloud.com', 'epicgames-download1-abc.file.myqcloud.com',
             ['epicgames-downloadx-123.file.myqcloud.com', 'epicgames-download11-123.file.myqcloud.com',
              'epicgames-download1-.file.myqcloud.com', 'other-download1-123.file.myqcloud.com']),
        ]
        import yaml
        for regex, numeric, relaxed, negatives in cases:
            globs = QX_REGEX_ADAPTATIONS[regex]
            match = lambda host: any(fnmatch.fnmatchcase(host, glob) for glob in globs)
            self.assertTrue(match(numeric))
            self.assertTrue(match(relaxed))
            self.assertRegex(numeric, regex)
            self.assertNotRegex(relaxed, regex)
            # Stars may cross label boundaries; this must remain an approximation.
            self.assertTrue(match(numeric.replace('123.', 'abc.extra.')))
            for host in [*negatives, numeric + '.evil', 'unrelated.file.myqcloud.com']:
                self.assertFalse(match(host), host)
            rendered = render_filter(yaml.safe_dump({'payload': ['DOMAIN-REGEX,' + regex]}))
            self.assertIn('# QX-COMPAT: ADAPTED-DOMAIN-IP;', rendered)
            self.assertIn('# QX-ADAPTED', rendered)
            self.assertIn(regex, rendered)
            self.assertNotIn('# LIMITATION', rendered)
            self.assertFalse(validate_filter(rendered))
        for regex in list(QX_REGEX_ADAPTATIONS)[1:]:
            self.assertEqual(len(QX_REGEX_ADAPTATIONS[regex]), 10)
            for digit in range(10):
                host = (f'cdn{digit}-epicgames-123.file.myqcloud.com' if regex.startswith('^cdn')
                        else f'epicgames-download{digit}-123.file.myqcloud.com')
                self.assertTrue(any(fnmatch.fnmatchcase(host, glob) for glob in QX_REGEX_ADAPTATIONS[regex]))

    def test_real_service_regexes_cannot_be_replaced_with_digit_blind_globs(self):
        cases = [
            (r'^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$',
             'chatgpt-async-webps-prod-x-123.webpubsub.azure.com',
             'chatgpt-async-webps-prod-x-abc.webpubsub.azure.com',
             'chatgpt-async-webps-prod-?*-?*.webpubsub.azure.com'),
            (r'^cdn\d-epicgames-\d+\.file\.myqcloud\.com$',
             'cdn1-epicgames-123.file.myqcloud.com',
             'cdnx-epicgames-abc.file.myqcloud.com',
             'cdn?-epicgames-?*.file.myqcloud.com'),
            (r'^epicgames-download\d-\d+\.file\.myqcloud\.com$',
             'epicgames-download1-123.file.myqcloud.com',
             'epicgames-downloadx-abc.file.myqcloud.com',
             'epicgames-download?-?*.file.myqcloud.com'),
        ]
        for regex, valid, invalid, tempting_glob in cases:
            self.assertRegex(valid, regex)
            self.assertNotRegex(invalid, regex)
            self.assertTrue(fnmatch.fnmatchcase(valid, tempting_glob))
            self.assertTrue(fnmatch.fnmatchcase(invalid, tempting_glob))
            self.assertIsNone(convert_regex(regex, set()))

    def test_full_coverage_gate_does_not_treat_approved_adaptation_as_equivalence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pattern = r'^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$'
            source = root / 'Ruleset/Mihomo/Example.yaml'
            egern = root / 'Ruleset/Egern/Example.yaml'
            target = root / 'Ruleset/QuantumultX/Example.list'
            for path in [source, egern, target]:
                path.parent.mkdir(parents=True, exist_ok=True)
            import yaml
            text = yaml.safe_dump({'payload':['DOMAIN-REGEX,'+pattern]})
            source.write_text(text, encoding='utf-8')
            egern.write_text(yaml.safe_dump({'domain_regex_set':[pattern]}), encoding='utf-8')
            target.write_text(render_filter(text), encoding='utf-8')
            for flags, expected in [([], 0), (['--require-complete-qx'], 1)]:
                output = io.StringIO()
                # This fixture exercises the QX gate, not unrelated Crypto/Finance aggregation.
                with patch.object(check_module, '__file__', str(root/'scripts/check.py')), \
                     patch.object(check_module, 'AGGREGATES', {}), \
                     patch.object(sys, 'argv', ['check.py', *flags]), redirect_stdout(output):
                    result = check_module.main()
                self.assertEqual(result, expected, output.getvalue())
                self.assertIn('0/1 complete', output.getvalue())
                self.assertIn('QX ADAPTED: Example.list', output.getvalue())

    def test_protocol_condition_remains_partial_instead_of_blocking_all_youtube(self):
        rule = 'AND,((NETWORK,UDP),(DOMAIN-SUFFIX,googlevideo.com))'
        rendered = render_filter('payload:\n  - "' + rule + '"\n')
        self.assertIn('# QX-COMPAT: PARTIAL;', rendered)
        self.assertIn('# LIMITATION', rendered)
        self.assertFalse([line for line in rendered.splitlines() if line and not line.startswith('#')])

    def test_complete_profile_sections_policy_cycles_and_resource_binding(self):
        profile = '\n'.join('['+s+']\n'+body for s, body in {
            'general':'', 'dns':'no-ipv6', 'policy':'static = AIGC, 日本\nstatic = 日本, server-tag-regex=JP',
            'server_remote':'', 'server_local':'',
            'filter_remote':'https://example.com/rules.list, force-policy=AIGC, opt-parser=false',
            'filter_local':'final, AIGC', 'rewrite_remote':'', 'rewrite_local':'',
            'task_local':'', 'http_backend':'', 'mitm':''}.items())
        errors = []
        check_quantumultx_config(profile, 'test.conf', errors)
        self.assertFalse(errors)
        for changed, fragment in [
            (profile.replace('[rewrite_remote]', '# removed'), 'missing section [rewrite_remote]'),
            (profile.replace('force-policy=AIGC', 'force-policy=missing'), 'force-policy'),
            (profile.replace('opt-parser=false', 'opt-parser=true'), 'opt-parser=false'),
            (profile.replace('final, AIGC', 'domain-regex,example,AIGC'), 'invalid local filter'),
            (profile.replace('static = 日本, server-tag-regex=JP', 'static = 日本, AIGC'), 'cycle'),
        ]:
            errors = []
            check_quantumultx_config(changed, 'test.conf', errors)
            self.assertTrue(any(fragment in x for x in errors), errors)

    def test_native_rule_types_and_ip_options(self):
        cases = {
            "DOMAIN,api.example.com": "host,api.example.com,proxy",
            "DOMAIN-SUFFIX,example.com": "host-suffix,example.com,proxy",
            "DOMAIN-KEYWORD,example": "host-keyword,example,proxy",
            "DOMAIN-WILDCARD,*.example?.com": "host-wildcard,*.example?.com,proxy",
            "IP-CIDR,192.0.2.0/24": "ip-cidr,192.0.2.0/24,proxy",
            "IP-CIDR,192.0.2.0/24,no-resolve": "ip-cidr,192.0.2.0/24,proxy",
            "IP-CIDR6,2001:db8::/32,no-resolve": "ip6-cidr,2001:db8::/32,proxy",
            "IP-ASN,132203": "ip-asn,132203,proxy",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(convert_rule(source), expected)

    def test_inherent_limits_and_platform_scope_are_distinguished(self):
        for rule in (
            r"DOMAIN-REGEX,^cdn\d+\.example\.com$",
            "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,googlevideo.com))",
        ):
            with self.subTest(rule=rule):
                self.assertTrue(convert_rule(rule).startswith("# LIMITATION"))
        self.assertTrue(convert_rule("PROCESS-NAME,example.exe").startswith("# PLATFORM-OMITTED"))

    def test_unknown_rules_and_options_require_review(self):
        for rule in (
            "NEW-RULE,example.com", "DOMAIN,", "DOMAIN,example.com,no-resolve",
            "IP-CIDR,192.0.2.0/24,unknown-option",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                convert_rule(rule)

    def test_preserves_attribution_and_removes_exact_duplicates(self):
        text = "# NAME: Example\n# SOURCE: upstream\n\npayload:\n  - DOMAIN,example.com\n  - DOMAIN,example.com\n"
        rendered = render_filter(text)
        self.assertTrue(rendered.startswith("# NAME: Example\n# SOURCE: upstream\n# QX-COMPAT: COMPLETE-DOMAIN-IP"))
        self.assertEqual(rendered.count("host,example.com,proxy"), 1)

    def assert_regex_equivalent(self, pattern, hosts):
        rows = convert_regex(pattern, set())
        self.assertIsNotNone(rows)
        for host in hosts:
            actual = any((host == row.split(',')[1] if row.startswith('host,')
                          else fnmatch.fnmatchcase(host, row.split(',')[1])) for row in rows)
            self.assertEqual(bool(re.search(pattern, host)), actual, (pattern, host))

    def test_finite_regexes_exact_hosts_and_boundaries(self):
        self.assert_regex_equivalent(r'^hses[1-7]?\.akamaized\.net$', [
            'hses.akamaized.net', 'hses1.akamaized.net', 'hses7.akamaized.net',
            'hses0.akamaized.net', 'hses8.akamaized.net', 'hses11.akamaized.net',
            'a.hses1.akamaized.net', 'hses1.akamaized.net.evil'])
        self.assert_regex_equivalent(r'^epicgames-download\d\.akamaized\.net$', [
            'epicgames-download0.akamaized.net', 'epicgames-download9.akamaized.net',
            'epicgames-downloadx.akamaized.net', 'epicgames-download12.akamaized.net',
            'xepicgames-download1.akamaized.net'])

    def test_exact_dns_globs_preserve_nonempty_and_subdomain_boundaries(self):
        self.assert_regex_equivalent(r'^.+-mihayo\.akamaized\.net$', [
            'a-mihayo.akamaized.net', 'a.b-mihayo.akamaized.net',
            '-mihayo.akamaized.net', 'a-mihayo.akamaized.net.evil'])
        for prefix in ['apiproxy-device-prod-nlb', 'apiproxy-website-nlb-prod',
                       r'dualstack\.apiproxy', r'dualstack\.ichnaea-web']:
            plain = prefix.replace(r'\.', '.')
            self.assert_regex_equivalent(r'(^|\.)' + prefix + r'-.+\.amazonaws\.com$', [
                plain+'-a.amazonaws.com', 'x.'+plain+'-a.amazonaws.com',
                plain+'-a.b.amazonaws.com', plain+'-.amazonaws.com',
                'evil'+plain+'-a.amazonaws.com', plain+'-a.amazonaws.com.evil'])

    def test_aws_china_suffix_adaptation_preserves_digits_and_documents_apex_scope(self):
        pattern = r'.+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$'
        # The approved apex expansion must not be reported as exact conversion.
        self.assertIsNone(convert_regex(pattern, set()))
        import yaml
        rendered = render_filter(yaml.safe_dump({'payload': ['DOMAIN-REGEX,' + pattern]}))
        self.assertIn('# QX-COMPAT: ADAPTED-DOMAIN-IP;', rendered)
        self.assertIn('additionally matches the 400 apex hostnames', rendered)
        self.assertIn(pattern, rendered)
        self.assertNotIn('host-wildcard,', rendered)
        self.assertFalse(validate_filter(rendered))
        rows = [r for r in rendered.splitlines() if r.startswith('host-suffix,')]
        suffixes = {row.split(',')[1] for row in rows}
        self.assertEqual(len(rows), 400)
        self.assertEqual(len(suffixes), 400)
        match = lambda host: any(host == suffix or host.endswith('.' + suffix) for suffix in suffixes)
        for suffix in suffixes:
            self.assertTrue(match(suffix))
            self.assertNotRegex(suffix, pattern)
            for host in ['a.' + suffix, 'a.b.' + suffix]:
                self.assertTrue(match(host))
                self.assertRegex(host, pattern)
        for host in ['a.awsdns-cn-1a.biz', 'a.awsdns-cn-1.biz', 'a.awsdns-cn-100.biz',
                     'a.awsdns-cn-00.org', 'a.awsdns-cn-00.com.evil', 'evilawsdns-cn-00.biz']:
            self.assertFalse(match(host), host)

    def test_coverage_requires_reviewed_pattern_and_actual_suffix(self):
        pattern = r'.+\.awsdns-cn-[0-9][a-e0-9]\.cn$'
        self.assertEqual(convert_regex(pattern, {'cn'}), [])
        self.assertEqual(len(convert_regex(pattern, set())), 150)
        self.assertIsNone(convert_regex(r'^other$|x\.example\.com$', {'example.com'}))

    def test_advertising_conjunctions_are_not_broadened(self):
        cases = [
            ('AND,((DOMAIN-KEYWORD,-ad-),(DOMAIN-SUFFIX,byteimg.com))',
             lambda h: '-ad-' in h and (h == 'byteimg.com' or h.endswith('.byteimg.com'))),
            ('AND,((DOMAIN-KEYWORD,ads),(DOMAIN-KEYWORD,-normal.zijieapi.com))',
             lambda h: 'ads' in h and '-normal.zijieapi.com' in h),
            ('AND,((DOMAIN-KEYWORD,adash),(DOMAIN-SUFFIX,ut.taobao.com))',
             lambda h: 'adash' in h and (h == 'ut.taobao.com' or h.endswith('.ut.taobao.com'))),
        ]
        hosts = ['a-ad-b.byteimg.com', 'a-ad-b.byteimg.com.evil', 'a-ad-b.evilbyteimg.com',
                 'ads-normal.zijieapi.com', 'a-normal.zijieapi.com-ads',
                 'a-normal.zijieapi.com', 'ads.example.com',
                 'adash.ut.taobao.com', 'adash.evilut.taobao.com', 'ut.taobao.com']
        for rule, expected in cases:
            rows = convert_rule(rule).splitlines()
            for host in hosts:
                self.assertEqual(any(fnmatch.fnmatchcase(host, r.split(',')[1]) for r in rows), expected(host))

    def test_independent_native_grammar_validation(self):
        self.assertFalse(validate_filter('host,example.com,proxy\nip-cidr,192.0.2.0/24,proxy\n'))
        for line in ['ip-cidr,192.0.2.0/24,proxy,no-resolve',
                     'ip-cidr,192.0.2.1/24,proxy', 'ip6-cidr,192.0.2.0/24,proxy',
                     'ip-asn,invalid,proxy', 'host,https://example.com,proxy']:
            self.assertTrue(validate_filter(line), line)

    def test_url_scope_and_dns_semantics_are_not_silently_omitted(self):
        text = 'payload:\n  - IP-CIDR,192.0.2.0/24,no-resolve\n'
        result = render_filter(text, (r'/igd\.xml',))
        self.assertIn('# QX-DNS:', result)
        self.assertIn('# SCOPE-EXCLUDED', result)
        self.assertIn('ip-cidr,192.0.2.0/24,proxy\n', result)

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
            target.write_text(render_filter(text), encoding="utf-8")
            errors = []
            self.assertEqual(check_quantumultx_pairs(root, errors), 1)
            self.assertEqual(errors, [])
            target.with_name("Orphan.list").write_text("host,example.com,proxy\n", encoding="utf-8")
            errors = []
            check_quantumultx_pairs(root, errors)
            self.assertEqual(errors, ["PAIR EXTRA QuantumultX/Orphan.list"])


if __name__ == "__main__":
    unittest.main()
