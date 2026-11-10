import json
import datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from generate import add_adblock, build, curate_adblock, fetch, parse, write_outputs


def source(name='test', policy='REJECT', use='routing', format='module', early=False):
    return {'name': name, 'policy': policy, 'use': use, 'format': format,
            'url': 'https://example.com/public.module', 'min_domains': 1, 'early': early}


class GenerationTests(unittest.TestCase):
    def adblock_fixture(self, status=None):
        if status is None:
            status = (r'^https?:\/\/ios\.chat\.openai\.com\/public-api\/mobile\/app_support_status '
                      'data-type=json data="{}" status-code=200\n')
        return ('#!name=Upstream\n#!author=Original Author\n#!url=https://example.com/original.module\n'
                '[Rule]\nDOMAIN,ads.example.com,REJECT,pre-matching\n'
                '[Map Local]\n' + status +
                '^https://example.com/ad data-type=json data="{}"\n'
                '[Script]\noriginal=type=http-response,pattern=^https://example.com/,script-path=https://example.com/a.js\n'
                '[MITM]\nhostname = example.com\n').encode()

    def test_adblock_preserves_features_and_attribution_while_restoring_status(self):
        config = {'url': 'https://example.com/adblock.module', 'min_lines': 1, 'min_rules': 1}
        body = self.adblock_fixture()
        result, metadata = curate_adblock(config, body)
        self.assertNotIn('app_support_status', result)
        self.assertIn('#!author=Original Author\n', result)
        self.assertNotIn('#!url=https://example.com/original.module', result)
        self.assertIn('generated/adblock.module\n', result)
        self.assertEqual(result[result.index('[Rule]'):],
                         body.decode()[body.decode().index('[Rule]'):].replace(
                             next(line for line in body.decode().splitlines(True) if 'app_support_status' in line), '', 1))
        self.assertEqual(metadata['removed_empty_chatgpt_status_rules'], 1)
        files = add_adblock(build([], {}), config, body)
        self.assertIn('adblock.module', json.loads(files['manifest.json'])['files'])

    def test_adblock_stops_if_the_status_rewrite_changes_semantics(self):
        config = {'url': 'https://example.com/adblock.module', 'min_lines': 1, 'min_rules': 1}
        status = ('^https://ios.chat.openai.com/public-api/mobile/app_support_status '
                  'data-type=json data="[]" status-code=200\n')
        with self.assertRaisesRegex(ValueError, 'status rewrite changed'):
            curate_adblock(config, self.adblock_fixture(status))
        fixed, metadata = curate_adblock(config, self.adblock_fixture(''))
        self.assertEqual(metadata['removed_empty_chatgpt_status_rules'], 0)
        self.assertIn('[Script]', fixed)

    def test_adblock_rejects_error_pages_and_truncated_modules(self):
        config = {'url': 'https://example.com/adblock.module', 'min_lines': 1, 'min_rules': 1}
        with self.assertRaises(ValueError):
            curate_adblock(config, b'<html>error</html>')
        with self.assertRaises(ValueError):
            curate_adblock(config, b'#!name=Unexpected\n[Rule]\nDOMAIN,ads.example.com,REJECT\n')

    def test_adblock_stops_if_status_regex_escaping_changes(self):
        config = {'url': 'https://example.com/adblock.module', 'min_lines': 1, 'min_rules': 1}
        body = self.adblock_fixture().replace(rb'ios\.chat', b'ios.chat')
        with self.assertRaisesRegex(ValueError, 'status rewrite changed'):
            curate_adblock(config, body)

    def test_domainset_leading_dot_and_tld_are_preserved(self):
        item = parse(source('cn', 'DIRECT', format='domainset'), b'# comment\n.cn\n.example.com\nexact.example.org\n')
        self.assertIn(('DOMAIN-SUFFIX', 'cn', ()), item.domains)
        self.assertIn(('DOMAIN-SUFFIX', 'example.com', ()), item.domains)
        self.assertIn(('DOMAIN', 'exact.example.org', ()), item.domains)

    def test_suffix_coverage_keeps_deep_names_and_domain_boundaries(self):
        item = parse(source(), b'[Rule]\nDOMAIN-SUFFIX,ads.example.com,REJECT\n')
        result = build([item], {'early': ['one.deep.ads.example.com']})
        self.assertIn('DOMAIN-SUFFIX,ads.example.com,REJECT,pre-matching', result['native-reject.module'])
        with self.assertRaises(ValueError):
            build([item], {'early': ['badads.example.com']})

    def test_parent_allow_scope_defers_child_reject_only(self):
        item = parse(source(), b'[Rule]\nDOMAIN,login.sdk.example.com,REJECT\n'
                     b'DOMAIN,ads.other.example.com,REJECT\n')
        result = build([item], {}, {'allow': {'suffix': ['sdk.example.com']}})
        self.assertNotIn('DOMAIN,login.sdk.example.com,REJECT', result['native-reject.module'])
        self.assertIn('DOMAIN,ads.other.example.com,REJECT,pre-matching', result['native-reject.module'])
        self.assertIn('DOMAIN,login.sdk.example.com', result['reject-deferred.list'])

    def test_keep_options_and_non_domain_routing(self):
        item = parse(source(), b'[Rule]\nDOMAIN,ad.example.com,REJECT,pre-matching\n'
                     b'IP-CIDR,192.0.2.0/24,REJECT,no-resolve\n'
                     b'URL-REGEX,^https://example.com/a,b,REJECT\n'
                     b'AND,((DOMAIN,example.com),(DST-PORT,443)),REJECT\n')
        result = build([item], {})
        self.assertIn('DOMAIN,ad.example.com,REJECT,pre-matching\n', result['native-reject.module'])
        self.assertIn('IP-CIDR,192.0.2.0/24,no-resolve\n', result['reject-deferred.list'])
        self.assertIn('URL-REGEX,^https://example.com/a,b\n', result['reject-deferred.list'])
        self.assertIn('AND,((DOMAIN,example.com),(DST-PORT,443))\n', result['reject-deferred.list'])
        self.assertNotIn('[Host]', result['native-reject.module'])

    def test_dns_only_module_cannot_change_connection_policy(self):
        direct = parse(source('direct', 'DIRECT'), b'[Rule]\nDOMAIN-SUFFIX,example.com,DIRECT\n')
        feature = parse(source('feature', use='dns'), b'[Rule]\nDOMAIN,deep.ad.example.com,REJECT\n'
                        b'DOMAIN,allow.example.com,DIRECT\n'
                        b'URL-REGEX,^https://example.com/ad,REJECT\n'
                        b'[Script]\nprivate-script=http-response,script-path=https://invalid.test/run.js\n')
        result = build([direct, feature], {})
        self.assertNotIn('deep.ad.example.com', result['native-reject.module'])
        self.assertNotIn('private-script', ''.join(result.values()))

    def test_native_module_preserves_recursive_suffix_and_uses_literal_policy(self):
        item = parse(source(), b'[Rule]\nDOMAIN-SUFFIX,ads.example.com,REJECT\n'
                     b'DOMAIN,deep.metrics.ads.example.com,REJECT,extended-matching\n')
        result = build([item], {})['native-reject.module']
        self.assertNotIn('[General]', result)
        self.assertIn('DOMAIN-SUFFIX,ads.example.com,REJECT,pre-matching\n', result)
        self.assertIn('DOMAIN,deep.metrics.ads.example.com,REJECT,extended-matching,pre-matching\n', result)
        self.assertNotIn('[Host]', result)
        self.assertNotIn('[Script]', result)

    def test_native_early_reject_does_not_override_feature_allow_exception(self):
        feature = parse(source(use='dns', early=True), b'[Rule]\nDOMAIN-SUFFIX,sdk.example.com,REJECT\n'
                        b'DOMAIN,login.sdk.example.com,DIRECT\n'
                        b'DOMAIN,other.ads.example.com,REJECT\n')
        result = build([feature], {})
        self.assertNotIn('DOMAIN-SUFFIX,sdk.example.com,REJECT', result['native-reject.module'])
        self.assertIn('DOMAIN,other.ads.example.com,REJECT,pre-matching', result['native-reject.module'])
        report = json.loads(result['manifest.json'])
        self.assertEqual(len(report['native_deferred_rules']), 1)
        self.assertEqual(report['native_protected_scopes'], 1)

    def test_manual_exception_is_exact_and_does_not_whitelist_neighbors(self):
        item = parse(source(), b'[Rule]\nDOMAIN,normal.example.com,REJECT\n'
                     b'DOMAIN,ads.example.com,REJECT\n')
        result = build([item], {}, {'allow': {'exact': ['normal.example.com']}})
        self.assertNotIn('DOMAIN,normal.example.com,REJECT', result['native-reject.module'])
        self.assertIn('DOMAIN,ads.example.com,REJECT,pre-matching', result['native-reject.module'])
        # The early gate is deferred; this does not silently change legacy routing.
        self.assertIn('DOMAIN,normal.example.com\n', result['reject-deferred.list'])

    def test_early_normal_control_blocks_a_bad_release(self):
        item = parse(source(), b'[Rule]\nDOMAIN-SUFFIX,example.com,REJECT\n')
        with self.assertRaisesRegex(ValueError, 'normal control'):
            build([item], {'early_unbound': ['normal.example.com']})

    def test_reject_mixed_routing_policy_and_unknown_options(self):
        for text in (b'[Rule]\nDOMAIN,a.example.com,REJECT\nDOMAIN,ok.example.com,DIRECT\n',
                     b'[Rule]\nDOMAIN,a.example.com,REJECT,unknown-condition\n',
                     b'[Rule]\nUNKNOWN,a,REJECT\nDOMAIN,a.example.com,REJECT\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse(source(), text)

    def test_short_or_html_upstream_is_not_a_valid_update(self):
        with self.assertRaises(ValueError):
            parse(source(), b'<html>Access denied</html>')
        with self.assertRaises(ValueError):
            parse(source(), b'[Rule]\n')

    def test_failed_check_leaves_previous_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'native-reject.module'
            target.write_text('previous valid generation')
            with self.assertRaises(ValueError):
                write_outputs(Path(temporary), build([], {'early': ['required.example.com']}))
            self.assertEqual(target.read_text(), 'previous valid generation')

    def test_cache_is_explicit_and_expires(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'snapshot.module').write_bytes(b'[Rule]\nDOMAIN,ad.example.com,REJECT\n')
            config = {**source(use='dns'), 'fallback': 'snapshot.module',
                      'fallback_recorded': datetime.date.today().isoformat(), 'fallback_max_days': 7}
            with patch('generate.urlopen', side_effect=OSError('unavailable')):
                item = fetch(config, root)
                self.assertTrue(item.fallback)
                self.assertTrue(json.loads(build([item], {})['manifest.json'])['sources'][0]['fallback'])
                config['fallback_recorded'] = (datetime.date.today() - datetime.timedelta(days=8)).isoformat()
                with self.assertRaisesRegex(ValueError, 'expired'):
                    fetch(config, root)

    def test_deterministic_deduplication_and_manifest_hashes(self):
        item = parse(source(), b'[Rule]\nDOMAIN,a.example.com,REJECT\nDOMAIN,a.example.com,REJECT\n')
        result = build([item, item], {})
        self.assertEqual(result['native-reject.module'].count('DOMAIN,a.example.com,REJECT,pre-matching\n'), 1)
        self.assertEqual(result, build([item, item], {}))
        manifest = json.loads(result['manifest.json'])
        self.assertEqual(manifest['native_early_reject_rules'], 1)


if __name__ == '__main__':
    unittest.main()
