import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('analyze.py')

class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'logs').mkdir()
        (self.root / 'users.csv').write_text('login\nAlice\nBob\nCarol\n', encoding='utf-8')
        (self.root / 'resources.csv').write_text('resource,domain,ip\nSoftware,software.com,192.0.2.1\nDocs,docs.example.com,192.0.2.2\nSharedA,a.example.com,192.0.2.3\nSharedB,b.example.com,192.0.2.3\n', encoding='utf-8')
        self.records = [self.row('ALICE', 'SOFTWARE.com', 'TUNNEL/200'), self.row('Alice', 'docs.example.com', 'TCP_DENIED/403'), self.row('Bob', 'other.example.com', 'TCP_MISS/000')]

    def row(self, user, host, status='TUNNEL/200', server='192.0.2.1', date='2026-10-27 08:03:56.087'):
        return [date, '44.100.230.120', 'TCP', status, '705521', 'CONNECT', host, '443', user, 'HIER_DIRECT', server]

    def run_tool(self, *extra, expected=0, discover=False):
        with (self.root / 'logs' / 'log.csv').open('w', newline='') as f:
            csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL).writerows(self.records)
        cmd = [sys.executable, str(SCRIPT), '--logs', str(self.root / 'logs'), '--users', str(self.root / 'users.csv'), '--resources', str(self.root / 'resources.csv'), '--out', str(self.root / 'reports'), *extra]
        if discover:
            position = cmd.index('--resources')
            del cmd[position:position+2]
        result = subprocess.run(cmd, text=True, capture_output=True)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def report(self, name):
        with (self.root / 'reports' / (name + '.csv')).open(encoding='utf-8-sig', newline='') as f:
            return list(csv.DictReader(f))

    def test_reference_coverage_and_outcomes(self):
        self.run_tool()
        self.assertEqual(self.report('no_log_activity'), [{'login': 'Carol'}])
        self.assertEqual({r['login'] for r in self.report('no_listed_resource_activity')}, {'Bob', 'Carol'})
        missing = {(r['login'], r['resource']) for r in self.report('missing_user_resources')}
        unsuccessful = {(r['login'], r['resource']) for r in self.report('no_success_user_resources')}
        self.assertNotIn(('Alice', 'Docs'), missing)
        self.assertIn(('Alice', 'Docs'), unsuccessful)
        self.assertEqual(len(missing), 10)
        users = {r['login']: r for r in self.report('users')}
        self.assertEqual(users['Alice']['connections'], '2')
        self.assertEqual(users['Alice']['successful'], '1')
        self.assertEqual(users['Alice']['failed'], '1')
        self.assertEqual(users['Bob']['unknown'], '1')
        self.assertEqual(self.report('source_ips')[0]['client_ip'], '44.100.230.120')

    def test_ip_ambiguity_and_domain_priority(self):
        self.records = [self.row('Alice', '192.0.2.1'), self.row('Bob', 'unknown.example.com', server='192.0.2.3'), self.row('Carol', 'software.com', server='192.0.2.3')]
        self.run_tool('--ip-fallback')
        report = {r['login']: r for r in self.report('resource_usage')}
        self.assertEqual(report['Alice']['resource'], 'Software')
        self.assertEqual(report['Bob']['resource'], '[unlisted]')
        self.assertEqual(report['Carol']['resource'], 'Software')
        summary = json.loads((self.root / 'reports' / 'summary.json').read_text())
        self.assertEqual(summary['ambiguous_ip'], 1)

    def test_subdomains_require_opt_in(self):
        self.records = [self.row('Alice', 'login.software.com')]
        self.run_tool()
        self.assertEqual(self.report('resource_usage')[0]['resource'], '[unlisted]')

    def test_subdomains_opt_in(self):
        self.records = [self.row('Alice', 'login.software.com')]
        self.run_tool('--subdomains')
        self.assertEqual(self.report('resource_usage')[0]['resource'], 'Software')

    def test_date_filter_inclusive_and_rejections(self):
        self.records += [self.row('Carol', 'software.com', date='2026-10-28 23:59:59.999'), ['bad']]
        self.run_tool('--from-date', '2026-10-28', '--to-date', '2026-10-28', expected=2)
        summary = json.loads((self.root / 'reports' / 'summary.json').read_text())
        self.assertEqual(summary['parsed'], 1)
        self.assertEqual(summary['outside_period'], 3)
        self.assertEqual(summary['rejected'], 1)
        self.assertEqual(self.report('users')[0]['login'], 'Carol')

    def test_existing_output_is_not_overwritten(self):
        self.run_tool()
        report = (self.root / 'reports' / 'summary.json').read_bytes()
        self.run_tool(expected=1)
        self.assertEqual((self.root / 'reports' / 'summary.json').read_bytes(), report)

    def test_formula_safety_and_html_escaping(self):
        self.records = [self.row('=1+1', '<script>.example.com')]
        self.run_tool()
        self.assertEqual(self.report('unknown_users')[0]['login'], "'=1+1")
        page = (self.root / 'reports' / 'report.html').read_text()
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;script&gt;', page)

    def test_empty_period_warns(self):
        self.run_tool('--from-date', '2027-01-01', expected=2)
        self.assertIn('No valid records', (self.root / 'reports' / 'report.html').read_text())

    def test_duplicate_reference_is_rejected(self):
        (self.root / 'users.csv').write_text('login\nAlice\nalice\n')
        self.run_tool(expected=1)
        self.assertFalse((self.root / 'reports').exists())

    def test_discovery_and_zero_activity_coverage(self):
        (self.root / 'resources.csv').unlink()
        self.records.append(self.row('UnlistedUser', 'unknown.example.com', server='192.0.2.50'))
        self.run_tool(discover=True)
        resources = {r['resource'] for r in self.report('resources')}
        self.assertEqual(resources, {'software.com', 'docs.example.com', 'other.example.com', 'unknown.example.com'})
        self.assertEqual(len(self.report('user_resource_coverage')), 12)
        missing = {(r['login'], r['resource']) for r in self.report('missing_user_resources')}
        self.assertIn(('Bob', 'software.com'), missing)
        self.assertNotIn(('Alice', 'docs.example.com'), missing)
        self.assertEqual(self.report('no_log_activity'), [{'login': 'Carol'}])
        summary = json.loads((self.root / 'reports' / 'summary.json').read_text())
        self.assertEqual(summary['resource_mode'], 'discovered')
        self.assertEqual(summary['listed_resources'], 4)

    def test_discovery_normalizes_domains_and_retains_distinct_ips(self):
        self.records = [self.row('Alice', 'SOFTWARE.com'), self.row('Alice', 'software.com', server='192.0.2.9'), self.row('Bob', 'software.com'), self.row('Bob', 'other.example.com')]
        self.run_tool(discover=True)
        resources = self.report('resources')
        self.assertEqual(len(resources), 3)
        self.assertEqual({r['ip'] for r in resources if r['resource'] == 'software.com'}, {'192.0.2.1', '192.0.2.9'})
        self.assertEqual(len({r['resource'] for r in resources}), 2)
        coverage = [r for r in self.report('user_resource_coverage') if r['login'] == 'Alice' and r['resource'] == 'software.com']
        self.assertEqual(coverage[0]['attempts'], '2')

    def test_failed_missing_ip_and_direct_ip_are_discovered(self):
        self.records = [self.row('Alice', 'blocked.example.com', 'TCP_DENIED/403', server='-'), self.row('Bob', '2001:db8::1', server='-')]
        self.run_tool(discover=True)
        resources = {r['resource']: r for r in self.report('resources')}
        self.assertEqual(resources['blocked.example.com']['ip'], '')
        self.assertEqual(resources['2001:db8::1']['ip'], '2001:db8::1')
        no_success = {(r['login'], r['resource']) for r in self.report('no_success_user_resources')}
        self.assertIn(('Alice', 'blocked.example.com'), no_success)
        self.assertNotIn(('Alice', 'blocked.example.com'), {(r['login'], r['resource']) for r in self.report('missing_user_resources')})

    def test_discovery_uses_selected_period_and_rejects_bad_rows(self):
        self.records = [self.row('Alice', 'old.example.com'), self.row('Bob', 'new.example.com', date='2026-10-28 00:00:00'), ['bad']]
        self.run_tool('--from-date', '2026-10-28', discover=True, expected=2)
        self.assertEqual({r['resource'] for r in self.report('resources')}, {'new.example.com'})

    def test_empty_discovery_has_no_resources(self):
        self.run_tool('--from-date', '2027-01-01', discover=True, expected=2)
        self.assertEqual(self.report('resources'), [])
        self.assertEqual(self.report('user_resource_coverage'), [])
        self.assertEqual(len(self.report('no_log_activity')), 3)

    def test_generated_resources_can_be_reused(self):
        self.run_tool(discover=True)
        generated = self.root / 'reports' / 'resources.csv'
        expected = self.report('user_resource_coverage')
        result = subprocess.run([sys.executable, str(SCRIPT), '--logs', str(self.root / 'logs'), '--users', str(self.root / 'users.csv'), '--resources', str(generated), '--out', str(self.root / 'reuse')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.root / 'reuse' / 'user_resource_coverage.csv').open(encoding='utf-8-sig') as f:
            self.assertEqual(list(csv.DictReader(f)), expected)

if __name__ == '__main__':
    unittest.main()
