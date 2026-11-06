#!/usr/bin/env python3
"""Offline proxy CSV analyzer. Python 3.10+; no third-party packages."""
import argparse
import csv
import datetime as dt
import html
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
from urllib.parse import urlsplit


def host(value):
    value = value.strip().lower().rstrip('.')
    if not value:
        return ''
    try:
        return str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        return (urlsplit(value if '://' in value else '//' + value).hostname or '').rstrip('.').encode('idna').decode()


def rows(path, encoding, delimiter=None):
    with path.open(encoding=encoding, newline='') as f:
        if delimiter is None:
            sample = f.read(8192)
            f.seek(0)
            try:
                delimiter = csv.Sniffer().sniff(sample, delimiters=';,\t').delimiter
            except csv.Error:
                delimiter = ','
        reader = csv.reader(f, delimiter=delimiter, strict=True)
        for row in reader:
            if row and any(v.strip() for v in row):
                yield reader.line_num, row


def write_csv(path, headings, records):
    # Protect spreadsheet users against formulas originating in log fields.
    def safe(v):
        if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@')):
            return "'" + v
        return v
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headings)
        for row in records:
            writer.writerow([safe(v) for v in row])


def read_reference(path, encoding, required):
    source = iter(rows(path, encoding))
    try:
        _, header = next(source)
    except StopIteration:
        raise ValueError(f'{path}: empty reference file')
    header = [v.strip().lower() for v in header]
    if not required.issubset(header):
        raise ValueError(f'{path}: required headers: {sorted(required)}')
    for line, row in source:
        if len(row) != len(header):
            raise ValueError(f'{path}:{line}: column count differs from header')
        yield line, dict(zip(header, (v.strip() for v in row)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--logs', required=True, type=Path)
    p.add_argument('--users', required=True, type=Path)
    p.add_argument('--resources', type=Path, help='Optional existing resource CSV; otherwise discover resources from logs')
    p.add_argument('--out', required=True, type=Path, help='New output directory; must not exist')
    p.add_argument('--pattern', default='*.csv', help='Recursive log filename pattern')
    p.add_argument('--encoding', default='utf-8-sig')
    p.add_argument('--delimiter', default=';')
    p.add_argument('--log-header', action='store_true')
    p.add_argument('--columns', default='0,1,3,6,8,10', help='Zero-based timestamp,client IP,status,host,login,server IP positions')
    p.add_argument('--from-date', type=dt.date.fromisoformat)
    p.add_argument('--to-date', type=dt.date.fromisoformat)
    p.add_argument('--subdomains', action='store_true', help='Also match subdomains; longest listed domain wins')
    p.add_argument('--case-sensitive-users', action='store_true')
    p.add_argument('--ip-fallback', action='store_true', help='Match unknown host by server IP only when unique across resources')
    a = p.parse_args()
    columns = [int(x) for x in a.columns.split(',')]
    if len(columns) != 6 or min(columns) < 0:
        p.error('--columns requires six nonnegative positions')
    if len(a.delimiter) != 1:
        p.error('--delimiter must be one character')
    if a.from_date and a.to_date and a.from_date > a.to_date:
        p.error('--from-date must precede --to-date')
    if not a.logs.is_dir():
        p.error('--logs must be an existing folder')
    normalize = (lambda v: v.strip()) if a.case_sensitive_users else (lambda v: v.strip().casefold())
    users = {}
    for line, row in read_reference(a.users, a.encoding, {'login'}):
        login = row['login']
        if not login or login in {'-', '(anonymous)'}:
            raise ValueError(f'{a.users}:{line}: empty or reserved login')
        key = normalize(login)
        if key in users:
            raise ValueError(f'{a.users}:{line}: duplicate normalized login {login}')
        users[key] = login
    domains, ips, resources = {}, {}, set()
    reference_rows = read_reference(a.resources, a.encoding, {'resource', 'domain', 'ip'}) if a.resources else []
    for line, row in reference_rows:
        resource = row['resource']
        if not resource or not (row['domain'] or row['ip']):
            raise ValueError(f'{a.resources}:{line}: resource and domain or IP required')
        resources.add(resource)
        if row['domain']:
            name = host(row['domain'])
            if not name:
                raise ValueError(f'{a.resources}:{line}: invalid domain')
            if name in domains and domains[name] != resource:
                raise ValueError(f'{a.resources}:{line}: domain assigned to multiple resources')
            domains[name] = resource
        if row['ip']:
            ip = str(ipaddress.ip_address(row['ip']))
            ips.setdefault(ip, set()).add(resource)
    if not users or (a.resources and not resources):
        raise ValueError('User and supplied resource reference lists must contain data')
    if a.out.resolve().is_relative_to(a.logs.resolve()):
        raise ValueError('Output folder must be outside the log folder')
    excluded = {a.users.resolve()}
    if a.resources:
        excluded.add(a.resources.resolve())
    files = sorted(f for f in a.logs.rglob(a.pattern) if f.is_file() and f.resolve() not in excluded)
    if not files:
        raise ValueError('No matching log files found')
    # Existing reports are never overwritten. Every run rebuilds from its input set.
    a.out.mkdir(parents=True, exist_ok=False)
    summary = dict(files=len(files), parsed=0, rejected=0, outside_period=0, ambiguous_ip=0)
    with tempfile.TemporaryDirectory(prefix='proxy-analysis-') as temp:
        db = sqlite3.connect(str(Path(temp) / 'analysis.sqlite'))
        db.execute('CREATE TABLE users(login TEXT PRIMARY KEY, display TEXT)')
        db.executemany('INSERT INTO users VALUES(?,?)', users.items())
        db.execute('CREATE TABLE resources(resource TEXT PRIMARY KEY)')
        db.executemany('INSERT INTO resources VALUES(?)', ((r,) for r in sorted(resources)))
        db.execute('CREATE TABLE events(login TEXT, source TEXT, resource TEXT, host TEXT, status TEXT, outcome TEXT, timestamp TEXT, server_ip TEXT)')
        with (a.out / 'rejected_rows.csv').open('w', encoding='utf-8-sig', newline='') as reject_file:
            rejects = csv.writer(reject_file)
            rejects.writerow(['file', 'line', 'reason'])
            for number, file in enumerate(files, 1):
                print(f'[{number}/{len(files)}] {file}', file=sys.stderr)
                source = iter(rows(file, a.encoding, a.delimiter))
                if a.log_header:
                    next(source, None)
                batch = []
                for line, row in source:
                    try:
                        stamp, client, status, destination, login, server = [row[i].strip() for i in columns]
                        when = dt.datetime.fromisoformat(stamp)
                        if when.tzinfo is not None:
                            raise ValueError('timezone-aware dates require conversion to a common timezone first')
                        client = str(ipaddress.ip_address(client))
                        target = host(destination)
                        if not target:
                            raise ValueError('empty destination')
                        match = re.fullmatch(r'[^/\s]+/(\d{3})', status)
                        if not match:
                            raise ValueError('expected proxy status such as TUNNEL/200')
                        code = int(match[1])
                        outcome = 'success' if 200 <= code < 400 else 'failed' if 400 <= code < 600 else 'unknown'
                        if 'DENIED' in status.upper() or 'FAIL' in status.upper():
                            outcome = 'failed'
                        if (a.from_date and when.date() < a.from_date) or (a.to_date and when.date() > a.to_date):
                            summary['outside_period'] += 1
                            continue
                        resource = domains.get(target)
                        if not resource and a.subdomains:
                            labels = target.split('.')
                            for i in range(1, len(labels)):
                                resource = domains.get('.'.join(labels[i:]))
                                if resource:
                                    break
                        try:
                            direct_ip = str(ipaddress.ip_address(target))
                        except ValueError:
                            direct_ip = None
                        candidates = ips.get(direct_ip, set()) if direct_ip else set()
                        if not resource and not candidates and a.ip_fallback:
                            try:
                                candidates = ips.get(str(ipaddress.ip_address(server)), set())
                            except ValueError:
                                pass
                        if not resource and len(candidates) == 1:
                            resource = next(iter(candidates))
                        elif not resource and len(candidates) > 1:
                            summary['ambiguous_ip'] += 1
                        if not a.resources:
                            # Each exact observed host is its own resource; never merge shared IPs.
                            resource = target
                        try:
                            observed_ip = str(ipaddress.ip_address(server))
                        except ValueError:
                            observed_ip = direct_ip or ''
                        user = normalize(login) if login and login != '-' else '(anonymous)'
                        batch.append((user, client, resource, target, status, outcome, when.isoformat(sep=' '), observed_ip))
                        summary['parsed'] += 1
                    except (ValueError, IndexError, UnicodeError) as e:
                        summary['rejected'] += 1
                        rejects.writerow([str(file), line, str(e)])
                    if len(batch) >= 10000:
                        db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)', batch)
                        batch.clear()
                db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)', batch)
                db.commit()
        if not a.resources:
            db.execute('INSERT INTO resources SELECT DISTINCT resource FROM events')
            db.commit()
        db.executescript('CREATE INDEX event_login ON events(login); CREATE INDEX event_pair ON events(login,resource);')
        summary['first_record'], summary['last_record'] = db.execute('SELECT MIN(timestamp),MAX(timestamp) FROM events').fetchone()
        summary['supplied_users'] = len(users)
        summary['listed_resources'] = db.execute('SELECT COUNT(*) FROM resources').fetchone()[0]
        summary['resource_mode'] = 'reference' if a.resources else 'discovered'
        summary['input_files'] = [str(f.resolve()) for f in files]
        summary['arguments'] = {k: str(v) if isinstance(v, (Path, dt.date)) else v for k, v in vars(a).items()}
        queries = {
            'users': '''SELECT u.display AS login,COUNT(e.login) AS connections,
              SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS successful,
              SUM(CASE WHEN outcome='failed' THEN 1 ELSE 0 END) AS failed,
              SUM(CASE WHEN outcome='unknown' THEN 1 ELSE 0 END) AS unknown,
              COUNT(DISTINCT e.source) AS source_ips,COUNT(DISTINCT e.resource) AS listed_resources,
              MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen
              FROM users u LEFT JOIN events e ON e.login=u.login GROUP BY u.login ORDER BY connections DESC,u.display''',
            'no_log_activity': '''SELECT display AS login FROM users u WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.login=u.login) ORDER BY display''',
            'no_listed_resource_activity': '''SELECT display AS login FROM users u WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.login=u.login AND resource IS NOT NULL) ORDER BY display''',
            'user_resource_coverage': '''SELECT u.display AS login,r.resource,COUNT(e.login) AS attempts,
              SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS successful,
              SUM(CASE WHEN outcome='failed' THEN 1 ELSE 0 END) AS failed,
              SUM(CASE WHEN outcome='unknown' THEN 1 ELSE 0 END) AS unknown,
              MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen
              FROM users u CROSS JOIN resources r LEFT JOIN events e ON e.login=u.login AND e.resource=r.resource
              GROUP BY u.login,r.resource ORDER BY u.display,r.resource''',
            'missing_user_resources': '''SELECT u.display AS login,r.resource FROM users u CROSS JOIN resources r
              WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.login=u.login AND e.resource=r.resource) ORDER BY u.display,r.resource''',
            'no_success_user_resources': '''SELECT u.display AS login,r.resource FROM users u CROSS JOIN resources r
              WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.login=u.login AND e.resource=r.resource AND outcome='success') ORDER BY u.display,r.resource''',
            'source_ips': '''SELECT COALESCE(u.display,e.login) AS login,source AS client_ip,COUNT(*) AS connections,
              MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen FROM events e LEFT JOIN users u ON u.login=e.login GROUP BY e.login,source ORDER BY connections DESC''',
            'resource_usage': '''SELECT COALESCE(u.display,e.login) AS login,COALESCE(resource,'[unlisted]') AS resource,
              host,COUNT(*) AS connections,SUM(outcome='success') AS successful,SUM(outcome='failed') AS failed,
              SUM(outcome='unknown') AS unknown,MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen
              FROM events e LEFT JOIN users u ON u.login=e.login GROUP BY e.login,resource,host ORDER BY connections DESC''',
            'status_codes': '''SELECT status,outcome,COUNT(*) AS connections FROM events GROUP BY status,outcome ORDER BY connections DESC''',
            'unknown_users': '''SELECT e.login,COUNT(*) AS connections FROM events e WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.login=e.login) GROUP BY e.login ORDER BY connections DESC''',
            'daily_activity': '''SELECT substr(timestamp,1,10) AS date,COALESCE(u.display,e.login) AS login,
              COUNT(*) AS connections FROM events e LEFT JOIN users u ON u.login=e.login GROUP BY date,e.login ORDER BY date,login'''
        }
        if not a.resources:
            queries = {'resources': '''SELECT DISTINCT resource,host AS domain,server_ip AS ip
              FROM events ORDER BY resource,ip''', **queries}
        previews = []
        for name, query in queries.items():
            cursor = db.execute(query)
            headings = [col[0] for col in cursor.description]
            write_csv(a.out / (name + '.csv'), headings, cursor)
            preview = db.execute(query + ' LIMIT 20').fetchall()
            table = '<tr>' + ''.join('<th>' + html.escape(h) + '</th>' for h in headings) + '</tr>'
            table += ''.join('<tr>' + ''.join('<td>' + html.escape(str(v) if v is not None else '') + '</td>' for v in row) + '</tr>' for row in preview)
            previews.append(f'<h2>{html.escape(name)}</h2><p><a href="{name}.csv">Full CSV</a> · First 20 rows</p><div><table>{table}</table></div>')
        (a.out / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        page = '''<!doctype html><meta charset="utf-8"><title>Proxy activity report</title>
        <style>body{font:15px system-ui;margin:32px;max-width:1400px;color:#203048}h2{margin-top:36px}table{border-collapse:collapse}td,th{padding:8px 12px;border-bottom:1px solid #ddd;text-align:left;white-space:nowrap}th{background:#eef3f8}div{overflow:auto}a{color:#1264ad}</style>
        <h1>Proxy activity report</h1><p>Counts represent log records / connection attempts, not page visits or time spent.
        Success means HTTP 2xx/3xx or a tunnel opened; it does not prove that the application worked.
        Missing activity applies only to these supplied logs and filters. Client IP is the recorded source; no geographic location is inferred.</p>'''
        if not a.resources:
            page += '<p>Resources were discovered from valid records in the selected period. Each exact destination host is one resource. Resources absent from all supplied records cannot be discovered.</p>'
        if not summary['parsed']:
            page += '<p><strong>No valid records in the selected period. Absence reports cannot establish actual inactivity.</strong></p>'
        page += '<p>' + html.escape(f"Period: {summary['first_record']} — {summary['last_record']}. Included: {summary['parsed']:,}; rejected: {summary['rejected']:,}; outside filter: {summary['outside_period']:,}.") + '</p>'
        page += '<p><a href="summary.json">Run details</a> · <a href="rejected_rows.csv">Rejected rows</a></p>' + ''.join(previews)
        (a.out / 'report.html').write_text(page, encoding='utf-8')
        db.close()
    print(f'Reports written to {a.out.resolve()}')
    if not summary['parsed']:
        print('WARNING: no valid records in the selected period; absence reports do not establish actual inactivity.', file=sys.stderr)
    return 2 if summary['rejected'] or not summary['parsed'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, csv.Error, sqlite3.Error) as e:
        print(f'ERROR: {e}. The run is incomplete; do not rely on partial reports.', file=sys.stderr)
        sys.exit(1)
