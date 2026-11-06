# Fro_AD — Proxy Log Analyzer

Offline command-line reports for the semicolon-separated proxy log layout in your example. Requires Python 3.10 or later, with no packages to install. Works with Windows, Linux and macOS. Logs remain on the machine running the tool; there are no external API calls.

## Try the included example

From this directory:

```
python analyze.py --logs examples/logs --users examples/users.csv --resources examples/resources.csv --out example-reports
```

Open `example-reports/report.html` in your browser. On Linux, use `python3` if needed. On Windows, use `py` if needed.

## Your files

```
py analyze.py --logs "C:\ProxyLogs" --users "C:\Reference\users.csv" --resources "C:\Reference\resources.csv" --out "C:\Reports\run-2026-10"
```

The output folder must be new and outside the logs folder. Each run reads all matching CSV files recursively, rebuilding reports from scratch. Input files are never changed. Do not include overlapping or duplicated exports: every row counts once, including identical rows in different files. Reference files are excluded from logs if placed within the log folder.

### User list

Must have a `login` header. Additional columns are allowed and ignored. Duplicate logins after normalization are rejected. Login matching ignores case unless `--case-sensitive-users` is supplied. Whitespace is trimmed. Domain prefixes are preserved: `CORP\alice` differs from `alice`.

```csv
login
USERNAME1
USERNAME2
```

### Resource list

Must have `resource`, `domain`, and `ip` headers. Each row must contain a resource name and at least a domain or an IP. Use multiple rows with the same resource name for its aliases or additional IP addresses. One IP per row. Domains are matched case-insensitively; URLs or host:port values are normalized to their host.

```csv
resource,domain,ip
Software,software.com,190.10.153.202
Software,login.software.com,
Documentation,docs.example.com,192.0.2.20
```

Reference delimiters (comma, semicolon, tab) are automatically detected; UTF-8 with or without BOM is the default encoding for all inputs. For Windows-1251 files use `--encoding cp1251`.

### Log layout

No header by default. Fields are timestamp, client IP, protocol, proxy status, numeric field, method, destination host, port, login, hierarchy, server IP. The numeric field is not interpreted; its meaning cannot be confirmed from one sample. There must be one pair of quotes around each field, as in the included example. The extra opening quote in the chat example is assumed to be a formatting artifact.

If logs have a header, add `--log-header` (applies to all files). For a different field order use `--columns 0,1,3,6,8,10`, listing zero-based positions for timestamp, client IP, proxy status, destination host, login and server IP respectively. `--delimiter` changes the log delimiter. `--pattern '*.log'` changes the recursive filename pattern.

## Reports

- `users.csv`: counts, outcomes, source-IP count, listed-resource count, first and last activity for every reference user, including users with zero activity.
- `source_ips.csv`: recorded client IPs per login. This answers which IP the user connected from, not country, device identity or physical location. NAT, VPNs and shared proxies may mask the original source.
- `resource_usage.csv`: connection counts and results per login, resource and observed destination; includes unknown users and unlisted destinations.
- `user_resource_coverage.csv`: all reference-user/resource pairs, including zeros, with attempt/success/failure counts.
- `missing_user_resources.csv`: reference-user/resource pairs with no attempts.
- `no_success_user_resources.csv`: pairs with no successful connections, including failed-only and zero-attempt pairs.
- `no_listed_resource_activity.csv`: reference users with no attempts to any listed resource, including users absent from all logs.
- `no_log_activity.csv`: reference users with no valid records in the supplied logs and selected period. This is not proof that they never authenticated.
- `unknown_users.csv`: observed login values absent from the user list, including `(anonymous)` for empty or `-` logins.
- `status_codes.csv` and `daily_activity.csv`: result-code totals and daily connection counts per login.
- `rejected_rows.csv`: invalid semantic rows and their file/line/reason; no raw sensitive rows are copied.
- `summary.json`: inputs, options, row counts and actual date coverage.
- `report.html`: local HTML summary with the first 20 rows of each report and links to the full CSVs.

“Never” always means not observed in this input set and selected date range. Failed attempts count as attempts. A TUNNEL/200 response means that the proxy opened a tunnel; it does not prove a completed page load or meaningful application usage. HTTP 200–399 is classified as success, 400–599 as failed, and other codes as unknown; statuses containing DENIED or FAIL are failed. Adapt this rule if your proxy uses different semantics. Connection counts are not visits, sessions, time spent, authentication events, or human intent; applications can create background traffic.

### Matching and dates

Default matching is exact domain, or direct destination IP. `--subdomains` also matches subdomains; the longest matching listed domain wins. Server-IP fallback is disabled by default because of shared hosting; enable `--ip-fallback` to use it for unmatched hosts only when the IP belongs to exactly one listed resource. Ambiguous IP matches remain unlisted and are counted in the summary. Hostname matches take priority over IP matches. The tool performs no DNS lookup or geolocation.

Use `--from-date 2026-10-01 --to-date 2026-10-31` for inclusive dates. Timestamps are interpreted in the timezone recorded by your proxy, without conversion. Mixed timezone-aware timestamps are rejected: convert logs to one common timezone before use. First/last dates describe observed data, not proof of continuous logging coverage.

### Scale and run status

Parsing uses batches of 10,000 rows and a temporary SQLite database. Provide enough temporary disk space for parsed logs and indexes, plus disk space for output reports. Memory does not grow with the full log row count, but file lists and reference lists are held in memory. Coverage and missing-pair reports can contain users × resources rows and may be very large. No enterprise-scale performance claim has been validated.

Exit 0: completed with valid included rows and no rejected rows. Exit 2: completed but some rows were rejected or no valid rows remained in the selected period; inspect the warnings and rejection report. Exit 1: fatal error, such as invalid reference columns, unreadable files or malformed CSV syntax; disregard partial output and rerun to a new output folder after correcting it. CSV cells that might be interpreted as spreadsheet formulas are prefixed with an apostrophe; JSON options and the original logs are not modified.

Reports contain user identities and network details. Store them with access appropriate to your organization. There is no access-control server: the HTML is a local file.

## Verification

```
python -m unittest -v test_analyze.py
```

Tests cover zero-activity users, failed-only access, case normalization, source addresses, direct-IP matching, shared-IP ambiguity, date filtering, malformed rows, and output overwrite protection. The included data is synthetic and is not analysis of your real logs.

Verified in this environment with Python 3.12: all nine functional tests passed. A synthetic 100,000-row import and report generation completed in about 2 seconds. Actual performance depends on row diversity, reference-list sizes, storage and report cardinality.
