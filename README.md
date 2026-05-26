# JS Recon & Secret Hunter — v5

Multi-stage JavaScript reconnaissance and secret scanning tool.

## Pipeline

```
subs.txt / --domain
    → httpx (live check)
    → URL harvest (gau + katana + waybackurls + hakrawler)
    → active <script> parsing
    → JS brute-force (common paths)
    → JS filter (exclude libraries)
    → download (curl → wget → urllib fallback)
    → secret scanning (regex + gf + trufflehog + gitleaks + SecretFinder)
```

## Requirements

- Python 3.8+
- Go 1.19+
- curl or wget

## Tool Installation

```bash
# Required
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest

# Optional but recommended
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/anew@latest

# TruffleHog
wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.3/trufflehog_3.95.3_linux_amd64.tar.gz
tar -xzf trufflehog_3.95.3_linux_amd64.tar.gz && mv trufflehog /usr/local/bin/

# Gitleaks (v5 new)
# https://github.com/gitleaks/gitleaks/releases

# SecretFinder (optional)
git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
pip install -r /opt/SecretFinder/requirements.txt --break-system-packages
ln -s /opt/SecretFinder/SecretFinder.py /usr/local/bin/SecretFinder
```

## Usage

```bash
# Single domain
python3 jsrecon.py --domain example.com -o output/

# Single domain, TLS bypass (self-signed / corporate proxy)
python3 jsrecon.py --domain example.com -o output/ --insecure

# Multiple subdomains from file
python3 jsrecon.py -s subs.txt -o output/

# With higher thread count
python3 jsrecon.py -s subs.txt -o output/ --threads 50 --insecure

# Scan all JS including libraries
python3 jsrecon.py -s subs.txt -o output/ --scan-all-js

# Skip stages (use cached results)
python3 jsrecon.py -s subs.txt -o output/ --skip-live-check
python3 jsrecon.py -s subs.txt -o output/ --skip-url-collection

# Only extract JS URLs, skip download and scanning
python3 jsrecon.py -s subs.txt -o output/ --skip-download
```

## Flags

| Flag | Description |
|------|-------------|
| `-d / --domain` | Single domain to scan |
| `-s / --subs` | File with subdomains (one per line) |
| `-o / --output` | Output directory |
| `-t / --threads` | Worker threads (default: 30) |
| `--insecure` | Disable TLS verification (curl -k, httpx -no-verify-ssl, etc.) |
| `--scan-all-js` | Scan all JS including known libraries |
| `--skip-live-check` | Reuse existing live.txt |
| `--skip-url-collection` | Reuse existing all_urls.txt |
| `--skip-download` | Stop after JS extraction |

## Output Structure

```
output/
├── live/
│   └── live.txt                  # Live hosts from httpx
├── urls/
│   └── all_urls.txt              # All collected URLs
├── js/
│   ├── js_urls.txt               # All JS URLs
│   ├── custom_js.txt             # Filtered (no libraries)
│   └── downloaded/               # Downloaded JS files
│       └── _failed.txt
├── secrets/
│   ├── final_report.txt          # Main report
│   └── raw/
│       ├── regex_findings.json
│       ├── gf_*.txt
│       ├── trufflehog.json
│       └── gitleaks.json
└── logs/
    └── run_YYYYMMDD_HHMMSS.log
```

## Secret Scanners

| Scanner | Type | Notes |
|---------|------|-------|
| regex | Built-in | 35+ patterns, entropy filtering, false-positive suppression |
| gf | External | aws-keys, jwt, firebase, secrets, s3-buckets, etc. |
| trufflehog | External | Filesystem scan, JSON output |
| gitleaks | External | 200+ built-in rules, v5 addition |
| SecretFinder | External | Auto-detected at `/opt/SecretFinder/` or `$PATH` |

## Downloader Behaviour (v5)

- Backend priority: `curl → wget → urllib`
- Per-domain rate limiting (max 4 concurrent, 150ms delay)
- Exponential backoff on failure (2s, 4s)
- User-Agent rotation across retries
- HTTP ↔ HTTPS scheme fallback
- Content validation — rejects HTML error pages
- SHA-256 deduplication (skips identical files from CDN mirrors)
- 15 MB max file size

## Notes

- `--insecure` disables TLS verification across **all** tools (curl, wget, httpx, katana, hakrawler, urllib). Use when target is behind a corporate SSL inspection proxy.
- SecretFinder is auto-detected at `/opt/SecretFinder/SecretFinder.py`, `~/tools/SecretFinder/`, or `$PATH`.
- All scanners run in parallel (ThreadPoolExecutor, 5 workers).
- Findings are deduplicated by `type|match` before the final report.

## License

MIT
