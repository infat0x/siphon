<p align="center">
  <img src="https://i.imgur.com/XpGnKSb.png" alt="Siphon Logo" width="200" style="border-radius: 20px;">
</p>

# Siphon — v6

Multi-stage JavaScript reconnaissance and secret scanning tool.

## Pipeline

```
subs.txt / --domain
    → httpx (live check)
    → URL harvest (gau + katana + waybackurls + hakrawler + subjs + cariddi)
    → active <script> parsing
    → JS brute-force (ffuf → head_ok fallback, alt extensions)
    → JS filter (exclude libraries)
    → download (curl → wget → urllib fallback)
    → git exposure check (git-dumper)
    → secret scanning (regex + gf + trufflehog + gitleaks + SecretFinder + jsluice + jsleak + nuclei + cariddi)
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

# v6 new URL collectors & fuzzers
go install github.com/lc/subjs@latest
go install github.com/edoardottt/cariddi/cmd/cariddi@latest
go install github.com/ffuf/ffuf/v2@latest

# v6 new secret scanners
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/byt3hx/jsleak@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# TruffleHog
wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.3/trufflehog_3.95.3_linux_amd64.tar.gz
tar -xzf trufflehog_3.95.3_linux_amd64.tar.gz && mv trufflehog /usr/local/bin/

# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.24.3/gitleaks_8.24.3_linux_x64.tar.gz
tar -xzf gitleaks_8.24.3_linux_x64.tar.gz && mv gitleaks /usr/local/bin/

# SecretFinder (optional)
git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
pip install -r /opt/SecretFinder/requirements.txt --break-system-packages
ln -s /opt/SecretFinder/SecretFinder.py /usr/local/bin/SecretFinder

# git-dumper (optional)
pip install git-dumper
```

## Usage

```bash
# Single domain
python3 siphon.py --domain example.com -o output/

# Single domain, TLS bypass (self-signed / corporate proxy)
python3 siphon.py --domain example.com -o output/ --insecure

# Multiple subdomains from file
python3 siphon.py -s subs.txt -o output/

# With higher thread count
python3 siphon.py -s subs.txt -o output/ --threads 50 --insecure

# Scan all JS including libraries
python3 siphon.py -s subs.txt -o output/ --scan-all-js

# Skip stages (use cached results)
python3 siphon.py -s subs.txt -o output/ --skip-live-check
python3 siphon.py -s subs.txt -o output/ --skip-url-collection

# Only extract JS URLs, skip download and scanning
python3 siphon.py -s subs.txt -o output/ --skip-download
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
│   ├── all_urls.txt              # All collected URLs
│   └── cariddi_secrets.json      # Secrets found during cariddi crawl
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
│       ├── gitleaks.json
│       ├── jsluice_findings.json
│       ├── jsleak_findings.txt
│       └── nuclei_findings.json
├── git_dumps/                    # Dumped .git repositories
└── logs/
    └── run_YYYYMMDD_HHMMSS.log
```

## Secret Scanners

| Scanner | Type | Notes |
|---------|------|-------|
| regex | Built-in | 35+ patterns, entropy filtering, false-positive suppression |
| gf | External | aws-keys, jwt, firebase, secrets, s3-buckets, etc. |
| trufflehog | External | Filesystem scan, JSON output |
| gitleaks | External | 200+ built-in rules, also scans dumped .git repos |
| SecretFinder | External | Auto-detected at `/opt/SecretFinder/` or `$PATH` |
| jsluice | External | AST-based JS secret extraction (context-aware) |
| jsleak | External | Fast per-file secret/path scanner |
| nuclei | External | `http/exposures/` templates over live JS URLs |
| cariddi | External | Crawl + secret scan combined (findings merged) |

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
- All scanners run in parallel (ThreadPoolExecutor, 10 workers).
- Findings are deduplicated by `type|match` before the final report.
- `ffuf` replaces the head_ok loop for JS brute-forcing when available (much faster).
- `git-dumper` checks `/.git/config` exposure and dumps accessible repos.
- `head_ok()` tries `.jsx`, `.ts`, `.mjs`, `.cjs` extensions on 404.

## License

MIT
