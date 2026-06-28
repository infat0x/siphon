<p align="center">
  <img src="https://i.imgur.com/EyOx34K.png" alt="Siphon Logo" width="500">
</p>

<h1 align="center">Siphon — v7 Ultra</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.19%2B-blue" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

<p align="center">
  <b>Multi-stage JavaScript reconnaissance and secret scanning tool, rewritten in Go for maximum performance.</b>
</p>

## Pipeline

> [!NOTE]
> The workflow runs linearly, chaining multiple tools together to ensure maximum coverage while filtering out noise.

```
subs.txt / -domain
    → httpx (live check)
    → URL harvest (gau + katana + waybackurls + hakrawler + subjs + cariddi)
    → active <script> parsing
    → JS filter (exclude libraries)
    → concurrent download
    → secret scanning (regex + mantra + trufflehog + gitleaks + jsluice + jsleak + nuclei + cariddi)
```

## Requirements

- Go 1.19+
- curl or wget

## Tool Installation

> [!TIP]
> **Quick Start:** We highly recommend using the provided auto-installer script, which handles dependencies, binaries, and `$PATH` configuration.

```bash
chmod +x install_tools.sh
./install_tools.sh
```

<details>
<summary><b>Manual Installation (Click to expand)</b></summary>

```bash
# Required
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Optional but recommended
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest

# URL collectors
go install github.com/lc/subjs@latest
go install github.com/edoardottt/cariddi/cmd/cariddi@latest

# Secret scanners
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/byt3hx/jsleak@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/MrEmpy/mantra@latest

# TruffleHog
wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.3/trufflehog_3.95.3_linux_amd64.tar.gz
tar -xzf trufflehog_3.95.3_linux_amd64.tar.gz && mv trufflehog /usr/local/bin/

# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.24.3/gitleaks_8.24.3_linux_x64.tar.gz
tar -xzf gitleaks_8.24.3_linux_x64.tar.gz && mv gitleaks /usr/local/bin/
```
</details>

## Installation

```bash
# Navigate to the go directory
cd siphon-go

# Build the binary
go build -o siphon main.go
sudo mv siphon /usr/local/bin/
```

## Usage

```bash
# Single domain
siphon -domain example.com -o output/

# Multiple subdomains from file
siphon -s subs.txt -o output/

# With higher thread count
siphon -s subs.txt -o output/ -t 50

# Scan all JS including libraries
siphon -s subs.txt -o output/ -scan-all-js

# Skip stages (use cached results)
siphon -s subs.txt -o output/ -skip-live-check
siphon -s subs.txt -o output/ -skip-url-collection

# Only extract JS URLs, skip download and scanning
siphon -s subs.txt -o output/ -skip-download
```

## Flags

| Flag | Description |
|------|-------------|
| `-domain` | Single domain to scan |
| `-s` | File with subdomains (one per line) |
| `-url` | Single JS file URL to scan directly |
| `-o` | Output directory (required) |
| `-t` | Concurrent threads (default: 30) |
| `-insecure` | Disable TLS verification |
| `-scan-all-js` | Scan all JS including known libraries |
| `-skip-live-check` | Skip httpx |
| `-skip-url-collection`| Skip URL harvest |
| `-skip-download` | Stop after JS extraction |
| `-path` | Filter JS URLs by specific path (e.g. /admin/) |

## Output Structure

<details>
<summary><b>View Directory Structure (Click to expand)</b></summary>

```text
output/
├── live/
│   └── live.txt                  # Live hosts from httpx
├── urls/
│   ├── all_urls.txt              # All collected URLs
├── js/
│   ├── js_urls.txt               # All JS URLs
│   ├── custom_js.txt             # Filtered (no libraries)
│   └── downloaded/               # Downloaded JS files
├── secrets/
│   ├── final_report.txt          # Main report (or final_report.json)
│   └── raw/
│       ├── regex_findings.json
│       ├── trufflehog.json
│       ├── gitleaks.json
│       ├── jsluice_findings.json
│       ├── jsleak_findings.txt
│       └── nuclei_findings.json
└── logs/
    └── log.log
```
</details>

## Downloader Behaviour (v7)

- Downloads are fully concurrent using Goroutines for massive speed improvements.
- Handles massive datasets effortlessly without memory bloat.

## Notes

> [!WARNING]
> `-insecure` disables TLS verification across **all** tools (httpx, katana, hakrawler, etc). Use when target is behind a corporate SSL inspection proxy.

> [!NOTE]
> **Performance & Core Behaviors:**
> - All scanners run concurrently.
> - Findings are deduplicated and aggregated by `type|match` before the final report.
> - Siphon is now fully rewritten in Go, deprecating the Python v6 version.
