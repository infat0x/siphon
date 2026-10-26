# CLI Usage

Siphon offers a comprehensive set of command-line flags to customize your reconnaissance and scanning runs.

## Basic Flags
- `-domain`: Single domain to scan (e.g. `example.com`).
- `-s`: Path to a file containing a list of target subdomains (one per line).
- `-url`: Scan a single target JavaScript file directly.
- `-o`: Output directory for reports and logs (required).
- `-t`: Concurrent thread count (default: `30`).

## Authenticated Scanning
Siphon supports authenticated scanning to crawl, extract, and analyze private JavaScript files behind login portals:
- `-H` / `-header`: Custom HTTP header (can be specified multiple times for multiple headers).
- `-cookie`: Convenience flag for passing cookie strings directly.

```bash
# Scan behind authentication using session cookies
siphon -domain example.com -o results/ -cookie "idToken=...; accessToken=..."

# Scan using a JWT Bearer token
siphon -domain example.com -o results/ -H "Authorization: Bearer eyJhbGci..."

# Combining multiple headers
siphon -domain example.com -o results/ -H "Authorization: Bearer eyJhbGci..." -H "X-Client-ID: 12345"
```

## Advanced Flags
- `-scan-all-js`: Scan all JS files including known third-party libraries (default filters vendor libs).
- `-skip-live-check`: Bypass the HTTPX live host check (uses inputs directly).
- `-skip-url-collection`: Bypass passive/active URL gathering stages and use cached URL files.
- `-skip-download`: Stop after JS extraction without downloading or scanning.
- `-path`: Filter JS URLs by specific path prefix (e.g. `/admin/`).
- `-insecure`: Disable TLS certificate verification (useful for internal corporate proxies).
- `-file`: Path to a previously generated report file (TXT or JSON) for direct AI analysis.
- `-ai`: Enable AI analysis automatically without interactive prompts.
