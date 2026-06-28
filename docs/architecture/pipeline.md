# Siphon Architecture & Pipeline

The Siphon workflow runs linearly, chaining multiple tools together to ensure maximum coverage while filtering out noise.

## Core Pipeline

```text
subs.txt / -domain
    → httpx (live check)
    → URL harvest (gau + katana + waybackurls + hakrawler + subjs + cariddi)
    → active <script> parsing
    → JS filter (exclude libraries)
    → concurrent download
    → secret scanning (regex + mantra + trufflehog + gitleaks + jsluice + jsleak + nuclei + cariddi)
```

## Smart Features

1. **Protocol Fallback**: Attempts `https://` first. On failure/WAF blocking, falls back to `http://` with smart evasion headers.
2. **Strict Timeout**: Fast execution with strict timeouts to prevent hanging on unresponsive servers.
3. **Entropy & Context Engines**: 
   - Uses Luhn validation for credit cards.
   - Base58 / Length validation for Bitcoin WIFs.
   - Magic Byte rejection to prevent flagging images (PNG/PDF/JPEG) as secrets.
   - Alphabet density filtering.
4. **AI Output Trimming**: An optional AI module runs on final findings to rigorously discard false positives (e.g., example API keys, dummy tokens, or terminal escape sequences).
