# Rate Limiting & Evasion

When scanning large targets, you may encounter HTTP 429 (Too Many Requests) errors.

## Handling 429s
Siphon has built-in exponential backoff. If it receives a 429, the worker thread will pause, double its delay, and retry the download up to 3 times.

## WAF Evasion
- Use `-random-agent` to rotate User-Agent strings.
- Pass custom headers via `-H "X-Forwarded-For: 127.0.0.1"` to bypass basic IP blocks.
