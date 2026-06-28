# CLI Usage

Siphon offers a comprehensive set of command-line flags to customize your scans.

## Basic Flags
- `-l`: Path to a file containing a list of target URLs or domains.
- `-url`: Scan a single target URL.
- `-o`: Output directory for reports (default: `results/`).

## Advanced Flags
- `-skip-live-check`: Bypass the HTTPX live host check.
- `-deep-scan`: Enable aggressive AST parsing (slower but more thorough).

```bash
siphon -l targets.txt -threads 100 -deep-scan -o my_report/
```
