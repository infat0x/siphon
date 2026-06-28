# Getting Started

Welcome to Siphon v7. This guide will help you run your first JavaScript reconnaissance scan.

## Prerequisites
- Go 1.21+
- API keys for Gemini (optional but recommended for AI filtering)

## Quick Run
Run the tool against a single URL:
```bash
siphon -url https://example.com/app.js
```
Run against a list of subdomains:
```bash
siphon -l subdomains.txt
```

> [!TIP]
> Siphon automatically discovers, downloads, and scans all JavaScript files referenced by the provided URLs.
