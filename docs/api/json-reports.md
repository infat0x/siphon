# JSON Report Schema

Siphon outputs all findings to `results/findings.json` by default.

## Schema Example
```json
{
  "timestamp": "2024-10-25T14:32:00Z",
  "target": "https://example.com",
  "findings": [
    {
      "tool": "regex",
      "type": "AWS Access Key",
      "file": "/app.1234.js",
      "line": 452,
      "match": "AKIAIOSFODNN7EXAMPLE",
      "severity": "CRITICAL",
      "confidence": 95,
      "entropy": "4.8"
    }
  ]
}
```

This format is easily parsed by `jq` or imported into Elasticsearch.
