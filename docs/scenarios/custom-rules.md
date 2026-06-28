# Custom Rules

Siphon allows you to define your own custom regular expressions without recompiling the binary.

## Rule File Syntax
Create a `rules.json` file:
```json
[
  {
    "id": "custom_internal_api",
    "description": "Company Internal API Token",
    "regex": "COMP-[A-Z0-9]{32}",
    "severity": "CRITICAL"
  }
]
```

Run Siphon with the custom rules:
```bash
siphon -rules rules.json -url https://target.com
```
