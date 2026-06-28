# Stdout Parsing

If you prefer to pipe Siphon's output into other Unix tools (like `grep`, `awk`, or `sed`), you can use the `-silent` flag.

## Silent Mode
```bash
siphon -url https://target.com -silent | grep "CRITICAL" | awk '{print $3}'
```

This will strip the UI banner and progress bars, outputting only raw text findings.
