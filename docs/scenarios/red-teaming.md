# Red Teaming

During red team engagements, stealth is often required. Siphon can be tuned for low-noise operations.

## Stealth Mode
Use the `-delay` flag to introduce sleep intervals between HTTP requests.
```bash
siphon -url https://target.com -threads 1 -delay 2000
```

This prevents WAFs (Web Application Firewalls) and SOC teams from detecting the rapid JS extraction behavior.
