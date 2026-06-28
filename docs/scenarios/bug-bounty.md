# Bug Bounty Hunting

Siphon was built specifically with Bug Bounty hunters in mind.

## Workflow
1. Enumerate all subdomains of your target.
2. Pipe the subdomains directly into Siphon:
```bash
cat subdomains.txt | siphon -threads 200
```
3. Review the `critical_findings.txt` report.

> [!TIP]
> Always enable the AI integration (`GEMINI_API_KEY`) when doing bug bounties to ensure you aren't wasting time manually verifying test credentials.
