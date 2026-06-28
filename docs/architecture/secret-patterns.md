# Secret Patterns

Siphon uses over 500 hand-crafted Regular Expressions.

## Structure
Each pattern consists of:
- **Name**: e.g., "AWS Access Key ID"
- **Regex**: e.g., `AKIA[0-9A-Z]{16}`
- **Severity**: Critical, High, Medium, Low
- **Validation**: (Optional) Functions to validatechecksums (like Luhn for Credit Cards).

## False Positive Engine
The `FalsePositiveRe` regex is run against every match. If it matches, the secret is discarded. This eliminates 90% of noise from CSS and minified variable names.
