# Inline Assignments (`scanner/inline_scanner.go`)

The `inline_scanner.go` module parses JavaScript syntax to find explicit variable assignments where the developer has hardcoded a secret into a variable or object property.

## Overview

While the Entropy Scanner looks at the data itself, the Inline Scanner looks at the *names* of the variables holding the data. 

If a developer writes `const stripe_secret = "rk_test_12345"`, the inline scanner will detect it specifically because the variable name `stripe_secret` indicates a high-value target.

> [!NOTE]
> This module utilizes 6 different Regular Expressions to parse different styles of JavaScript assignment, ensuring it catches secrets regardless of coding style.

## Assignment Patterns

The scanner checks for:

1. **JS Variable Assignment**: `let apiKey = "..."` or `window.token = "..."`
2. **Object Properties**: `{ apiKey: "..." }`
3. **Bracket Notation**: `config["apiKey"] = "..."`
4. **Generic Assignment**: `auth_token = "..."`
5. **Template Literals**: `` key = `...` ``

## Intelligent Scoring

Siphon maintains a massive list of variable names categorized by threat level.

```go
// Very high confidence variable names
var criticalVarNameRe = regexp.MustCompile(`(?i)^(password|passwd|pwd|secret_key|private_key|api_key|access_token|db_password)$`)

// Non-secret variable name patterns (false positive reduction)
var nonSecretVarRe = regexp.MustCompile(`(?i)(version|name|label|title|description|css|style|class|width|height|color|padding)$`)
```

When an assignment is found, the `scoreInlineAssignment` function calculates a confidence score based on:
1. Is the variable name in the `critical` list? (+50 points, HIGH severity)
2. Does the assigned value have high entropy? (+20 points)
3. Does the assigned value start with a known prefix like `sk_live_`? (+25 points, CRITICAL severity)

> [!WARNING]
> Siphon aggressively discards assignments to variables like `width`, `color`, or `className`, completely eliminating the false positives that plague naive regex scanners.
