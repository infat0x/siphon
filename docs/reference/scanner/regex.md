# Core Regex Scanner (`scanner/regex.go`)

The `regex.go` module is the primary scanning engine of Siphon. It executes the hundreds of patterns defined in `patterns.go` concurrently against all downloaded JavaScript files.

## Overview

This module is highly optimized for speed. It pre-compiles all regular expressions into a `map[string]*regexp.Regexp` once at runtime, rather than compiling them per file. It utilizes a `sync.WaitGroup` and a semaphore channel to limit concurrency and prevent memory exhaustion when scanning gigabytes of JavaScript.

> [!NOTE]
> Siphon dynamically calculates a confidence score for every regex match. Unlike traditional scanners that simply flag a match as "Found", Siphon analyzes the Shannon Entropy and the surrounding context to determine if it is a true positive.

## Validation and Verification

Siphon doesn't just blindly trust regex matches. It implements specific mathematical validations for certain types of secrets:

```go
// Validate Credit Card matches with Luhn algorithm
if name == "Credit Card (PAN)" && !LuhnCheck(snippet) {
    continue
}

// Validate Bitcoin WIF matches with Base58 charset & length check
if name == "Bitcoin WIF Private Key" && !IsValidBitcoinWIF(snippet) {
    continue
}
```

## Confidence Scoring Engine

The `calculateRegexConfidence` function evaluates the quality of the finding:

1. **Base Score**: Starts at 40%.
2. **Pattern Quality**: Known, highly reliable patterns (like AWS `AKIA` or Stripe `sk_live`) get an immediate +30% boost.
3. **Entropy Boost**: If the matched string has an entropy `> 4.0` (+10%) or `> 5.0` (+20%).
4. **Context Proximity**: If the scanner finds keywords like `password` or `api_key` within 100 characters of the match (+10%).

> [!WARNING]
> Findings with low confidence or those that match the `FalsePositiveRe` are silently dropped to ensure the final report is actionable.
