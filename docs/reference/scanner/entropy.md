# Entropy Scanner (`scanner/entropy.go`)

The `entropy.go` module utilizes Shannon Entropy calculations to detect highly randomized strings that represent cryptographic keys, passwords, or tokens, even when they don't match any known regex pattern.

## Overview

Regular expressions are great for finding known patterns (like `AKIA...` for AWS), but what about a custom API key format, or a randomly generated database password? 

The Entropy Scanner extracts every string literal from the JavaScript file, filters out common noise, and mathematically scores the remaining strings based on their randomness.

> [!NOTE]
> The Shannon Entropy calculation determines the uncertainty or randomness of the data. Normal English text has low entropy (around 2.5 - 3.5), while a securely generated 32-character API key will have high entropy (> 4.5).

## The Filtering Pipeline

If Siphon simply flagged every high-entropy string, the report would be completely unusable, filled with CSS hashes, webpack chunks, and base64 images. `entropy.go` employs a massive exclusion pipeline before calculating entropy:

1. **Length Bounds**: Strings must be between 16 and 200 characters.
2. **Hex Hashes**: Pure hex strings (`^[0-9a-fA-F]+$`) of length 32, 40, or 64 are ignored as they are usually MD5/SHA1/SHA256 hashes, not secrets.
3. **UUIDs**: Standard UUIDs are ignored as they are typically public identifiers.
4. **Repetitive Strings**: Strings like `aaaaaaaaaaaaaaaa` are discarded.
5. **Alphabets**: Strings containing exact alphabet sets (like `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=`) are ignored.
6. **Code Snippets**: If the string looks like minified JS code (containing `function`, `return`, `{}`), it's skipped.

## Contextual Scoring

If a string survives the filters and has an entropy `> 4.0`, Siphon checks the surrounding 200 characters for "sensitive context".

```go
var sensitiveContextRe = regexp.MustCompile(`(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|password|bearer|authorization|jwt|hmac)`)
```

If sensitive context is found, the confidence score of the finding is drastically increased.

> [!TIP]
> A string with an entropy of `4.8` near the word `db_pass` will be flagged as a `HIGH` severity finding, whereas the exact same string with no surrounding context might only be flagged as `LOW` severity.
