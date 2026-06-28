# Base64/Encoded Scanner (`scanner/base64_scanner.go`)

The `base64_scanner.go` module implements a multi-stage decoding pipeline that hunts for obfuscated or heavily encoded secrets hidden within JavaScript files.

## Overview

Modern web applications frequently embed configuration blocks or payloads that are Base64, Hex, or URL-encoded. While a regular expression might miss a hardcoded Stripe key if it is Base64 encoded, the `base64_scanner.go` module intercepts the encoded string, decodes it in memory, and re-scans the plain text for secrets.

> [!NOTE]
> This scanner handles multiple encoding formats simultaneously: standard Base64, URL-safe Base64, Hex-encoding (e.g., `0x` or `\x`), URL-encoding (`%20`), and Unicode escapes (`\uXXXX`).

## Decoding Pipeline

For every JavaScript file downloaded, the scanner runs multiple regex patterns to find strings that *look* like encoded data (e.g., strings containing only `A-Z`, `a-z`, `0-9`, `+`, `/` that are at least 20 characters long).

```go
var base64Re = regexp.MustCompile(`(?:"|'|=\s*|:\s*)([A-Za-z0-9+/]{20,}={0,2})(?:"|'|\s|;|,|$)`)
var hexEncodedRe = regexp.MustCompile(`(?:0x|\\x)([0-9a-fA-F]{20,})`)
```

When a match is found, the scanner attempts to decode it:

```go
decoded, err = base64.StdEncoding.DecodeString(padBase64(encoded))
// If successful, check if decoded content is valid UTF-8 text
if !utf8.Valid(decoded) {
    continue
}
```

## Secondary Secret Detection

Once a string is successfully decoded into valid UTF-8 text, Siphon runs a secondary, highly focused set of regular expressions against the *decoded* string.

```go
criticalPatterns := []string{
    `AIza[0-9A-Za-z\-_]{35}`,          // Google API
    `AKIA[0-9A-Z]{16}`,                // AWS Access Key
    `sk_live_[0-9a-zA-Z]{24}`,         // Stripe Live
    `eyJ[a-zA-Z0-9_-]+\.eyJ...`,       // JWT
}
```

> [!WARNING]
> The scanner also checks the **Shannon Entropy** of the decoded string. If the decoded string doesn't match a specific regex but has an entropy `> 4.5`, Siphon will flag it as a `High-Entropy Decoded` secret if the surrounding code context contains sensitive keywords (like `password` or `secret`).
