# Brute Forcer (`collector/brute.go`)

The `brute.go` module implements an intelligent brute-forcing mechanism specifically targeting common, high-value JavaScript file paths.

## Overview

Often, the most critical JavaScript files (like internal configuration or unlinked bundles) are not explicitly referenced in the HTML DOM and are not present in passive archives. The Brute Forcer solves this by actively guessing and requesting common JS file locations.

> [!NOTE]
> This module utilizes a predefined list of paths, ranging from standard frontend entry points to hidden framework configurations and API manifests.

## Target Paths

The `CommonJSPaths` slice contains highly curated targets derived from common modern web frameworks (React, Vue, Angular) and legacy conventions.

```go
var CommonJSPaths = []string{
	// Core config & generic roots
	"/app.js", "/main.js", "/index.js", "/config.js", "/env.js",
	"/settings.js", "/constants.js", "/api.js", "/utils.js",

	// Hidden / framework config variants
	"/env.production.js", "/config.production.js",
	"/static/js/main.js", "/assets/js/app.js", "/dist/app.js",

	// Framework manifests
	"/asset-manifest.json", "/precache-manifest.js",

	// Specific high-value endpoints
	"/js/app.js", "/js/main.js", "/js/config.js", "/js/api.js",
	"/admin/app.js", "/admin/js/app.js", "/admin/js/config.js",
	"/admin/main.js", "/api/v1/app.js", "/api/v2/app.js",
}
```

## Brute-Forcing Logic

The `BruteJSPaths` function launches a high-speed, concurrent scan across all live hosts against the predefined paths.

> [!TIP]
> The scanner intelligently checks the `Content-Type` of the response. If the response is HTML rather than JavaScript, it assumes a soft-404 or a catch-all route, but it *still* parses the returned HTML for any embedded script tags!

### Path Filtering

When the user specifies a `-path` flag (e.g., `/admin/`), the brute forcer automatically roots its guesses within that specific directory context.

```go
for _, path := range CommonJSPaths {
    fullPath := pathFilter + path
    
    // Example: if pathFilter is "/admin", fullPath becomes "/admin/app.js"
}
```

### Execution Speed

Because brute-forcing generates a high volume of requests, the HTTP transport is heavily optimized with an increased `MaxIdleConns` and a strict timeout.

```go
transport := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
    MaxIdleConns:    200,
}
client := &http.Client{
    Transport: transport,
    Timeout:   8 * time.Second,
}
```
