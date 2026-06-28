# Config Leak Scanner (`scanner/config_leak_scanner.go`)

The `config_leak_scanner.go` module is a two-part engine designed to find exposed configuration files on live servers and extract hardcoded configuration blocks embedded directly within JavaScript source code.

## Part 1: Active Configuration Probing

While Siphon is primarily a JavaScript scanner, developers frequently leave `.env` files or backup configurations exposed on the root of the domain alongside their JS bundles. 

Siphon leverages its `httpx` live host list to aggressively probe for over 50 highly sensitive file paths and prefixes.

> [!NOTE]
> The prober uses a rapid HTTP `GET` request pool to check paths like `/.env`, `/.git/config`, `/config.json`, `/wp-config.php`, and `/.aws/credentials`.

### Intelligent File Parsing

Unlike dumb fuzzers that just check for a `200 OK` status, Siphon downloads the file and validates its structure to ensure it's not a custom 404 HTML page.

```go
// isActualConfig checks if content looks like a real config file (not an error page)
func isActualConfig(content, path string) bool {
	// .env files have KEY=VALUE
	if strings.Contains(path, ".env") {
		return envLineRe.MatchString(content)
	}
	// JSON config
	if strings.HasSuffix(path, ".json") {
		return strings.HasPrefix(strings.TrimSpace(content), "{")
	}
    // ...
}
```

If an exposed `.env` file is found, Siphon automatically parses the `KEY=VALUE` pairs, checking the entropy of the values to flag high-risk secrets.

## Part 2: Embedded Configuration Extraction

Modern frontend frameworks (like React, Next.js, and Nuxt) often embed the application's configuration state directly into the HTML or JavaScript so the client can boot quickly without additional API calls.

Siphon scans the downloaded JS files for common embedded configuration patterns:

### Webpack `process.env` Injection

```go
processEnvRe := regexp.MustCompile(`(?i)process\.env\.([A-Z_][A-Z0-9_]*)\s*...\s*['"]([^'"]{4,100})['"]`)
```

### Next.js / Global State Injection

```go
configVarRe := regexp.MustCompile(`(?i)(?:window\.__(?:CONFIG|INITIAL_STATE|APP_DATA|NEXT_DATA|NUXT__)__)\s*=\s*(\{[^;]{20,1000}\})`)
```

> [!TIP]
> When Siphon finds a `window.__NEXT_DATA__` block, it extracts the JSON object and recursively scans the inner values for API keys and tokens, bypassing the need for a headless browser.
