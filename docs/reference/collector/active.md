# Active Scraper (`collector/active.go`)

The `active.go` module is responsible for performing active HTML scraping on live hosts to extract JavaScript references directly from the DOM.

## Overview

Unlike passive aggregation tools (like `gau` or `waybackurls`), the active scraper directly visits the targets and extracts:
- Absolute script URLs
- Relative script URLs
- Dynamically imported `.js` chunks

> [!NOTE]
> Active scraping is crucial because passive data sources often lack the latest application bundles or internal scripts that aren't indexed by Wayback Machine.

## How it works

The module relies heavily on Regular Expressions to parse the HTML body. It initiates a concurrent HTTP `GET` request to every live host and extracts the `src` attribute of `<script>` tags.

### Regex Patterns

```go
var (
	scriptRe         = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	inlineAbsoluteRe = regexp.MustCompile(`(https?://[a-zA-Z0-9.\-/_]+/[a-zA-Z0-9.\-_]+\.js(?:\?[a-zA-Z0-9=&_\.\-]+)?)`)
	inlineRelativeRe = regexp.MustCompile(`['"](/[a-zA-Z0-9.\-/_]+\.js(?:\?[a-zA-Z0-9=&_\.\-]+)?)['"]`)
)
```

> [!TIP]
> The regular expressions handle query parameters (e.g., `app.js?v=1.2.3`), ensuring that cache-busting suffixes do not prevent the URL from being extracted.

### Concurrent Scraping

To maximize speed, `ActiveHTMLScrape` processes URLs using a semaphore pattern to limit concurrency to the user-defined thread count.

```go
func ActiveHTMLScrape(liveHosts []string) []string {
	var found []string
	var mu sync.Mutex

	// Semaphore to limit concurrent HTTP requests
	sem := make(chan struct{}, core.GlobalConfig.Threads)
	var wg sync.WaitGroup

	for _, host := range liveHosts {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Execute HTTP GET...
            // Extract via parseScriptTags()...
		}(host)
	}

	wg.Wait()
	return core.Dedup(found)
}
```

> [!WARNING]
> By default, the active scraper ignores TLS certificate errors if the global `-insecure` flag is passed via the CLI, allowing it to function against corporate or self-signed targets.
