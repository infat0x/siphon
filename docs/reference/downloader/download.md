# Async Downloader (`downloader/download.go`)

The `download.go` module handles the concurrent acquisition of JavaScript files from the internet, employing advanced evasion and speed optimization techniques.

## Overview

Downloading hundreds of thousands of files sequentially would take hours. Siphon utilizes a highly tuned Goroutine pool and `http.Transport` to execute thousands of downloads in parallel, saturating the user's network bandwidth for maximum speed.

> [!NOTE]
> The downloader automatically handles deduplication at the content level. If two different URLs serve the exact same JavaScript file (by comparing SHA256 hashes), Siphon immediately discards the duplicate to save disk space and scanning time.

## Concurrency Optimization

The HTTP client is specifically configured for high-throughput scanning. The `MaxIdleConnsPerHost` is massively inflated to prevent connection bottlenecks when downloading thousands of chunks from a single CDN or root domain.

```go
transport := &http.Transport{
    TLSClientConfig:     &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
    MaxIdleConns:        10000,
    MaxIdleConnsPerHost: 1000,
    MaxConnsPerHost:     0, // 0 means no limit
    IdleConnTimeout:     30 * time.Second,
    ForceAttemptHTTP2:   true,
}
```

> [!TIP]
> The worker pool is dynamically sized based on the `-t` (threads) CLI flag.

## WAF / Bot Evasion

Web Application Firewalls (WAFs) like Cloudflare or Akamai often block automated scrapers. Siphon mitigates this by injecting realistic browser headers into every request.

```go
req.Header.Set("User-Agent", userAgents[time.Now().UnixNano()%int64(len(userAgents))])
req.Header.Set("Accept", "*/*")
req.Header.Set("Accept-Language", "en-US,en;q=0.9")
req.Header.Set("Sec-Fetch-Dest", "script")
req.Header.Set("Sec-Fetch-Mode", "no-cors")
req.Header.Set("Sec-Fetch-Site", "same-origin")
req.Header.Set("Referer", urlStr)
```

## Protocol Fallback

If a target server refuses a connection over `HTTPS` due to a broken certificate or misconfiguration, the downloader automatically falls back and attempts the download over plain `HTTP`.

```go
if err != nil || finalPath == "" {
    fallbackURL := ""
    if strings.HasPrefix(urlStr, "https://") {
        fallbackURL = "http://" + strings.TrimPrefix(urlStr, "https://")
    }
    // ... attempts download with fallbackURL
}
```
