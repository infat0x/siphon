# HTTPX Probe (`scanner/httpx.go`)

The `httpx.go` module is a lightweight wrapper around ProjectDiscovery's `httpx` tool, used to filter a massive list of subdomains down to only those that are actively hosting web services.

## Overview

When performing reconnaissance on a large target, you might start with 10,000 subdomains. However, many of these might be dead, point to internal IP addresses, or refuse connections. Running the full JS extraction pipeline against dead hosts wastes massive amounts of time and network bandwidth.

Siphon uses `httpx` as a blazing-fast pre-flight check to verify which hosts return a valid HTTP/HTTPS response.

> [!NOTE]
> The `httpx` step can be skipped entirely by using the `-skip-live-check` flag via the Siphon CLI, which assumes all input domains are already alive.

## Execution Parameters

Siphon shells out to `httpx` using `os/exec` with highly optimized flags.

```go
args := []string{
    "-l", subsFile,
    "-threads", fmt.Sprintf("%d", core.GlobalConfig.Threads),
    "-silent",
    "-no-color",
    "-o", liveFile,
    "-timeout", "10",
    "-retries", "2",
    "-follow-redirects",
    "-status-code",
    "-title",
    "-tech-detect",
    "-web-server",
}
```

> [!TIP]
> If the `-insecure` flag is passed to Siphon, the `-no-verify-ssl` flag is automatically appended to the `httpx` arguments, allowing it to connect to hosts with expired or self-signed certificates.
