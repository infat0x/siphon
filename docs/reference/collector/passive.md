# Passive Discovery (`collector/passive.go`)

The `passive.go` module orchestrates external, well-known passive reconnaissance tools to harvest a massive list of historical and current URLs without heavily probing the target directly.

## Overview

Passive reconnaissance leverages third-party datasets (like the Wayback Machine, CommonCrawl, and AlienVault OTX) to find URLs that belong to a target domain.

Siphon utilizes Go's `os/exec` package to seamlessly shell out to four primary tools:
- **Gau** (GetAllUrls)
- **Katana**
- **Waybackurls**
- **Hakrawler**

> [!NOTE]
> All external tools are executed concurrently with strict context timeouts to ensure the pipeline doesn't hang indefinitely on unresponsive third-party APIs.

## Tool Execution Wrapper

To unify the execution of these disparite CLI tools, `passive.go` implements a standard wrapper function `runCmdLinesStdin`.

This wrapper:
1. Pipes the list of domains into the tool via `stdin`.
2. Captures the `stdout` buffer.
3. Cleans up terminal escape sequences and extracts the raw HTTP/HTTPS URLs.

```go
func runCmdLinesStdin(ctx context.Context, input []string, name string, args ...string) []string {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stdin = strings.NewReader(strings.Join(input, "\n") + "\n")
	
    // ... Executes command and extracts URLs via string parsing
}
```

## Tool Configurations

Each tool is highly tuned to maximize extraction speed while explicitly rejecting non-text/binary assets that slow down the pipeline.

### Gau

```go
runCmdLinesStdin(ctx, bareHosts, "gau", 
    "--providers", "wayback,commoncrawl,otx,urlscan", 
    "--threads", "20", 
    "--blacklist", "ttf,woff,woff2,eot,svg,png,jpg,jpeg,gif,ico,css,pdf,mp4,mp3,zip")
```

### Katana

```go
args := []string{"-jc", "-d", "3", "-c", "50", "-silent", "-nc", 
    "-ef", "css,png,jpg,jpeg,gif,ico,svg,ttf,woff,woff2,eot,pdf,mp4,mp3,zip"}
```

> [!TIP]
> If Siphon is run with the `-insecure` flag, it automatically passes the `-insecure` argument down to Katana and Hakrawler to ensure they function properly behind corporate proxies or against targets with broken SSL configurations.
