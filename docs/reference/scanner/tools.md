# External Tools Wrapper (`scanner/tools.go`)

The `tools.go` module acts as the orchestration layer for executing external, third-party security scanners alongside Siphon's custom scanning engine.

## Overview

Siphon is designed to be the ultimate Swiss-army knife for JavaScript reconnaissance. While its internal regex and entropy engines are incredibly powerful, it also leverages industry-standard external tools to maximize coverage.

> [!NOTE]
> `tools.go` executes these commands concurrently using `os/exec` and standardizes their disparate JSON/text outputs into Siphon's unified `core.Finding` format.

## Supported External Tools

This module contains dedicated wrapper functions for:

1. **Trufflehog** (`ScanTrufflehog`): Runs `trufflehog filesystem --json` against the downloaded JS directory to find verified credentials.
2. **Gitleaks** (`ScanGitleaks`): Runs `gitleaks detect --no-git` for additional regex coverage.
3. **Jsluice** (`ScanJsluice`): Runs BishopFox's `jsluice` to extract URLs and secrets from AST trees.
4. **Nuclei** (`ScanNuclei`): Runs ProjectDiscovery's `nuclei` against the live JS URLs using the `exposure` and `token` tags.
5. **Git-Dumper** (`CheckGitExposure`): Checks if `/.git/config` is exposed on the root domain and automatically dumps the repository if vulnerable.
6. **Cariddi** / **Subjs** / **JSLeak** / **Mantra**: Assorted single-purpose JS recon tools.

## Execution and Error Handling

`tools.go` implements a robust `runCmd` wrapper with strict timeouts (usually 5 to 10 minutes) and error-catching mechanisms.

```go
type ToolResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Failed   bool
	FailMsg  string
}
```

If an external tool crashes, panics, or hangs, Siphon kills the process, logs the failure to a dedicated tool log file in the `secrets/raw/` directory, and continues scanning without interrupting the main pipeline.

> [!TIP]
> Siphon intelligently boosts the confidence score of external tool findings if they match high-value targets (like AWS or Stripe) or if the tool marks the finding as "Verified" (e.g., Trufflehog's active verification).
