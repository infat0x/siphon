# Development Guide

Want to contribute to Siphon? We welcome PRs!

## Project Structure
- `cmd/`: CLI entrypoints
- `core/`: Global types, UI, and logging
- `collector/`: Subdomain and URL enumeration
- `downloader/`: Concurrent HTTP clients
- `scanner/`: Regex, Entropy, and External Tool orchestrators

## Building locally
```bash
go mod tidy
go build
```

## Adding a New Scanner
To add a new external tool, create a new function in `scanner/tools.go` and implement the `ToolResult` interface. Then, add it to the execution pipeline in `main.go`.
