# Core System (`main.go`)

The `main.go` file is the entry point of the Siphon application. It acts as the central orchestrator for the entire JavaScript reconnaissance and secret scanning pipeline.

## Overview

Siphon is designed to be a hyper-concurrent offensive security engine. The `main.go` file handles the following core responsibilities:
1. **Command Line Flag Parsing**: Accepts parameters like `-domain`, `-url`, `-s` (subdomains), and operational flags like `-insecure`.
2. **Environment & Dependency Checks**: Ensures tools like `httpx`, `katana`, `nuclei` are installed and API keys (like OpenAI) are available.
3. **Execution Pipeline**: Sequentially triggers the live host detection, URL collection, JS extraction, downloading, and finally secret scanning.

> [!NOTE]
> Siphon aggregates the findings from 14+ different scanning engines and deduplicates them using a `type|match` signature before generating the final report.

## Core Implementation

### Dependency Pre-flight Check

Before running any scans, `main.go` verifies that all required external tools are available in the system's `$PATH`.

```go
// requiredTools lists all external CLI tools that siphon-go depends on.
var requiredTools = []string{
	"katana", "gau", "hakrawler", "waybackurls", "subjs",
	"nuclei", "trufflehog", "gitleaks", "jsluice", "cariddi",
	"httpx", "mantra",
}
```

> [!WARNING]
> If any tool is missing, Siphon will issue a warning and ask if you want to continue. Continuing without essential tools like `katana` or `trufflehog` will severely limit the scanner's capabilities.

### Pipeline Orchestration

The pipeline heavily relies on Go's concurrency model (`Goroutines` and `sync.WaitGroup`) to execute tools simultaneously. For example, URL collection happens via multiple tools at once:

```go
var mu sync.Mutex
var wg sync.WaitGroup

tools := []struct {
    name string
    fn   func([]string) []string
}{
    {"Gau", collector.RunGau},
    {"Katana", collector.RunKatana},
    {"Waybackurls", collector.RunWaybackurls},
    {"Hakrawler", collector.RunHakrawler},
}

for _, t := range tools {
    wg.Add(1)
    go func(name string, tool func([]string) []string) {
        defer wg.Done()
        res := tool(live)
        
        mu.Lock()
        allUrls = append(allUrls, res...)
        mu.Unlock()
    }(t.name, t.fn)
}
```

> [!TIP]
> The use of `sync.Mutex` ensures that the shared `allUrls` slice is safely updated from multiple Goroutines without causing race conditions.

### AI Integration

After the traditional scanning pipeline completes, `main.go` prompts the user to pass the findings to the AI engine for intelligent false-positive reduction.

```go
// Interactive AI Prompt
core.PrintWarning("WARNING: Analyzing the report with AI will send the found secrets to AI servers!")
fmt.Printf("  [?] Do you still want to analyze with AI? (y/N): ")
```
