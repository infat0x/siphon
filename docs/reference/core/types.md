# Types & Data Structures (`core/types.go`)

The `types.go` file contains the primary data structures that flow through the entire Siphon pipeline. 

By defining these structures in the `core` module, both the `collector` and `scanner` packages can import and utilize them without creating circular dependencies.

## Finding Struct

The `Finding` struct is the most critical data type in Siphon. Every time any of the 15 scanning engines detects a potential secret, it must construct a `Finding` object.

```go
// Finding represents a single discovered secret or exposure.
type Finding struct {
	Tool         string `json:"tool"`
	Type         string `json:"type"`
	URL          string `json:"url"`
	File         string `json:"file"`
	Match        string `json:"match"`
	Line         string `json:"line"`
	Entropy      string `json:"entropy"`
	Context      string `json:"context,omitempty"`
	Severity     string `json:"severity,omitempty"`      // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Confidence   int    `json:"confidence,omitempty"`    // 0-100
	DecodedMatch string `json:"decoded_match,omitempty"` // Decoded value for base64/hex/url-encoded secrets
}
```

> [!NOTE]
> The `json` tags dictate how the final report is generated. Siphon outputs its findings in a highly parsable format, making it easy to integrate with custom CI/CD pipelines or vulnerability management systems.

## Global Config

The `Config` struct holds the runtime configuration passed via CLI flags. It is instantiated once as the `GlobalConfig` variable.

```go
// Config holds global flags.
type Config struct {
	Insecure bool
	Threads  int
}

var GlobalConfig Config
```

> [!WARNING]
> Because `GlobalConfig` is exported and mutable, it should only be written to *once* during `flag.Parse()` in `main.go`. Changing its values dynamically during execution could lead to race conditions.

## Execution Statistics

To provide the user with a clean summary at the end of the scan, the `Stats` struct tracks metrics like total downloaded files and total live hosts.

```go
type Stats struct {
	SingleDomain bool
	Live         int
	Urls         int
	// ... other metrics
	mu           sync.Mutex
}
```

> [!TIP]
> The `Stats` struct incorporates a `sync.Mutex`. All setter methods (e.g., `SetLive()`) lock the mutex to ensure thread-safe increments when multiple Goroutines are reporting their status simultaneously.
