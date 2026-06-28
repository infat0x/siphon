# Logging System (`core/log.go`)

The `log.go` module provides a thread-safe, file-backed debugging and execution logger for Siphon.

## Overview

Because Siphon runs up to 15 different scanning engines concurrently using dozens of Goroutines, outputting debug information directly to `stdout` would result in a chaotic, unreadable terminal.

To solve this, Siphon splits its output:
- **Terminal (UI)**: Only clean, minimal progress bars and summary statistics are shown.
- **Log File**: All verbose debug information, errors, and external tool outputs are written to `debug.log`.

> [!NOTE]
> The logger is strictly guarded by `sync.Mutex` to prevent file corruption when hundreds of threads attempt to write errors simultaneously.

## Initialization

The logger must be initialized at the start of the `main()` function, creating the `logs/` directory inside the user-specified output folder.

```go
func InitLogger(logDir string) error {
	logMu.Lock()
	defer logMu.Unlock()

	// Ensure directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	path := filepath.Join(logDir, "debug.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    // ...
	logFile = f
	logger = log.New(logFile, "", log.LstdFlags|log.Lshortfile)
	
	return nil
}
```

## Writing External Tool Logs

Many of Siphon's underlying scanners (like Trufflehog or Nuclei) are executed via `os/exec`. Their raw `stdout` and `stderr` can be massive.

The `WriteToolLog` function seamlessly dumps these execution buffers into dedicated `.out` files (e.g., `trufflehog.out`).

```go
func WriteToolLog(logDir, toolName, stdout, stderr string) error {
	path := filepath.Join(logDir, toolName+".out")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	
    // Dumps STDOUT and STDERR with timestamps
}
```

> [!TIP]
> Always check the `logs/` directory if Siphon reports 0 findings. If a tool like Nuclei failed to download its templates, the exact error will be silently captured in `logs/nuclei.out`.
