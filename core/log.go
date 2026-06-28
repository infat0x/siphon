package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	logFile *os.File
	logger  *log.Logger
	logMu   sync.Mutex
)

// InitLogger initializes the global debug logger to write to the specified directory.
func InitLogger(logDir string) error {
	logMu.Lock()
	defer logMu.Unlock()

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	path := filepath.Join(logDir, "debug.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	
	logFile = f
	logger = log.New(logFile, "", log.LstdFlags|log.Lshortfile)
	logger.Printf("=== Siphon-Go Debug Log Started at %s ===", time.Now().Format(time.RFC3339))
	return nil
}

// CloseLogger closes the global debug logger file handle safely.
func CloseLogger() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		logger.Printf("=== Siphon-Go Debug Log Ended at %s ===\n\n", time.Now().Format(time.RFC3339))
		logFile.Close()
		logFile = nil
	}
}

// Debug logs debug-level messages to the file. It does not print to the CLI.
func Debug(format string, v ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	if logger != nil {
		// Output with call depth 2 to capture the actual caller file/line
		logger.Output(2, fmt.Sprintf("[DEBUG] "+format, v...))
	}
}

// Info logs info-level messages to the file.
func Info(format string, v ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	if logger != nil {
		logger.Output(2, fmt.Sprintf("[INFO] "+format, v...))
	}
}

// Error logs error-level messages to the file.
func Error(format string, v ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	if logger != nil {
		logger.Output(2, fmt.Sprintf("[ERROR] "+format, v...))
	}
}

// WriteToolLog writes the complete output of an external tool to a dedicated .out file
// in the specified log directory. Creates the file if it doesn't exist, appends if it does.
// Example: WriteToolLog("/path/to/logs", "jsluice", "stdout content", "stderr content")
// produces /path/to/logs/jsluice.out with both stdout and stderr.
func WriteToolLog(logDir, toolName, stdout, stderr string) error {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	path := filepath.Join(logDir, toolName+".out")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	ts := time.Now().Format(time.RFC3339)
	fmt.Fprintf(f, "=== %s output at %s ===\n", toolName, ts)

	if stdout != "" {
		fmt.Fprintf(f, "--- STDOUT ---\n%s\n", stdout)
	}
	if stderr != "" {
		fmt.Fprintf(f, "--- STDERR ---\n%s\n", stderr)
	}

	fmt.Fprintln(f, "=== END ===")
	fmt.Fprintln(f)
	return nil
}
