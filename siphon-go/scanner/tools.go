package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"siphon-go/core"
	"strings"
	"time"
)

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	return stdout.String(), err
}

func ScanTrufflehog(dlDir string) []core.Finding {
	var findings []core.Finding
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out, err := runCmd(ctx, "trufflehog", "filesystem", "--directory", dlDir, "--json", "--no-update")
	if err != nil && out == "" {
		return findings
	}

	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			findings = append(findings, core.Finding{
				Tool:  "trufflehog",
				Type:  fmt.Sprintf("%v", obj["DetectorName"]),
				URL:   fmt.Sprintf("%v", obj["SourceMetadata"]),
				File:  fmt.Sprintf("%v", obj["SourceMetadata"]),
				Match: fmt.Sprintf("%v", obj["Raw"]),
			})
		}
	}
	return findings
}

func ScanGitleaks(dlDir string) []core.Finding {
	var findings []core.Finding
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reportPath := dlDir + "/gitleaks.json"
	_, _ = runCmd(ctx, "gitleaks", "detect", "--source", dlDir, "--no-git", "--report-format", "json", "--report-path", reportPath, "--exit-code", "0", "--log-level", "warn")

	// Read and parse reportPath... (stubbed for brevity, would read the file)
	return findings
}

// Add more stubs for other tools...
