package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)

// ToolResult captures the full output and status of an external tool execution.
type ToolResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Failed   bool   // true if tool exited non-zero or stderr contains fatal errors
	FailMsg  string // human-readable failure reason
}

// fatalErrorPatterns are stderr substrings that indicate a tool has failed fatally.
var fatalErrorPatterns = []string{"panic", "fatal", "FATAL", "PANIC"}

func runCmd(ctx context.Context, name string, args ...string) ToolResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmdArgs := append([]string{"/c", name}, args...)
		cmd = exec.CommandContext(ctx, "cmd", cmdArgs...)
	} else {
		cmd = exec.CommandContext(ctx, name, args...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := ToolResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	// Determine exit code
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	// Check for fatal errors in stderr
	stderrLower := strings.ToLower(result.Stderr)
	for _, pattern := range fatalErrorPatterns {
		if strings.Contains(stderrLower, strings.ToLower(pattern)) {
			result.Failed = true
			result.FailMsg = fmt.Sprintf("stderr contains '%s'", pattern)
			break
		}
	}

	// Non-zero exit also means failure (unless already marked)
	if result.ExitCode != 0 && !result.Failed {
		result.Failed = true
		result.FailMsg = fmt.Sprintf("exit code %d", result.ExitCode)
	}

	return result
}

// isDirEmpty checks if a directory exists and contains at least one file.
func isDirEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if !e.IsDir() {
			return false
		}
	}
	return true
}

// isDlMapEmpty returns true if dlMap has no real downloaded files.
func isDlMapEmpty(dlMap map[string]string) bool {
	for _, p := range dlMap {
		if p != "" && p != "/dev/null" {
			return false
		}
	}
	return true
}

func ScanTrufflehog(dlDir string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding

	// Empty input check: skip if no downloaded files exist
	if isDirEmpty(dlDir) {
		core.Info("Trufflehog skipped — no files in %s", dlDir)
		return findings
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result := runCmd(ctx, "trufflehog", "filesystem", dlDir, "--json", "--no-verification", "--no-update")
	os.WriteFile(filepath.Join(rawDir, "trufflehog.json"), []byte(result.Stdout), 0644)

	// Write segregated tool log
	core.WriteToolLog(logDir, "trufflehog", result.Stdout, result.Stderr)

	// If tool failed fatally, don't report 0 findings — report failure
	if result.Failed {
		core.Error("Trufflehog failed: %s", result.FailMsg)
		return findings
	}

	for _, line := range strings.Split(result.Stdout, "\n") {
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			
			// Trufflehog v3 JSON nested structure parsing
			filePath := ""
			if sm, ok := obj["SourceMetadata"].(map[string]interface{}); ok {
				if data, ok := sm["Data"].(map[string]interface{}); ok {
					if fs, ok := data["Filesystem"].(map[string]interface{}); ok {
						if f, ok := fs["file"].(string); ok {
							filePath = f
						}
					}
				}
			}

			// Fallback if not found
			if filePath == "" {
				filePath = fmt.Sprintf("%v", obj["SourceMetadata"])
			}

			// Determine if verified
			verified := false
			if v, ok := obj["Verified"].(bool); ok {
				verified = v
			}

			severity := "HIGH"
			confidence := 70
			if verified {
				severity = "CRITICAL"
				confidence = 95
			}

			detectorName := fmt.Sprintf("%v", obj["DetectorName"])
			rawMatch := fmt.Sprintf("%v", obj["Raw"])

			// Boost confidence for known high-value detectors
			highValueDetectors := []string{"AWS", "GCP", "Azure", "Stripe", "GitHub", "Slack", "Twilio", "SendGrid"}
			for _, hvd := range highValueDetectors {
				if strings.Contains(detectorName, hvd) {
					confidence += 10
					break
				}
			}
			if confidence > 100 {
				confidence = 100
			}

			findings = append(findings, core.Finding{
				Tool:       "trufflehog",
				Type:       detectorName,
				URL:        filePath, // Will be mapped to original URL in main.go
				File:       filePath,
				Match:      rawMatch,
				Severity:   severity,
				Confidence: confidence,
			})
		}
	}
	return findings
}

func ScanGitleaks(dlDir string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding

	// Empty input check: skip if no downloaded files exist
	if isDirEmpty(dlDir) {
		core.Info("Gitleaks skipped — no files in %s", dlDir)
		return findings
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reportPath := filepath.Join(rawDir, "gitleaks.json")
	result := runCmd(ctx, "gitleaks", "detect", "--source", dlDir, "--no-git", "--report-format", "json", "--report-path", reportPath, "--exit-code", "0", "--log-level", "warn")

	// Write segregated tool log
	core.WriteToolLog(logDir, "gitleaks", result.Stdout, result.Stderr)

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return findings
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err == nil {
		for _, item := range results {
			ruleID := fmt.Sprintf("%v", item["RuleID"])
			match := fmt.Sprintf("%v", item["Match"])
			secret := fmt.Sprintf("%v", item["Secret"])
			entropy := core.ShannonEntropy(secret)

			// Severity based on rule type
			severity := "MEDIUM"
			confidence := 60

			highSeverityRules := []string{"private-key", "aws", "gcp", "azure", "stripe", "github", "gitlab", "slack", "twilio", "sendgrid", "database", "postgres", "mysql", "mongodb", "redis"}
			for _, hsr := range highSeverityRules {
				if strings.Contains(strings.ToLower(ruleID), hsr) {
					severity = "HIGH"
					confidence = 75
					break
				}
			}

			if entropy > 4.5 {
				confidence += 10
			}
			if confidence > 100 {
				confidence = 100
			}

			findings = append(findings, core.Finding{
				Tool:       "gitleaks",
				Type:       ruleID,
				File:       fmt.Sprintf("%v", item["File"]),
				Match:      match,
				Line:       fmt.Sprintf("%v", item["StartLine"]),
				Entropy:    fmt.Sprintf("%.2f", entropy),
				Severity:   severity,
				Confidence: confidence,
			})
		}
	}
	return findings
}

func ScanJsluice(dlMap map[string]string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 50)

	for url, path := range dlMap {
		if path == "" || path == "/dev/null" {
			continue
		}
		wg.Add(1)
		go func(urlStr, fpath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			resSec := runCmd(ctx, "jsluice", "secrets", fpath)
			resUrl := runCmd(ctx, "jsluice", "urls", fpath)
			cancel()

			// Write segregated tool log (append per-file results)
			core.WriteToolLog(logDir, "jsluice", resSec.Stdout+resUrl.Stdout, resSec.Stderr+resUrl.Stderr)

			outSec := resSec.Stdout
			outUrl := resUrl.Stdout

			var localFindings []core.Finding
			
			// Parse secrets
			for _, line := range strings.Split(outSec, "\n") {
				if line == "" {
					continue
				}
				var obj map[string]interface{}
				if err := json.Unmarshal([]byte(line), &obj); err == nil {
					dataMap, _ := obj["data"].(map[string]interface{})
					matchStr := fmt.Sprintf("%v", dataMap["match"])

					severity := "MEDIUM"
					confidence := 55
					kind := fmt.Sprintf("%v", obj["kind"])

					// Boost for specific kinds
					if strings.Contains(strings.ToLower(kind), "api") || strings.Contains(strings.ToLower(kind), "secret") || strings.Contains(strings.ToLower(kind), "token") {
						severity = "HIGH"
						confidence = 70
					}

					entropy := core.ShannonEntropy(matchStr)
					if entropy > 4.0 {
						confidence += 10
					}
					if confidence > 100 {
						confidence = 100
					}

					localFindings = append(localFindings, core.Finding{
						Tool:       "jsluice",
						Type:       kind,
						URL:        urlStr,
						File:       fpath,
						Match:      matchStr,
						Line:       fmt.Sprintf("%v", obj["line"]),
						Entropy:    fmt.Sprintf("%.2f", entropy),
						Severity:   severity,
						Confidence: confidence,
					})
				}
			}

			// Parse urls
			for _, line := range strings.Split(outUrl, "\n") {
				if line == "" {
					continue
				}
				var obj map[string]interface{}
				if err := json.Unmarshal([]byte(line), &obj); err == nil {
					localFindings = append(localFindings, core.Finding{
						Tool:       "jsluice",
						Type:       "endpoint",
						URL:        urlStr,
						File:       fpath,
						Match:      fmt.Sprintf("%v", obj["url"]),
						Severity:   "INFO",
						Confidence: 30,
					})
				}
			}

			if len(localFindings) > 0 {
				mu.Lock()
				findings = append(findings, localFindings...)
				mu.Unlock()
			}
		}(url, path)
	}
	wg.Wait()
	return findings
}

func ScanNuclei(jsUrls []string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding
	if len(jsUrls) == 0 {
		return findings
	}

	urlListPath := filepath.Join(rawDir, "_nuclei_urls.txt")
	os.WriteFile(urlListPath, []byte(strings.Join(jsUrls, "\n")+"\n"), 0644)
	reportPath := filepath.Join(rawDir, "nuclei_findings.json")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Extended tags for better coverage
	result := runCmd(ctx, "nuclei", "-l", urlListPath,
		"-tags", "exposure,token,javascript,config,secret,apikey,credential,leak,misconfiguration",
		"-silent", "-no-color", "-jsonl", "-o", reportPath,
		"-rate-limit", "50", "-concurrency", "20", "-timeout", "10",
		"-no-update-templates")

	// Write segregated tool log
	core.WriteToolLog(logDir, "nuclei", result.Stdout, result.Stderr)

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return findings
	}

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			info, _ := obj["info"].(map[string]interface{})
			nucleiSeverity := strings.ToUpper(fmt.Sprintf("%v", info["severity"]))

			// Map nuclei severity to our severity
			severity := "MEDIUM"
			confidence := 60
			switch nucleiSeverity {
			case "CRITICAL":
				severity = "CRITICAL"
				confidence = 90
			case "HIGH":
				severity = "HIGH"
				confidence = 80
			case "MEDIUM":
				severity = "MEDIUM"
				confidence = 65
			case "LOW":
				severity = "LOW"
				confidence = 45
			case "INFO":
				severity = "INFO"
				confidence = 30
			}

			findings = append(findings, core.Finding{
				Tool:       "nuclei",
				Type:       fmt.Sprintf("%v", obj["template-id"]),
				URL:        fmt.Sprintf("%v", obj["matched-at"]),
				Match:      fmt.Sprintf("%v", obj["extracted-results"]),
				Context:    fmt.Sprintf("severity=%v", info["severity"]),
				Severity:   severity,
				Confidence: confidence,
			})
		}
	}
	return findings
}

func ScanJsleak(dlMap map[string]string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding
	var rawLines []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 50)

	for url, path := range dlMap {
		if path == "" || path == "/dev/null" {
			continue
		}
		wg.Add(1)
		go func(urlStr, fpath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// jsleak reads from stdin, not -f flag
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.CommandContext(ctx, "cmd", "/c", "type", fpath, "|", "jsleak", "-s")
			} else {
				cmd = exec.CommandContext(ctx, "sh", "-c", "cat "+fpath+" | jsleak -s")
			}

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			_ = cmd.Run()

			// Write segregated tool log
			core.WriteToolLog(logDir, "jsleak", stdout.String(), stderr.String())

			out := stdout.String()

			var localFindings []core.Finding
			var localRaw []string
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if len(line) < 10 {
					continue
				}
				localRaw = append(localRaw, urlStr+": "+line)

				entropy := core.ShannonEntropy(line)
				severity := "LOW"
				confidence := 40

				if entropy > 4.0 {
					severity = "MEDIUM"
					confidence = 55
				}
				if entropy > 5.0 {
					severity = "HIGH"
					confidence = 70
				}

				localFindings = append(localFindings, core.Finding{
					Tool:       "jsleak",
					Type:       "secret",
					URL:        urlStr,
					File:       fpath,
					Match:      line,
					Entropy:    fmt.Sprintf("%.2f", entropy),
					Severity:   severity,
					Confidence: confidence,
				})
			}

			mu.Lock()
			findings = append(findings, localFindings...)
			rawLines = append(rawLines, localRaw...)
			mu.Unlock()
		}(url, path)
	}

	wg.Wait()
	os.WriteFile(filepath.Join(rawDir, "jsleak_findings.txt"), []byte(strings.Join(rawLines, "\n")), 0644)
	return findings
}

func CheckGitExposure(liveHosts []string, gitDir string, threads int) []string {
	var dumpPaths []string
	
	for _, host := range liveHosts {
		host = strings.TrimRight(host, "/")
		url := host + "/.git/config"
		
		req, _ := http.NewRequest("HEAD", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		}
		client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			domainSlug := regexp.MustCompile(`[^\w\-]`).ReplaceAllString(core.BareDomain(host), "_")
			dumpPath := filepath.Join(gitDir, domainSlug)
			os.MkdirAll(dumpPath, 0755)
			
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			runCmd(ctx, "git-dumper", host, dumpPath)
			cancel()
			
			dumpPaths = append(dumpPaths, dumpPath)
		}
	}
	
	return dumpPaths
}

func ScanCariddi(dlMap map[string]string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding
	var urls []string
	for u, p := range dlMap {
		if p != "" && p != "/dev/null" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return findings
	}

	urlListPath := filepath.Join(rawDir, "_cariddi_urls.txt")
	os.WriteFile(urlListPath, []byte(strings.Join(urls, "\n")+"\n"), 0644)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", "type", urlListPath, "|", "cariddi", "-s", "-json")
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", "cat "+urlListPath+" | cariddi -s -json")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	out := stdout.String()
	os.WriteFile(filepath.Join(rawDir, "cariddi_findings.txt"), []byte(out), 0644)

	// Write segregated tool log
	core.WriteToolLog(logDir, "cariddi", out, stderr.String())

	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			urlStr := ""
			if u, ok := obj["url"].(string); ok {
				urlStr = u
			}
			match := ""
			if m, ok := obj["secret"].(string); ok {
				match = m
			}
			if match == "" {
				if d, ok := obj["data"].(string); ok {
					match = d
				}
			}
			if match == "" {
				match = line
			}

			entropy := core.ShannonEntropy(match)
			severity := "LOW"
			confidence := 40

			if entropy > 4.0 {
				severity = "MEDIUM"
				confidence = 55
			}
			if entropy > 5.0 {
				severity = "HIGH"
				confidence = 70
			}

			findings = append(findings, core.Finding{
				Tool:       "cariddi",
				Type:       "secret",
				URL:        urlStr,
				File:       "",
				Match:      match,
				Severity:   severity,
				Confidence: confidence,
			})
		}
	}
	return findings
}

func ScanSubjs(dlMap map[string]string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding
	var urls []string
	for u, p := range dlMap {
		if p != "" && p != "/dev/null" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return findings
	}

	urlListPath := filepath.Join(rawDir, "_subjs_urls.txt")
	os.WriteFile(urlListPath, []byte(strings.Join(urls, "\n")+"\n"), 0644)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", "type", urlListPath, "|", "subjs")
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", "cat "+urlListPath+" | subjs")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	out := stdout.String()
	os.WriteFile(filepath.Join(rawDir, "subjs_findings.txt"), []byte(out), 0644)

	// Write segregated tool log
	core.WriteToolLog(logDir, "subjs", out, stderr.String())

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, core.Finding{
			Tool:       "subjs",
			Type:       "endpoint",
			URL:        line,
			File:       "",
			Match:      line,
			Severity:   "INFO",
			Confidence: 25,
		})
	}
	return findings
}

// ScanMantra runs the Mantra tool for JS API key leak detection
func ScanMantra(dlMap map[string]string, rawDir string, logDir string) []core.Finding {
	var findings []core.Finding

	// Check if mantra is installed before iterating files
	if _, err := exec.LookPath("mantra"); err != nil {
		core.Info("Mantra skipped — not installed")
		return findings
	}

	// Empty input check: skip if no real files in dlMap
	if isDlMapEmpty(dlMap) {
		core.Info("Mantra skipped — no downloaded files")
		return findings
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	for urlStr, fpath := range dlMap {
		if fpath == "" || fpath == "/dev/null" {
			continue
		}
		wg.Add(1)
		go func(u, fp string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Run mantra on the file content via stdin pipe
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.CommandContext(ctx, "cmd", "/c", "type", fp, "|", "mantra")
			} else {
				cmd = exec.CommandContext(ctx, "sh", "-c", "cat "+fp+" | mantra")
			}

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			_ = cmd.Run()

			// Write segregated tool log
			core.WriteToolLog(logDir, "mantra", stdout.String(), stderr.String())

			out := stdout.String()
			var localFindings []core.Finding

			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || len(line) < 10 {
					continue
				}

				// Mantra outputs JSON lines or plain text matches
				var obj map[string]interface{}
				if err := json.Unmarshal([]byte(line), &obj); err == nil {
					match := ""
					matchType := "API Key Leak"
					if m, ok := obj["match"].(string); ok {
						match = m
					}
					if t, ok := obj["type"].(string); ok {
						matchType = t
					}
					if match == "" {
						if u, ok := obj["url"].(string); ok {
							match = u
						}
					}
					if match == "" {
						match = line
					}

					entropy := core.ShannonEntropy(match)
					severity := "MEDIUM"
					confidence := 60

					if entropy > 4.0 {
						severity = "HIGH"
						confidence = 75
					}
					if confidence > 100 {
						confidence = 100
					}

					localFindings = append(localFindings, core.Finding{
						Tool:       "mantra",
						Type:       matchType,
						URL:        u,
						File:       fp,
						Match:      match,
						Entropy:    fmt.Sprintf("%.2f", entropy),
						Severity:   severity,
						Confidence: confidence,
					})
				} else {
					// Plain text output
					entropy := core.ShannonEntropy(line)
					severity := "LOW"
					confidence := 45

					if entropy > 4.0 {
						severity = "MEDIUM"
						confidence = 60
					}

					localFindings = append(localFindings, core.Finding{
						Tool:       "mantra",
						Type:       "API Key Leak",
						URL:        u,
						File:       fp,
						Match:      line,
						Entropy:    fmt.Sprintf("%.2f", entropy),
						Severity:   severity,
						Confidence: confidence,
					})
				}
			}

			if len(localFindings) > 0 {
				mu.Lock()
				findings = append(findings, localFindings...)
				mu.Unlock()
			}
		}(urlStr, fpath)
	}
	wg.Wait()

	os.WriteFile(filepath.Join(rawDir, "mantra_findings.json"), []byte(fmt.Sprintf("%d findings", len(findings))), 0644)
	return findings
}
