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
	"siphon-go/core"
	"strings"
	"sync"
	"time"
	"runtime"
)

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmdArgs := append([]string{"/c", name}, args...)
		cmd = exec.CommandContext(ctx, "cmd", cmdArgs...)
	} else {
		cmd = exec.CommandContext(ctx, name, args...)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	return stdout.String(), err
}

func ScanTrufflehog(dlDir string, rawDir string) []core.Finding {
	var findings []core.Finding
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out, _ := runCmd(ctx, "trufflehog", "filesystem", dlDir, "--json", "--no-verification", "--no-update")
	os.WriteFile(filepath.Join(rawDir, "trufflehog.json"), []byte(out), 0644)

	for _, line := range strings.Split(out, "\n") {
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

			findings = append(findings, core.Finding{
				Tool:  "trufflehog",
				Type:  fmt.Sprintf("%v", obj["DetectorName"]),
				URL:   filePath, // Will be mapped to original URL in main.go
				File:  filePath,
				Match: fmt.Sprintf("%v", obj["Raw"]),
			})
		}
	}
	return findings
}

func ScanGitleaks(dlDir string, rawDir string) []core.Finding {
	var findings []core.Finding
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reportPath := filepath.Join(rawDir, "gitleaks.json")
	_, _ = runCmd(ctx, "gitleaks", "detect", "--source", dlDir, "--no-git", "--report-format", "json", "--report-path", reportPath, "--exit-code", "0", "--log-level", "warn", "--redact=false")

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return findings
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err == nil {
		for _, item := range results {
			findings = append(findings, core.Finding{
				Tool:    "gitleaks",
				Type:    fmt.Sprintf("%v", item["RuleID"]),
				File:    fmt.Sprintf("%v", item["File"]),
				Match:   fmt.Sprintf("%v", item["Match"]),
				Line:    fmt.Sprintf("%v", item["StartLine"]),
				Entropy: fmt.Sprintf("%.2f", core.ShannonEntropy(fmt.Sprintf("%v", item["Secret"]))),
			})
		}
	}
	return findings
}

func ScanJsluice(dlMap map[string]string, rawDir string) []core.Finding {
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
			outSec, _ := runCmd(ctx, "jsluice", "secrets", fpath)
			outUrl, _ := runCmd(ctx, "jsluice", "urls", fpath)
			cancel()

			var localFindings []core.Finding
			
			// Parse secrets
			for _, line := range strings.Split(outSec, "\n") {
				if line == "" {
					continue
				}
				var obj map[string]interface{}
				if err := json.Unmarshal([]byte(line), &obj); err == nil {
					dataMap, _ := obj["data"].(map[string]interface{})
					localFindings = append(localFindings, core.Finding{
						Tool:  "jsluice",
						Type:  fmt.Sprintf("%v", obj["kind"]),
						URL:   urlStr,
						File:  fpath,
						Match: fmt.Sprintf("%v", dataMap["match"]),
						Line:  fmt.Sprintf("%v", obj["line"]),
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
						Tool:  "jsluice",
						Type:  "endpoint",
						URL:   urlStr,
						File:  fpath,
						Match: fmt.Sprintf("%v", obj["url"]),
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

func ScanNuclei(jsUrls []string, rawDir string) []core.Finding {
	var findings []core.Finding
	if len(jsUrls) == 0 {
		return findings
	}

	urlListPath := filepath.Join(rawDir, "_nuclei_urls.txt")
	os.WriteFile(urlListPath, []byte(strings.Join(jsUrls, "\n")+"\n"), 0644)
	reportPath := filepath.Join(rawDir, "nuclei_findings.json")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	_, _ = runCmd(ctx, "nuclei", "-l", urlListPath, "-tags", "exposure,token,javascript,config", "-silent", "-no-color", "-json", "-o", reportPath, "-rate-limit", "50", "-concurrency", "20", "-timeout", "10", "-no-update-templates")

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
			findings = append(findings, core.Finding{
				Tool:    "nuclei",
				Type:    fmt.Sprintf("%v", obj["template-id"]),
				URL:     fmt.Sprintf("%v", obj["matched-at"]),
				Match:   fmt.Sprintf("%v", obj["extracted-results"]),
				Context: fmt.Sprintf("severity=%v", info["severity"]),
			})
		}
	}
	return findings
}



func ScanJsleak(dlMap map[string]string, rawDir string) []core.Finding {
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
			out, _ := runCmd(ctx, "jsleak", "-f", fpath, "-s")
			cancel()

			var localFindings []core.Finding
			var localRaw []string
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if len(line) < 10 {
					continue
				}
				localRaw = append(localRaw, urlStr+": "+line)
				localFindings = append(localFindings, core.Finding{
					Tool:    "jsleak",
					Type:    "secret",
					URL:     urlStr,
					File:    fpath,
					Match:   line,
					Entropy: fmt.Sprintf("%.2f", core.ShannonEntropy(line)),
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
