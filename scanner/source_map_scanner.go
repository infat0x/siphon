package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)

// sourceMappingURLRe matches sourceMappingURL comments in JS files
var sourceMappingURLRe = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)

// sourceMapFileRe matches X-SourceMap header values
var sourceMapFileRe = regexp.MustCompile(`\.map$`)

// ScanSourceMaps discovers and downloads source maps for JS files,
// then scans the original source code for secrets.
func ScanSourceMaps(dlMap map[string]string, rawDir string) []core.Finding {
	var findings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 15)

	mapDir := filepath.Join(rawDir, "source_maps")
	os.MkdirAll(mapDir, 0755)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		},
	}

	for urlStr, fpath := range dlMap {
		if fpath == "" || fpath == "/dev/null" {
			continue
		}
		wg.Add(1)
		go func(jsURL, jsPath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var localFindings []core.Finding

			// Read the JS file and look for sourceMappingURL
			data, err := os.ReadFile(jsPath)
			if err != nil {
				return
			}
			content := string(data)

			mapURLs := discoverSourceMapURLs(jsURL, content)

			for _, mapURL := range mapURLs {
				// Download the source map
				mapContent, err := downloadSourceMap(client, mapURL)
				if err != nil || len(mapContent) < 50 {
					continue
				}

				// Save for reference
				safeName := regexp.MustCompile(`[^\w\-.]`).ReplaceAllString(filepath.Base(mapURL), "_")
				mapFile := filepath.Join(mapDir, safeName)
				os.WriteFile(mapFile, []byte(mapContent), 0644)

				// Extract original sources from source map
				sources := extractSourcesFromMap(mapContent)

				// Scan each extracted source for secrets
				for sourceName, sourceContent := range sources {
					if len(sourceContent) < 20 {
						continue
					}

					// Run regex patterns on source content
					secretFindings := scanContentForSecrets(sourceContent, jsURL, sourceName)
					localFindings = append(localFindings, secretFindings...)
				}

				// Also scan the raw source map JSON for leaked secrets
				rawFindings := scanContentForSecrets(mapContent, jsURL, mapURL)
				for i := range rawFindings {
					rawFindings[i].Type = "Source Map Raw: " + rawFindings[i].Type
				}
				localFindings = append(localFindings, rawFindings...)
			}

			// Also try common .map URL patterns
			commonMapURLs := []string{
				jsURL + ".map",
				strings.TrimSuffix(jsURL, ".js") + ".js.map",
			}

			for _, mapURL := range commonMapURLs {
				// Avoid duplicates
				alreadyTried := false
				for _, tried := range mapURLs {
					if tried == mapURL {
						alreadyTried = true
						break
					}
				}
				if alreadyTried {
					continue
				}

				mapContent, err := downloadSourceMap(client, mapURL)
				if err != nil || len(mapContent) < 50 {
					continue
				}

				// Verify it's actually JSON (source map)
				if !strings.HasPrefix(strings.TrimSpace(mapContent), "{") {
					continue
				}

				safeName := regexp.MustCompile(`[^\w\-.]`).ReplaceAllString(filepath.Base(mapURL), "_")
				mapFile := filepath.Join(mapDir, safeName)
				os.WriteFile(mapFile, []byte(mapContent), 0644)

				sources := extractSourcesFromMap(mapContent)
				for sourceName, sourceContent := range sources {
					if len(sourceContent) < 20 {
						continue
					}
					secretFindings := scanContentForSecrets(sourceContent, jsURL, sourceName)
					localFindings = append(localFindings, secretFindings...)
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
	return findings
}

// discoverSourceMapURLs finds source map URLs from JS file content and headers
func discoverSourceMapURLs(jsURL, content string) []string {
	var urls []string
	seen := make(map[string]bool)

	matches := sourceMappingURLRe.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		mapPath := strings.TrimSpace(m[1])

		// Skip data: URIs
		if strings.HasPrefix(mapPath, "data:") {
			continue
		}

		// Resolve relative URLs
		var mapURL string
		if strings.HasPrefix(mapPath, "http://") || strings.HasPrefix(mapPath, "https://") {
			mapURL = mapPath
		} else if strings.HasPrefix(mapPath, "//") {
			mapURL = "https:" + mapPath
		} else {
			// Relative to JS file URL
			lastSlash := strings.LastIndex(jsURL, "/")
			if lastSlash >= 0 {
				mapURL = jsURL[:lastSlash+1] + mapPath
			} else {
				mapURL = jsURL + "/" + mapPath
			}
		}

		if !seen[mapURL] {
			seen[mapURL] = true
			urls = append(urls, mapURL)
		}
	}

	return urls
}

// downloadSourceMap fetches a source map file
func downloadSourceMap(client *http.Client, mapURL string) (string, error) {
	req, err := http.NewRequest("GET", mapURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// extractSourcesFromMap parses a source map JSON and extracts sourcesContent
func extractSourcesFromMap(mapJSON string) map[string]string {
	result := make(map[string]string)

	// Simple JSON parsing for sourcesContent array
	// Looking for "sourcesContent":["...","..."] pattern
	scIdx := strings.Index(mapJSON, `"sourcesContent"`)
	if scIdx < 0 {
		return result
	}

	// Find sources array for names
	var sourceNames []string
	sIdx := strings.Index(mapJSON, `"sources"`)
	if sIdx >= 0 {
		sourceNames = extractJSONStringArray(mapJSON[sIdx:])
	}

	contents := extractJSONStringArray(mapJSON[scIdx:])
	for i, content := range contents {
		name := fmt.Sprintf("source_%d", i)
		if i < len(sourceNames) {
			name = sourceNames[i]
		}
		// Unescape JSON string
		content = strings.ReplaceAll(content, `\n`, "\n")
		content = strings.ReplaceAll(content, `\t`, "\t")
		content = strings.ReplaceAll(content, `\"`, `"`)
		content = strings.ReplaceAll(content, `\\`, `\`)
		result[name] = content
	}

	return result
}

// extractJSONStringArray extracts string values from a JSON array starting at the current position
func extractJSONStringArray(s string) []string {
	var result []string

	// Find the opening bracket
	bracketIdx := strings.Index(s, "[")
	if bracketIdx < 0 {
		return result
	}
	s = s[bracketIdx+1:]

	depth := 1
	inString := false
	escaped := false
	var current strings.Builder
	stringStarted := false

	for i := 0; i < len(s) && depth > 0; i++ {
		c := s[i]

		if escaped {
			if stringStarted {
				current.WriteByte(c)
			}
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			if stringStarted {
				current.WriteByte(c)
			}
			continue
		}

		if c == '"' && !escaped {
			if inString {
				// End of string
				result = append(result, current.String())
				current.Reset()
				stringStarted = false
				inString = false
			} else {
				// Start of string
				inString = true
				stringStarted = true
			}
			continue
		}

		if !inString {
			if c == '[' {
				depth++
			} else if c == ']' {
				depth--
			}
		} else if stringStarted {
			current.WriteByte(c)
		}
	}

	return result
}

// scanContentForSecrets runs the compiled regex patterns against content
func scanContentForSecrets(content, urlStr, sourceName string) []core.Finding {
	var findings []core.Finding
	falsePosRe := regexp.MustCompile(FalsePositiveRe)

	// Compile a subset of critical patterns for source map scanning
	criticalPatterns := map[string]string{
		"AWS Access Key":              `AKIA[0-9A-Z]{16}`,
		"Google API Key":              `AIza[0-9A-Za-z\-_]{35}`,
		"Stripe Live Key":             `sk_live_[0-9a-zA-Z]{24}`,
		"Stripe Test Key":             `sk_test_[0-9a-zA-Z]{24}`,
		"GitHub Token":                `ghp_[0-9a-zA-Z]{36}`,
		"GitHub Fine-grained PAT":     `github_pat_[0-9a-zA-Z_]{82}`,
		"GitLab PAT":                  `glpat-[0-9a-zA-Z\-]{20}`,
		"Slack Token":                 `xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]+`,
		"Slack Webhook":               `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`,
		"Discord Webhook":             `https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+`,
		"Telegram Bot Token":          `[0-9]{8,10}:[a-zA-Z0-9_-]{35}`,
		"SendGrid Key":                `SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}`,
		"Twilio SID":                  `AC[a-z0-9]{32}`,
		"RSA Private Key":             `-----BEGIN RSA PRIVATE KEY-----`,
		"Private Key":                 `-----BEGIN PRIVATE KEY-----`,
		"EC Private Key":              `-----BEGIN EC PRIVATE KEY-----`,
		"OpenSSH Private Key":         `-----BEGIN OPENSSH PRIVATE KEY-----`,
		"JWT Token":                   `eyJ[a-zA-Z0-9_-]{2,}\.eyJ[a-zA-Z0-9_-]{2,}\.[a-zA-Z0-9_-]{2,}`,
		"PostgreSQL Connection":       `(?i)postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[a-z0-9_]+`,
		"MySQL Connection":            `(?i)mysql://[^:]+:[^@]+@[^/]+/[a-z0-9_]+`,
		"MongoDB URI":                 `(?i)mongodb\+srv://[^:]+:[^@]+@[a-z0-9.-]+`,
		"Redis Connection":            `(?i)redis://:[^@]+@[a-z0-9._-]+`,
		"Password in URL":             `[a-zA-Z]{3,10}://[^/\s:@]+:[^/\s:@]+@.{1,100}`,
		"Firebase URL":                `[a-z0-9.-]+\.firebaseio\.com`,
		"Sentry DSN":                  `https://[a-f0-9]+@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+`,
		"Generic Password Assignment": `(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*['"]([^'"]{8,})['"]`,
		"Hardcoded API Key":           `(?i)(api_key|apikey|api_secret)\s*[:=]\s*['"]([^'"]{16,})['"]`,
	}

	for name, pattern := range criticalPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(content, 50)
		for _, m := range matches {
			match := content[m[0]:m[1]]
			if len(match) > 200 {
				match = match[:200]
			}
			if len(match) < 10 || falsePosRe.MatchString(match) {
				continue
			}

			lineNum := strings.Count(content[:m[0]], "\n") + 1

			findings = append(findings, core.Finding{
				Tool:       "source-map",
				Type:       name,
				URL:        urlStr,
				File:       sourceName,
				Match:      match,
				Line:       fmt.Sprintf("%d", lineNum),
				Entropy:    fmt.Sprintf("%.2f", core.ShannonEntropy(match)),
				Severity:   "HIGH",
				Confidence: 80,
			})
		}
	}

	return findings
}
