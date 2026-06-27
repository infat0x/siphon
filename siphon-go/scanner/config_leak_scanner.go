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

// sensitiveFilePatterns maps file types to their importance
var sensitiveFilePatterns = map[string]string{
	".env":                "Environment File",
	".env.local":          "Local Environment File",
	".env.production":     "Production Environment File",
	".env.staging":        "Staging Environment File",
	".env.development":    "Development Environment File",
	".env.test":           "Test Environment File",
	".env.backup":         "Backup Environment File",
	".env.example":        "Example Environment File",
	".env.sample":         "Sample Environment File",
	"config.json":         "Config JSON",
	"config.yaml":         "Config YAML",
	"config.yml":          "Config YAML",
	"secrets.json":        "Secrets JSON",
	"credentials.json":    "Credentials JSON",
	"service-account.json":"GCP Service Account",
	"firebase.json":       "Firebase Config",
	"database.yml":        "Database Config",
	"wp-config.php":       "WordPress Config",
	"web.config":          "IIS Web Config",
	"appsettings.json":    "ASP.NET Config",
	"application.properties":"Spring Boot Config",
	"application.yml":     "Spring Boot Config",
	"settings.py":         "Django Settings",
	"docker-compose.yml":  "Docker Compose",
	"Dockerfile":          "Dockerfile",
	".dockerenv":          "Docker Environment",
	".htpasswd":           "Apache Password",
	".htaccess":           "Apache Config",
	"id_rsa":              "RSA Private Key",
	"id_rsa.pub":          "RSA Public Key",
	"id_ed25519":          "Ed25519 Private Key",
	"known_hosts":         "SSH Known Hosts",
	"authorized_keys":     "SSH Authorized Keys",
	".npmrc":              "NPM Config",
	".pypirc":             "PyPI Config",
	".netrc":              "Netrc File",
	".git-credentials":    "Git Credentials",
	"Thumbs.db":           "Windows Thumbs",
	".DS_Store":           "macOS Metadata",
}

// sensitivePathPrefixes are URL paths that often expose config
var sensitivePathPrefixes = []string{
	"/.env",
	"/.git/config",
	"/.git/HEAD",
	"/.svn/entries",
	"/.svn/wc.db",
	"/config.json",
	"/config.yaml",
	"/package.json",
	"/composer.json",
	"/Gemfile",
	"/requirements.txt",
	"/wp-config.php",
	"/web.config",
	"/appsettings.json",
	"/application.properties",
	"/server-status",
	"/server-info",
	"/phpinfo.php",
	"/.well-known/",
	"/actuator",
	"/actuator/env",
	"/actuator/configprops",
	"/api/debug",
	"/api/config",
	"/swagger.json",
	"/swagger-ui.html",
	"/v2/api-docs",
	"/graphql",
	"/.aws/credentials",
	"/backup.sql",
	"/dump.sql",
	"/database.sql",
	"/.vscode/settings.json",
	"/.idea/workspace.xml",
	"/Procfile",
	"/docker-compose.yml",
	"/.dockerenv",
	"/.htpasswd",
	"/crossdomain.xml",
	"/robots.txt",
	"/sitemap.xml",
	"/debug/vars",
	"/debug/pprof",
	"/_config.yml",
	"/netlify.toml",
	"/vercel.json",
	"/now.json",
	"/firebase.json",
	"/.firebaserc",
	"/amplify.yml",
}

// envLineRe matches KEY=VALUE patterns in .env files
var envLineRe = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([^\s'"#]+)['"]?`)

// envSecretKeyRe matches environment variable names that suggest secrets
var envSecretKeyRe = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key|api_key|apikey|access_key|auth|credential|private|bearer|jwt|hmac|signing|encryption|database_url|db_pass|redis_url|mongo_url|connection_string|dsn)`)

// ScanConfigLeaks probes live hosts for exposed sensitive files/paths
// and scans downloaded JS files for references to config files.
func ScanConfigLeaks(liveHosts []string, dlMap map[string]string, rawDir string) []core.Finding {
	var findings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Part 1: Probe live hosts for sensitive files
	sem := make(chan struct{}, 20)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for _, host := range liveHosts {
		host = strings.TrimRight(host, "/")
		for _, path := range sensitivePathPrefixes {
			wg.Add(1)
			go func(h, p string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				targetURL := h + p
				req, err := http.NewRequest("GET", targetURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != 200 {
					return
				}

				body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB limit
				if err != nil || len(body) < 10 {
					return
				}
				content := string(body)

				// Skip HTML error pages
				if core.IsValidJS(body) || isActualConfig(content, p) {
					var configFindings []core.Finding

					// Check for .env-style files
					if strings.Contains(p, ".env") || strings.Contains(p, "config") {
						envFindings := scanEnvContent(content, targetURL, p)
						configFindings = append(configFindings, envFindings...)
					}

					// If no env findings, report the exposure itself
					if len(configFindings) == 0 {
						severity := "MEDIUM"
						confidence := 60
						fileType := "Sensitive File"

						for ext, fType := range sensitiveFilePatterns {
							if strings.HasSuffix(p, ext) || strings.Contains(p, ext) {
								fileType = fType
								severity = "HIGH"
								confidence = 80
								break
							}
						}

						// Private keys and credentials are critical
						if strings.Contains(p, "private") || strings.Contains(p, "credential") ||
							strings.Contains(p, ".htpasswd") || strings.Contains(p, "id_rsa") {
							severity = "CRITICAL"
							confidence = 95
						}

						configFindings = append(configFindings, core.Finding{
							Tool:       "config-leak",
							Type:       fmt.Sprintf("Exposed %s", fileType),
							URL:        targetURL,
							File:       p,
							Match:      truncateContent(content, 200),
							Severity:   severity,
							Confidence: confidence,
						})
					}

					// Save the exposed file
					safeName := regexp.MustCompile(`[^\w\-.]`).ReplaceAllString(
						strings.ReplaceAll(p, "/", "_"), "_")
					saveFile := filepath.Join(rawDir, "config_leaks_"+safeName)
					os.WriteFile(saveFile, body, 0644)

					mu.Lock()
					findings = append(findings, configFindings...)
					mu.Unlock()
				}
			}(host, path)
		}
	}
	wg.Wait()

	// Part 2: Scan downloaded files for config references
	for urlStr, fpath := range dlMap {
		if fpath == "" || fpath == "/dev/null" {
			continue
		}
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}
		content := string(data)

		// Look for embedded config/env content in JS
		embeddedFindings := scanEmbeddedConfig(content, urlStr, fpath)
		findings = append(findings, embeddedFindings...)
	}

	return findings
}

// isActualConfig checks if content looks like a real config file (not an error page)
func isActualConfig(content, path string) bool {
	// Check for common config indicators
	lower := strings.ToLower(content)

	// Skip HTML pages
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return false
	}

	// .env files have KEY=VALUE
	if strings.Contains(path, ".env") {
		return envLineRe.MatchString(content)
	}

	// JSON config
	if strings.HasSuffix(path, ".json") {
		trimmed := strings.TrimSpace(content)
		return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	}

	// YAML config
	if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		return strings.Contains(content, ":") && !strings.Contains(lower, "<html")
	}

	// Git config
	if strings.Contains(path, ".git/") {
		return strings.Contains(content, "[core]") || strings.Contains(content, "[remote") || strings.Contains(content, "ref:")
	}

	// Properties files
	if strings.HasSuffix(path, ".properties") {
		return envLineRe.MatchString(content)
	}

	return true
}

// scanEnvContent scans .env-style content for secrets
func scanEnvContent(content, urlStr, filePath string) []core.Finding {
	var findings []core.Finding
	matches := envLineRe.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		key := m[1]
		value := m[2]

		if len(value) < 4 {
			continue
		}

		// Only flag keys that look like secrets
		if !envSecretKeyRe.MatchString(key) {
			continue
		}

		entropy := core.ShannonEntropy(value)
		severity := "HIGH"
		confidence := 75

		if entropy > 4.0 {
			severity = "CRITICAL"
			confidence = 90
		}

		findings = append(findings, core.Finding{
			Tool:       "config-leak",
			Type:       fmt.Sprintf("Env Secret (%s)", key),
			URL:        urlStr,
			File:       filePath,
			Match:      fmt.Sprintf("%s=%s", key, value),
			Entropy:    fmt.Sprintf("%.2f", entropy),
			Severity:   severity,
			Confidence: confidence,
		})
	}

	return findings
}

// scanEmbeddedConfig looks for embedded config patterns in JS files
func scanEmbeddedConfig(content, urlStr, filePath string) []core.Finding {
	var findings []core.Finding

	// Webpack DefinePlugin / process.env patterns
	processEnvRe := regexp.MustCompile(`(?i)process\.env\.([A-Z_][A-Z0-9_]*)\s*(?:===?\s*|!==?\s*|,|\|\||&&)?\s*['"]([^'"]{4,100})['"]`)
	matches := processEnvRe.FindAllStringSubmatchIndex(content, 200)

	for _, m := range matches {
		if len(m) < 6 {
			continue
		}
		key := content[m[2]:m[3]]
		value := content[m[4]:m[5]]

		if !envSecretKeyRe.MatchString(key) {
			continue
		}

		if isObviouslyNotSecret(value) {
			continue
		}

		lineNum := strings.Count(content[:m[0]], "\n") + 1
		entropy := core.ShannonEntropy(value)

		findings = append(findings, core.Finding{
			Tool:       "config-leak",
			Type:       fmt.Sprintf("Embedded process.env (%s)", key),
			URL:        urlStr,
			File:       filePath,
			Match:      fmt.Sprintf("process.env.%s = %s", key, value),
			Line:       fmt.Sprintf("%d", lineNum),
			Entropy:    fmt.Sprintf("%.2f", entropy),
			Severity:   "MEDIUM",
			Confidence: 65,
		})
	}

	// __NEXT_DATA__ / window.__CONFIG__ patterns
	configVarRe := regexp.MustCompile(`(?i)(?:window\.__(?:CONFIG|INITIAL_STATE|APP_DATA|NEXT_DATA|NUXT__|PRELOADED_STATE)__|globalThis\.__CONFIG__|window\.config)\s*=\s*(\{[^;]{20,1000}\})`)
	configMatches := configVarRe.FindAllStringSubmatchIndex(content, 10)

	for _, m := range configMatches {
		if len(m) < 4 {
			continue
		}
		configBlock := content[m[2]:m[3]]

		// Look for secrets inside the config block
		innerSecretRe := regexp.MustCompile(`(?i)(api[_\-]?key|secret|token|password|auth|credential)\s*['":]?\s*[:=]\s*['"]([^'"]{8,100})['"]`)
		innerMatches := innerSecretRe.FindAllStringSubmatch(configBlock, 50)

		for _, im := range innerMatches {
			if len(im) < 3 {
				continue
			}
			key := im[1]
			value := im[2]
			if isObviouslyNotSecret(value) {
				continue
			}

			lineNum := strings.Count(content[:m[0]], "\n") + 1
			entropy := core.ShannonEntropy(value)

			findings = append(findings, core.Finding{
				Tool:       "config-leak",
				Type:       fmt.Sprintf("Embedded Config Secret (%s)", key),
				URL:        urlStr,
				File:       filePath,
				Match:      fmt.Sprintf("%s = %s", key, value),
				Line:       fmt.Sprintf("%d", lineNum),
				Entropy:    fmt.Sprintf("%.2f", entropy),
				Severity:   "HIGH",
				Confidence: 70,
			})
		}
	}

	return findings
}

// truncateContent safely truncates content for display
func truncateContent(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
