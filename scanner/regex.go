package scanner

import (
	"fmt"
	"os"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
)

// severityMap assigns severity to known pattern types
var severityMap = map[string]string{
	// CRITICAL
	"AWS Access Key": "CRITICAL", "AWS Secret Key": "CRITICAL", "AWS IAM Long-term": "CRITICAL",
	"RSA Private Key": "CRITICAL", "EC Private Key": "CRITICAL", "DSA Private Key": "CRITICAL",
	"OpenSSH Private Key": "CRITICAL", "PKCS8 Private Key": "CRITICAL", "Encrypted Private Key": "CRITICAL",
	"PGP Private Key Block": "CRITICAL", "GitHub App Private Key": "CRITICAL",
	"PostgreSQL Connection String": "CRITICAL", "MySQL Connection String": "CRITICAL",
	"MongoDB Atlas URI": "CRITICAL", "Redis Connection String": "CRITICAL",
	"MSSQL Connection String": "CRITICAL", "Oracle DB JDBC String": "CRITICAL",
	"Azure DB Connection": "CRITICAL", "Azure Storage Key": "CRITICAL",
	"Azure CosmosDB Key": "CRITICAL", "Django Secret Key": "CRITICAL",
	"Rails Secret Key Base": "CRITICAL", "Laravel APP_KEY": "CRITICAL",
	"WordPress DB Password": "CRITICAL", "Spring Boot Datasource PW": "CRITICAL",
	"Ethereum Private Key": "CRITICAL", "Bitcoin WIF Private Key": "CRITICAL",
	"Mnemonic Seed Phrase": "CRITICAL", "Credit Card (PAN)": "CRITICAL",
	"Kubernetes Secret (b64)": "CRITICAL",

	// HIGH
	"Google API Key": "HIGH", "Stripe Standard API": "HIGH", "Stripe Restricted": "HIGH",
	"GitHub Token": "HIGH", "GitHub PAT (classic)": "HIGH", "GitHub Fine-grained PAT": "HIGH",
	"GitHub Actions Secret": "HIGH", "GitLab PAT": "HIGH",
	"Slack Token": "HIGH", "Slack Bot Token": "HIGH", "Slack Webhook URL": "HIGH",
	"Discord Bot Token": "HIGH", "Telegram Bot Token": "HIGH",
	"SendGrid API Key": "HIGH", "Twilio API Key": "HIGH", "Twilio Auth Token": "HIGH",
	"Mailgun API Key": "HIGH", "Mailchimp API Key": "HIGH",
	"Stripe Test Secret": "HIGH", "Stripe Live Publishable": "HIGH",
	"PayPal Client ID": "HIGH", "PayPal Secret": "HIGH",
	"Square Access Token": "HIGH", "Adyen API Key": "HIGH",
	"Facebook Access Token": "HIGH", "Twitter Bearer Token": "HIGH",
	"Google OAuth Client Secret": "HIGH", "Instagram Access Token": "HIGH",
	"Sentry DSN": "HIGH", "Datadog API Key": "HIGH", "New Relic API Key": "HIGH",
	"Vault Token": "HIGH", "Databricks PAT": "HIGH",
	"DigitalOcean PAT": "HIGH", "Heroku API Key": "HIGH",
	"Cloudflare API Key": "HIGH", "Supabase JWT Secret": "HIGH",
	"Firebase URL": "HIGH", "GCP Service Account JSON": "HIGH",
	"AWS Session Token": "HIGH", "Azure Client Secret": "HIGH",
	"Mapbox Secret Token": "HIGH", "Password in URL": "HIGH",
	"Extended JWT Token": "HIGH",
	"AZ CBS/Core Banking": "HIGH", "AZ SWIFT Gateway": "HIGH",

	// MEDIUM
	"Stripe Test Publishable": "MEDIUM", "Stripe Webhook Secret": "MEDIUM",
	"GCP API Key": "MEDIUM", "GCP OAuth Client ID": "MEDIUM",
	"Azure SAS Token": "MEDIUM", "Azure Tenant ID": "MEDIUM",
	"AWS Cognito Pool": "MEDIUM", "AWS SNS ARN Leak": "MEDIUM",
	"S3 Bucket Leak": "MEDIUM", "Internal IP (10.x.x.x)": "MEDIUM",
	"Internal IP (192.168.x.x)": "MEDIUM", "Internal Hostname Leak": "MEDIUM",
	"PHP Error Leak": "MEDIUM",
	"IBAN (European format)": "MEDIUM", "SWIFT / BIC Code": "MEDIUM",
	"Google Tag Manager ID": "MEDIUM", "Google Analytics ID": "MEDIUM",
	"NPM Auth Token": "MEDIUM", "Docker Hub Token": "MEDIUM",

	// LOW
	"Generic API Key": "LOW", "Generic Secret": "LOW",
	"Generic token": "LOW", "Generic key": "LOW",
	"generic password": "LOW", "Generic secret": "LOW",
	"Basic token": "LOW", "Bearer token": "LOW",
}

// ScanRegex scans downloaded files with regex patterns and keyword matching.
// Files are processed in parallel for performance.
func ScanRegex(dlMap map[string]string) []core.Finding {
	var findings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30) // Limit concurrency

	falsePosRe := regexp.MustCompile(FalsePositiveRe)

	// Pre-compile all patterns once
	compiled := make(map[string]*regexp.Regexp)
	for name, pat := range SecretPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		compiled[name] = re
	}

	keywordReStr := GetBankingKeywordRegex()
	keywordRe := regexp.MustCompile(keywordReStr)

	for url, filepath := range dlMap {
		if filepath == "" || filepath == "/dev/null" {
			continue
		}
		wg.Add(1)
		go func(urlStr, fpath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := os.ReadFile(fpath)
			if err != nil {
				return
			}
			content := string(data)
			var localFindings []core.Finding

			// 1. Scan standard and extended regex patterns
			for name, rx := range compiled {
				minEntropy := DefaultEntropy
				if val, ok := PatternEntropy[name]; ok {
					minEntropy = val
				}

				matches := rx.FindAllStringIndex(content, -1)
				for _, m := range matches {
					startIdx, endIdx := m[0], m[1]
					snippet := content[startIdx:endIdx]
					if len(snippet) > 200 {
						snippet = snippet[:200]
					}

					if len(snippet) < 12 || falsePosRe.MatchString(snippet) {
						continue
					}

					// Skip base64-encoded binary data (PNG, PDF, JPEG, GIF)
					if IsMagicByteEncoded(snippet) {
						continue
					}

					// Validate Credit Card matches with Luhn algorithm
					if name == "Credit Card (PAN)" && !LuhnCheck(snippet) {
						continue
					}

					// Validate Bitcoin WIF matches with Base58 charset & length check
					if name == "Bitcoin WIF Private Key" && !IsValidBitcoinWIF(snippet) {
						continue
					}

					entropy := core.ShannonEntropy(snippet)
					if entropy < minEntropy {
						continue
					}

					ctxStart := startIdx - 100
					if ctxStart < 0 {
						ctxStart = 0
					}
					ctxEnd := endIdx + 100
					if ctxEnd > len(content) {
						ctxEnd = len(content)
					}

					contextStr := content[ctxStart:ctxEnd]
					contextStr = strings.ReplaceAll(contextStr, "\n", " ")
					if len(contextStr) > 300 {
						contextStr = contextStr[:300]
					}

					lineNum := strings.Count(content[:startIdx], "\n") + 1

					// Determine severity and confidence
					severity := "LOW"
					if s, ok := severityMap[name]; ok {
						severity = s
					}
					confidence := calculateRegexConfidence(name, snippet, entropy, contextStr)

					localFindings = append(localFindings, core.Finding{
						Tool:       "regex",
						Type:       name,
						URL:        urlStr,
						Entropy:    fmt.Sprintf("%.2f", entropy),
						File:       fpath,
						Match:      snippet,
						Context:    contextStr,
						Line:       fmt.Sprintf("%d", lineNum),
						Severity:   severity,
						Confidence: confidence,
					})
				}
			}

			// 2. Scan banking keywords assignments
			keywordMatches := keywordRe.FindAllStringSubmatchIndex(content, -1)
			for _, m := range keywordMatches {
				if len(m) < 6 {
					continue
				}

				keyName := content[m[2]:m[3]]
				secretVal := content[m[4]:m[5]]

				if len(secretVal) < 4 || falsePosRe.MatchString(secretVal) {
					continue
				}

				entropy := core.ShannonEntropy(secretVal)
				if entropy < 2.5 {
					continue
				}

				lineNum := strings.Count(content[:m[0]], "\n") + 1
				fullSnippet := content[m[0]:m[1]]

				severity := "MEDIUM"
				confidence := 50
				if entropy > 4.0 {
					severity = "HIGH"
					confidence = 70
				}
				if sensitiveVarNameRe.MatchString(keyName) {
					confidence += 15
				}
				if confidence > 100 {
					confidence = 100
				}

				localFindings = append(localFindings, core.Finding{
					Tool:       "regex-keyword",
					Type:       "Banking Keyword Assignment (" + keyName + ")",
					URL:        urlStr,
					Entropy:    fmt.Sprintf("%.2f", entropy),
					File:       fpath,
					Match:      fullSnippet,
					Context:    fullSnippet,
					Line:       fmt.Sprintf("%d", lineNum),
					Severity:   severity,
					Confidence: confidence,
				})
			}

			if len(localFindings) > 0 {
				mu.Lock()
				findings = append(findings, localFindings...)
				mu.Unlock()
			}
		}(url, filepath)
	}
	wg.Wait()
	return findings
}

// calculateRegexConfidence scores a regex finding's confidence 0-100
func calculateRegexConfidence(patternName, match string, entropy float64, context string) int {
	confidence := 40 // Base confidence for regex match

	// Known high-confidence patterns with fixed prefixes
	highConfPatterns := []string{
		"AWS Access Key", "Google API Key", "Stripe", "GitHub", "GitLab",
		"Slack", "SendGrid", "Twilio", "Mailgun", "Mailchimp",
		"RSA Private Key", "EC Private Key", "OpenSSH Private Key",
		"PGP Private Key", "PKCS8 Private Key",
		"PostgreSQL", "MySQL", "MongoDB", "Redis",
		"Sentry DSN", "Firebase", "JWT",
	}
	for _, p := range highConfPatterns {
		if strings.Contains(patternName, p) {
			confidence += 30
			break
		}
	}

	// Entropy-based boost
	if entropy > 4.0 {
		confidence += 10
	}
	if entropy > 5.0 {
		confidence += 10
	}

	// Context keyword proximity boost
	if sensitiveContextRe.MatchString(context) {
		confidence += 10
	}

	if confidence > 100 {
		confidence = 100
	}
	return confidence
}
