package scanner

import (
	"fmt"
	"os"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
)

// JS-style inline assignment patterns
var jsAssignRe = regexp.MustCompile(`(?i)(?:var|let|const|this\.|self\.|window\.|global\.)\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*['"]([^'"]{4,200})['"]`)

// Object property assignment: { key: "value" } or key: "value"
var objPropRe = regexp.MustCompile(`(?i)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*['"]([^'"]{4,200})['"]`)

// Bracket notation: obj["key"] = "value" or window["key"] = "value"
var bracketAssignRe = regexp.MustCompile(`(?i)(?:\w+)\s*\[\s*['"]([a-zA-Z_$][a-zA-Z0-9_$]*)['"]]\s*=\s*['"]([^'"]{4,200})['"]`)

// Environment variable patterns: KEY=value or KEY="value"
var envAssignRe = regexp.MustCompile(`(?m)^([A-Z][A-Z0-9_]{2,})\s*=\s*['"]?([^\s'"]{4,200})['"]?`)

// Python/Ruby style: key = "value"
var genericAssignRe = regexp.MustCompile(`(?i)([a-zA-Z_][a-zA-Z0-9_]*(?:key|secret|token|password|passwd|pwd|auth|credential|api|access|private|bearer|jwt|hmac|signing)[a-zA-Z0-9_]*)\s*=\s*['"]([^'"]{4,200})['"]`)

// Template literal assignment: key = `value`
var templateLiteralRe = regexp.MustCompile("(?i)([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*=\\s*`([^`]{4,200})`")

// Sensitive variable name pattern (used for scoring)
var sensitiveVarNameRe = regexp.MustCompile(`(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?key|auth[_\-]?token|private[_\-]?key|password|passwd|pwd|credential|bearer|authorization|token|secret|apikey|api_secret|app_secret|client_secret|signing_key|encryption_key|jwt_secret|hmac|db_pass|db_password|database_password|redis_pass|mongo_pass|mysql_pass|postgres_pass|admin_pass|root_pass|master_key|master_secret|webhook_secret|stripe_key|paypal_secret|aws_secret|azure_secret|gcp_key|firebase_secret|twilio_token|sendgrid_key|slack_token|discord_token|telegram_token|github_token|gitlab_token|npm_token|pypi_token|docker_password|vault_token|consul_token|private_token|service_key|service_secret|merchant_key|merchant_secret|encryption|decryption)`)

// Very high confidence variable names
var criticalVarNameRe = regexp.MustCompile(`(?i)^(password|passwd|pwd|secret_key|private_key|api_key|apikey|secret|access_token|auth_token|client_secret|db_password|master_password|root_password|admin_password|jwt_secret|encryption_key|signing_key|webhook_secret)$`)

// Non-secret variable name patterns (false positive reduction)
var nonSecretVarRe = regexp.MustCompile(`(?i)(version|name|label|title|description|message|text|content|body|html|css|style|class|type|format|encoding|charset|lang|locale|timezone|currency|country|city|state|region|color|background|border|font|margin|padding|width|height|size|display|position|align|index|count|total|page|limit|offset|sort|order|direction|status|enabled|disabled|visible|hidden|active|inactive|default|placeholder|example|sample|test|mock|dummy|fake|temp|tmp|debug|dev|development|staging|production|mode|level|env|environment|log|verbose|quiet|silent)$`)

// ScanInlineAssign deep-scans JS files for variable/property assignments
// where the variable name suggests it holds a secret.
func ScanInlineAssign(dlMap map[string]string) []core.Finding {
	var findings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)
	falsePosRe := regexp.MustCompile(FalsePositiveRe)

	for urlStr, fpath := range dlMap {
		if fpath == "" || fpath == "/dev/null" {
			continue
		}
		wg.Add(1)
		go func(u, fp string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := os.ReadFile(fp)
			if err != nil {
				return
			}
			content := string(data)
			seen := make(map[string]bool)
			var localFindings []core.Finding

			// Scan each pattern type
			patterns := []struct {
				re      *regexp.Regexp
				patType string
			}{
				{jsAssignRe, "JS Variable Assignment"},
				{objPropRe, "Object Property"},
				{bracketAssignRe, "Bracket Notation"},
				{envAssignRe, "Environment Variable"},
				{genericAssignRe, "Generic Assignment"},
				{templateLiteralRe, "Template Literal"},
			}

			for _, pat := range patterns {
				matches := pat.re.FindAllStringSubmatchIndex(content, 500)
				for _, m := range matches {
					if len(m) < 6 {
						continue
					}

					varName := content[m[2]:m[3]]
					varValue := content[m[4]:m[5]]

					// Deduplicate
					dedup := varName + "=" + varValue
					if seen[dedup] {
						continue
					}
					seen[dedup] = true

					// Skip non-secret variable names
					if nonSecretVarRe.MatchString(varName) {
						continue
					}

					// Skip false positive values
					if falsePosRe.MatchString(varValue) || len(varValue) < 4 {
						continue
					}

					// Skip values that are obviously not secrets
					if isObviouslyNotSecret(varValue) {
						continue
					}

					// Score the finding
					confidence, severity := scoreInlineAssignment(varName, varValue)

					// Skip low-confidence findings
					if confidence < 30 {
						continue
					}

					lineNum := strings.Count(content[:m[0]], "\n") + 1
					entropy := core.ShannonEntropy(varValue)
					matchStr := fmt.Sprintf("%s = %s", varName, varValue)
					if len(matchStr) > 200 {
						matchStr = matchStr[:200]
					}

					localFindings = append(localFindings, core.Finding{
						Tool:       "inline-scanner",
						Type:       fmt.Sprintf("%s (%s)", pat.patType, varName),
						URL:        u,
						File:       fp,
						Match:      matchStr,
						Line:       fmt.Sprintf("%d", lineNum),
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
	return findings
}

// scoreInlineAssignment returns confidence (0-100) and severity based on variable name and value
func scoreInlineAssignment(varName, value string) (int, string) {
	confidence := 0
	severity := "INFO"

	// Variable name scoring
	if criticalVarNameRe.MatchString(varName) {
		confidence += 50
		severity = "HIGH"
	} else if sensitiveVarNameRe.MatchString(varName) {
		confidence += 35
		severity = "MEDIUM"
	} else {
		// Generic variable, only flag if value looks very secret-like
		confidence += 5
	}

	// Value scoring
	entropy := core.ShannonEntropy(value)

	if entropy > 4.5 {
		confidence += 20
		if severity == "INFO" {
			severity = "LOW"
		}
	} else if entropy > 3.5 {
		confidence += 10
	}

	if len(value) >= 20 {
		confidence += 5
	}
	if len(value) >= 40 {
		confidence += 5
	}

	// Known prefix boost
	if hasKnownSecretPrefix(value) {
		confidence += 25
		severity = "CRITICAL"
	}

	// Connection string pattern
	if strings.Contains(value, "://") && strings.Contains(value, "@") {
		confidence += 20
		severity = "HIGH"
	}

	// Looks like a key/token format
	if regexp.MustCompile(`^[a-zA-Z0-9_\-+/=]{20,}$`).MatchString(value) && entropy > 3.5 {
		confidence += 10
	}

	if confidence > 100 {
		confidence = 100
	}
	return confidence, severity
}

// isObviouslyNotSecret checks if a value is obviously not a secret
func isObviouslyNotSecret(val string) bool {
	lower := strings.ToLower(val)

	// Common non-secret values
	nonSecrets := []string{
		"true", "false", "null", "undefined", "none", "nil",
		"yes", "no", "on", "off",
		"http://", "https://", "ftp://", "file://",
		"localhost", "127.0.0.1", "0.0.0.0", "::1",
		"example.com", "test.com", "foo.com",
		"utf-8", "utf8", "ascii", "iso-8859",
		"application/json", "text/html", "text/plain",
		"GET", "POST", "PUT", "DELETE", "PATCH",
	}
	for _, ns := range nonSecrets {
		if lower == ns || lower == strings.ToLower(ns) {
			return true
		}
	}

	// URL without credentials
	if (strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")) && !strings.Contains(val, "@") {
		return true
	}

	// Pure number
	if regexp.MustCompile(`^\d+$`).MatchString(val) {
		return true
	}

	// Looks like a CSS property
	if regexp.MustCompile(`(?i)^(#[0-9a-f]{3,8}|rgba?\(|hsla?\(|\d+px|\d+em|\d+rem|\d+%|auto|inherit|initial|none|block|inline|flex|grid)$`).MatchString(val) {
		return true
	}

	return false
}
