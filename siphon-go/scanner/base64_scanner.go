package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
	"unicode/utf8"
)

// base64Re matches base64-encoded strings (min 20 chars, valid charset, optional padding)
var base64Re = regexp.MustCompile(`(?:"|'|=\s*|:\s*)([A-Za-z0-9+/]{20,}={0,2})(?:"|'|\s|;|,|$)`)

// base64UrlSafeRe matches URL-safe base64 strings
var base64UrlSafeRe = regexp.MustCompile(`(?:"|'|=\s*|:\s*)([A-Za-z0-9_-]{20,}={0,2})(?:"|'|\s|;|,|$)`)

// hexEncodedRe matches hex-encoded strings (0x prefix or \x escapes)
var hexEncodedRe = regexp.MustCompile(`(?:0x|\\x)([0-9a-fA-F]{20,})`)

// urlEncodedRe matches URL-encoded strings with significant encoding
var urlEncodedRe = regexp.MustCompile(`(%[0-9a-fA-F]{2}){5,}[A-Za-z0-9%._~:/?#\[\]@!$&'()*+,;=-]*`)

// unicodeEscapeRe matches unicode escape sequences
var unicodeEscapeRe = regexp.MustCompile(`(?:\\u[0-9a-fA-F]{4}){4,}`)

// doubleBase64Re matches strings that when decoded contain another base64 string
var innerBase64Re = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// Compiled secret patterns for checking decoded content
var decodedSecretPatterns []*regexp.Regexp

func init() {
	// Compile critical patterns for checking decoded content
	criticalPatterns := []string{
		`AIza[0-9A-Za-z\-_]{35}`,
		`AKIA[0-9A-Z]{16}`,
		`sk_live_[0-9a-zA-Z]{24}`,
		`sk_test_[0-9a-zA-Z]{24}`,
		`ghp_[0-9a-zA-Z]{36}`,
		`xox[baprs]-[0-9]{10,}`,
		`-----BEGIN\s*(RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY`,
		`(?i)(password|passwd|pwd|secret|token|api_key|apikey|access_key|auth_token)\s*[:=]\s*['\"]([^'"]{4,})`,
		`(?i)(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@`,
		`[0-9]{9}:[a-zA-Z0-9_-]{35}`, // Telegram bot token
		`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`, // JWT
		`SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}`, // SendGrid
	}
	for _, p := range criticalPatterns {
		decodedSecretPatterns = append(decodedSecretPatterns, regexp.MustCompile(p))
	}
}

// ScanBase64 scans files for base64, hex, and URL-encoded strings,
// decodes them, and checks if the decoded content contains secrets.
func ScanBase64(dlMap map[string]string) []core.Finding {
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
			var localFindings []core.Finding

			// 1. Standard base64
			localFindings = append(localFindings, scanBase64Strings(content, u, fp, base64Re, "base64", falsePosRe)...)

			// 2. URL-safe base64
			localFindings = append(localFindings, scanBase64Strings(content, u, fp, base64UrlSafeRe, "base64-urlsafe", falsePosRe)...)

			// 3. Hex-encoded strings
			localFindings = append(localFindings, scanHexStrings(content, u, fp, falsePosRe)...)

			// 4. URL-encoded strings
			localFindings = append(localFindings, scanURLEncodedStrings(content, u, fp, falsePosRe)...)

			// 5. Unicode escape sequences
			localFindings = append(localFindings, scanUnicodeEscapes(content, u, fp, falsePosRe)...)

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

func scanBase64Strings(content, urlStr, filePath string, re *regexp.Regexp, encoding string, falsePosRe *regexp.Regexp) []core.Finding {
	var findings []core.Finding
	matches := re.FindAllStringSubmatchIndex(content, 200) // limit to avoid flooding

	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		encoded := content[m[2]:m[3]]

		// Skip if it looks like known non-secret content
		if falsePosRe.MatchString(encoded) {
			continue
		}

		// Decode
		var decoded []byte
		var err error
		if encoding == "base64-urlsafe" {
			decoded, err = base64.URLEncoding.DecodeString(padBase64(encoded))
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(encoded)
			}
		} else {
			decoded, err = base64.StdEncoding.DecodeString(padBase64(encoded))
			if err != nil {
				decoded, err = base64.RawStdEncoding.DecodeString(encoded)
			}
		}
		if err != nil || len(decoded) < 8 {
			continue
		}

		// Check if decoded content is valid UTF-8 text
		if !utf8.Valid(decoded) {
			continue
		}
		decodedStr := string(decoded)

		// Check decoded content for secret patterns
		for _, pat := range decodedSecretPatterns {
			if pat.MatchString(decodedStr) {
				lineNum := strings.Count(content[:m[0]], "\n") + 1

				// Truncate for display
				matchDisplay := encoded
				if len(matchDisplay) > 150 {
					matchDisplay = matchDisplay[:150] + "..."
				}
				decodedDisplay := decodedStr
				if len(decodedDisplay) > 200 {
					decodedDisplay = decodedDisplay[:200]
				}

				findings = append(findings, core.Finding{
					Tool:         "base64-decoder",
					Type:         fmt.Sprintf("Encoded Secret (%s)", encoding),
					URL:          urlStr,
					File:         filePath,
					Match:        matchDisplay,
					DecodedMatch: decodedDisplay,
					Line:         fmt.Sprintf("%d", lineNum),
					Entropy:      fmt.Sprintf("%.2f", core.ShannonEntropy(decodedStr)),
					Severity:     "HIGH",
					Confidence:   75,
				})
				break // One finding per encoded string
			}
		}

		// Even if no pattern match, check entropy of decoded content
		decodedEntropy := core.ShannonEntropy(decodedStr)
		if decodedEntropy > 4.5 && len(decodedStr) >= 16 {
			// Check context for keywords
			ctxStart := m[0] - 100
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := m[1] + 50
			if ctxEnd > len(content) {
				ctxEnd = len(content)
			}
			ctx := content[ctxStart:ctxEnd]

			if sensitiveContextRe.MatchString(ctx) {
				lineNum := strings.Count(content[:m[0]], "\n") + 1
				decodedDisplay := decodedStr
				if len(decodedDisplay) > 200 {
					decodedDisplay = decodedDisplay[:200]
				}
				matchDisplay := encoded
				if len(matchDisplay) > 150 {
					matchDisplay = matchDisplay[:150] + "..."
				}

				findings = append(findings, core.Finding{
					Tool:         "base64-decoder",
					Type:         fmt.Sprintf("High-Entropy Decoded (%s)", encoding),
					URL:          urlStr,
					File:         filePath,
					Match:        matchDisplay,
					DecodedMatch: decodedDisplay,
					Line:         fmt.Sprintf("%d", lineNum),
					Entropy:      fmt.Sprintf("%.2f", decodedEntropy),
					Severity:     "MEDIUM",
					Confidence:   55,
				})
			}
		}
	}
	return findings
}

func scanHexStrings(content, urlStr, filePath string, falsePosRe *regexp.Regexp) []core.Finding {
	var findings []core.Finding
	matches := hexEncodedRe.FindAllStringSubmatchIndex(content, 100)

	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		hexStr := content[m[2]:m[3]]
		if len(hexStr) < 20 {
			continue
		}

		decoded, err := hex.DecodeString(hexStr)
		if err != nil || len(decoded) < 8 {
			continue
		}
		if !utf8.Valid(decoded) {
			continue
		}
		decodedStr := string(decoded)
		if falsePosRe.MatchString(decodedStr) {
			continue
		}

		for _, pat := range decodedSecretPatterns {
			if pat.MatchString(decodedStr) {
				lineNum := strings.Count(content[:m[0]], "\n") + 1
				decodedDisplay := decodedStr
				if len(decodedDisplay) > 200 {
					decodedDisplay = decodedDisplay[:200]
				}
				findings = append(findings, core.Finding{
					Tool:         "base64-decoder",
					Type:         "Hex-Encoded Secret",
					URL:          urlStr,
					File:         filePath,
					Match:        content[m[0]:m[1]],
					DecodedMatch: decodedDisplay,
					Line:         fmt.Sprintf("%d", lineNum),
					Entropy:      fmt.Sprintf("%.2f", core.ShannonEntropy(decodedStr)),
					Severity:     "HIGH",
					Confidence:   70,
				})
				break
			}
		}
	}
	return findings
}

func scanURLEncodedStrings(content, urlStr, filePath string, falsePosRe *regexp.Regexp) []core.Finding {
	var findings []core.Finding
	matches := urlEncodedRe.FindAllStringIndex(content, 100)

	for _, m := range matches {
		encoded := content[m[0]:m[1]]
		if len(encoded) < 20 {
			continue
		}

		decoded, err := url.QueryUnescape(encoded)
		if err != nil || len(decoded) < 8 {
			continue
		}
		if falsePosRe.MatchString(decoded) {
			continue
		}

		for _, pat := range decodedSecretPatterns {
			if pat.MatchString(decoded) {
				lineNum := strings.Count(content[:m[0]], "\n") + 1
				decodedDisplay := decoded
				if len(decodedDisplay) > 200 {
					decodedDisplay = decodedDisplay[:200]
				}
				matchDisplay := encoded
				if len(matchDisplay) > 150 {
					matchDisplay = matchDisplay[:150] + "..."
				}
				findings = append(findings, core.Finding{
					Tool:         "base64-decoder",
					Type:         "URL-Encoded Secret",
					URL:          urlStr,
					File:         filePath,
					Match:        matchDisplay,
					DecodedMatch: decodedDisplay,
					Line:         fmt.Sprintf("%d", lineNum),
					Entropy:      fmt.Sprintf("%.2f", core.ShannonEntropy(decoded)),
					Severity:     "HIGH",
					Confidence:   65,
				})
				break
			}
		}
	}
	return findings
}

func scanUnicodeEscapes(content, urlStr, filePath string, falsePosRe *regexp.Regexp) []core.Finding {
	var findings []core.Finding
	matches := unicodeEscapeRe.FindAllStringIndex(content, 50)

	for _, m := range matches {
		encoded := content[m[0]:m[1]]
		decoded := decodeUnicodeEscapes(encoded)
		if len(decoded) < 8 {
			continue
		}
		if falsePosRe.MatchString(decoded) {
			continue
		}

		for _, pat := range decodedSecretPatterns {
			if pat.MatchString(decoded) {
				lineNum := strings.Count(content[:m[0]], "\n") + 1
				findings = append(findings, core.Finding{
					Tool:         "base64-decoder",
					Type:         "Unicode-Escaped Secret",
					URL:          urlStr,
					File:         filePath,
					Match:        encoded,
					DecodedMatch: decoded,
					Line:         fmt.Sprintf("%d", lineNum),
					Entropy:      fmt.Sprintf("%.2f", core.ShannonEntropy(decoded)),
					Severity:     "HIGH",
					Confidence:   70,
				})
				break
			}
		}
	}
	return findings
}

// padBase64 adds padding to base64 strings if missing
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// decodeUnicodeEscapes converts \uXXXX sequences to actual characters
func decodeUnicodeEscapes(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
			hexStr := s[i+2 : i+6]
			decoded, err := hex.DecodeString(hexStr)
			if err == nil && len(decoded) == 2 {
				r := rune(decoded[0])<<8 | rune(decoded[1])
				result.WriteRune(r)
				i += 6
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String()
}
