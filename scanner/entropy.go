package scanner

import (
	"fmt"
	"os"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
)

// stringLiteralRe matches JS string literals: double-quoted, single-quoted, and backtick
var stringLiteralRe = regexp.MustCompile(`(?:"|')([^"'\\]{16,200})(?:"|')`)

// sensitiveContextRe matches keywords near a potential secret that boost confidence
var sensitiveContextRe = regexp.MustCompile(`(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|private[_\-]?key|password|passwd|credential|bearer|authorization|token|secret|apikey|api_secret|app_secret|client_secret|signing_key|encryption_key|jwt|hmac)`)

// commonFalsePositiveRe matches known non-secret high-entropy strings
var entropyFalsePositiveRe = regexp.MustCompile(`(?i)(^[0-9a-f]{32,}$|^[A-Za-z]+$|sha256|sha512|sha1|md5|webpack|chunk|module|vendor|polyfill|sourceMappingURL|sourceURL|data:image|data:application|data:text|font-face|base64,|charset=|application/json|text/html|text/css|text/javascript|image/png|image/jpeg|image/svg|console\.|function\s|return\s|var\s|let\s|const\s|import\s|export\s|require\(|\.prototype\.|\.indexOf\(|\.replace\(|\.split\(|\.join\(|\.map\(|\.filter\(|\.reduce\(|Math\.|Array\.|Object\.|String\.|Number\.|Boolean\.|undefined|null|true|false|localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|test\.com|foo|bar|baz|qux|lorem|ipsum|dolor|amet|hello|world)`)

// hexLikeRe matches pure hex strings which are often hashes, not secrets
var hexLikeRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// uuidRe matches UUID patterns
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// repetitive strings are now checked manually in the loop

// semVerRe matches semantic version strings
var semVerRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// jwtTokenRe matches valid JSON Web Tokens (header.payload.signature)
var jwtTokenRe = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$`)

// dateTimeRe matches date/time strings
var dateTimeRe = regexp.MustCompile(`^\d{4}[-/]\d{2}[-/]\d{2}`)

// commonLibPattern matches known library identifiers and hash-like content IDs
var commonLibPatternRe = regexp.MustCompile(`(?i)(node_modules|\.min\.|\.bundle\.|\.chunk\.|jquery|react|angular|vue|bootstrap|tailwind|lodash|moment|webpack|babel|polyfill|modernizr|fontawesome|animate\.css|normalize\.css)`)

// ScanEntropy extracts all string literals from JS files and checks their entropy.
// High-entropy strings (> threshold) with sensitive context are flagged as potential secrets.
func ScanEntropy(dlMap map[string]string) []core.Finding {
	var findings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	for url, fpath := range dlMap {
		if fpath == "" || fpath == "/dev/null" {
			continue
		}
		wg.Add(1)
		go func(urlStr, filePath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := os.ReadFile(filePath)
			if err != nil {
				return
			}
			content := string(data)

			var localFindings []core.Finding
			matches := stringLiteralRe.FindAllStringSubmatchIndex(content, -1)

			for _, m := range matches {
				if len(m) < 4 {
					continue
				}
				valStart, valEnd := m[2], m[3]
				value := content[valStart:valEnd]

				// Skip short or too long strings
				if len(value) < 16 || len(value) > 200 {
					continue
				}

				// Cryptographic secrets, API tokens, and hashes never contain whitespace.
				// This instantly eliminates prose, error messages, and Tailwind CSS utility class lists.
				if strings.ContainsAny(value, " \t\r\n") {
					continue
				}

				// Skip CSS style declarations, selectors, colors, and SVG paths
				if isCSSOrStyleValue(value) || IsSVGPath(value) {
					continue
				}

				// Skip code identifiers composed of standard dictionary/programming words
				if IsCodeIdentifierOrDictionaryWords(value) {
					continue
				}

				// Skip known false positives
				if entropyFalsePositiveRe.MatchString(value) {
					continue
				}

				// Skip pure hex if it looks like a content hash or build artifact
				if hexLikeRe.MatchString(value) && (len(value) == 32 || len(value) == 40 || len(value) == 64) {
					// Check surrounding context for build/asset/integrity keywords
					ctxStartCheck := valStart - 60
					if ctxStartCheck < 0 {
						ctxStartCheck = 0
					}
					ctxEndCheck := valEnd + 60
					if ctxEndCheck > len(content) {
						ctxEndCheck = len(content)
					}
					surrounding := strings.ToLower(content[ctxStartCheck:ctxEndCheck])
					if strings.Contains(surrounding, "chunk") || strings.Contains(surrounding, "buildid") ||
						strings.Contains(surrounding, "integrity") || strings.Contains(surrounding, "webpack") ||
						strings.Contains(surrounding, "sourcemap") || strings.Contains(surrounding, "asset") ||
						strings.Contains(surrounding, "cache") {
						continue
					}
				}

				// Skip UUIDs — often just identifiers
				if uuidRe.MatchString(value) {
					continue
				}

				// Skip repetitive patterns manually (Go regex doesn't support backreferences)
				if isRepetitive(value) {
					continue
				}

				// Skip semver and dates
				if semVerRe.MatchString(value) || dateTimeRe.MatchString(value) {
					continue
				}

				// Skip common library patterns
				if commonLibPatternRe.MatchString(value) {
					continue
				}

				// Skip URLs — they are not secrets
				if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//") {
					continue
				}

				// Skip alphabet/charset strings (Base64 table, hex table, etc.)
				if isAlphabetString(value) {
					continue
				}

				// Skip minified JavaScript code snippets
				if isMinifiedCode(value) {
					continue
				}

				// Skip base64-encoded binary data (PNG, PDF, JPEG, GIF)
				if IsMagicByteEncoded(value) {
					continue
				}

				entropy := core.ShannonEntropy(value)
				if entropy < 4.0 {
					continue
				}

				// Context analysis: check surrounding 200 chars for keywords
				ctxStart := valStart - 200
				if ctxStart < 0 {
					ctxStart = 0
				}
				ctxEnd := valEnd + 100
				if ctxEnd > len(content) {
					ctxEnd = len(content)
				}
				contextStr := content[ctxStart:ctxEnd]

				confidence := 40 // Base confidence for high-entropy
				severity := "LOW"
				findingType := "High-Entropy String"

				// Check for JSON Web Token (JWT)
				if jwtTokenRe.MatchString(value) {
					findingType = "JSON Web Token (JWT)"
					confidence = 90
					severity = "HIGH"
				} else if hasKnownSecretPrefix(value) {
					findingType = "High-Entropy Secret Token"
					confidence = 95
					severity = "CRITICAL"
				} else {
					// Boost confidence if sensitive keywords are nearby
					if sensitiveContextRe.MatchString(contextStr) {
						confidence += 35
						severity = "HIGH"
						findingType = "High-Entropy Secret Token"
					}

					// Higher entropy = higher confidence
					if entropy > 4.5 {
						confidence += 10
						if severity != "HIGH" {
							severity = "MEDIUM"
						}
					}
					if entropy > 5.0 {
						confidence += 10
						severity = "HIGH"
					}
					if entropy > 5.5 {
						confidence += 10
					}
				}

				if confidence > 100 {
					confidence = 100
				}

				lineNum := strings.Count(content[:valStart], "\n") + 1
				contextClean := strings.ReplaceAll(contextStr, "\n", " ")
				if len(contextClean) > 300 {
					contextClean = contextClean[:300]
				}

				localFindings = append(localFindings, core.Finding{
					Tool:       "entropy",
					Type:       findingType,
					URL:        urlStr,
					File:       filePath,
					Match:      value,
					Line:       fmt.Sprintf("%d", lineNum),
					Entropy:    fmt.Sprintf("%.2f", entropy),
					Context:    contextClean,
					Severity:   severity,
					Confidence: confidence,
				})
			}

			if len(localFindings) > 0 {
				mu.Lock()
				findings = append(findings, localFindings...)
				mu.Unlock()
			}
		}(url, fpath)
	}
	wg.Wait()
	return findings
}

// hasKnownSecretPrefix checks if a string starts with a known secret prefix
func hasKnownSecretPrefix(s string) bool {
	prefixes := []string{
		"sk_live_", "sk_test_", "pk_live_", "pk_test_",
		"rk_live_", "rk_test_",
		"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
		"github_pat_",
		"glpat-", "glptt-",
		"xox", "xapp-",
		"AIza",
		"AKIA", "ASIA", "AIDA", "AROA",
		"dop_v1_", "doo_v1_",
		"SG.",
		"sq0atp-", "sq0csp-",
		"key-",
		"whsec_",
		"rnd_",
		"pscale_tkn_", "pscale_pw_",
		"dapi",
		"hvs.",
		"eyJ", // JWT
		"-----BEGIN",
		"bearer ", "Bearer ",
		"Basic ",
		"EAA", // Facebook
		"AAAA", // Twitter
		"ya29.", // Google OAuth
		"rzp_live_", "rzp_test_",
		"v1.0-",
		"GOCSPX-",
		"npm_",
		"pypi-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// standardAlphabets contains known character set strings that should not be flagged as secrets.
var standardAlphabets = []string{
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",  // Base64
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",   // Base64 (no padding)
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",   // Base64URL
	"0123456789abcdefABCDEF",                                              // Hex
	"0123456789abcdef",                                                     // Hex lowercase
	"0123456789ABCDEF",                                                     // Hex uppercase
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",      // Alphanumeric
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",                // Alpha only
	"0123456789",                                                           // Numeric only
}

// isAlphabetString returns true if the string is ≥90% a substring of a standard
// character set alphabet (Base64, Hex, etc). These are lookup tables, not secrets.
func isAlphabetString(s string) bool {
	for _, alphabet := range standardAlphabets {
		// Check if s is a direct substring of the alphabet
		if strings.Contains(alphabet, s) {
			return true
		}
		// Check if ≥90% of s's characters appear sequentially in the alphabet
		if len(s) > 10 && float64(countSubstringOverlap(s, alphabet))/float64(len(s)) > 0.90 {
			return true
		}
	}
	return false
}

// countSubstringOverlap counts how many characters in s are also in alphabet.
func countSubstringOverlap(s, alphabet string) int {
	count := 0
	for _, c := range s {
		if strings.ContainsRune(alphabet, c) {
			count++
		}
	}
	return count
}

// structuralChars are characters typical in minified JavaScript code, not in secrets.
const structuralChars = "{}()<>=+-;,:!?."

// jsCodeKeywords are substrings that indicate the string is JS code, not a secret.
var jsCodeKeywords = []string{
	"function", "return ", "return(", "var ", "let ", "const ",
	"this.", "typeof ", "instanceof ", ".prototype", ".apply(",
	".call(", ".bind(", "=>{", "=>{\n", "if(", "else{",
	"for(", "while(", "switch(", "case ", "break;",
	"new ", "delete ", "throw ", "catch(", "try{",
	"null)", "undefined)", "true)", "false)",
	".push(", ".pop(", ".shift(", ".map(", ".filter(",
	".reduce(", ".forEach(", ".indexOf(", ".replace(",
	".split(", ".join(", ".slice(", ".concat(",
	"document.", "window.", "console.", "Math.",
	"JSON.", "Object.", "Array.",
	"&&", "||", "!==", "===",
	"dataType:", "withCredentials", "siblingRole",
	"pluginConfig", "globalSwatchId",
}

// isMinifiedCode returns true if the string looks like minified JS code.
// It checks both structural character density (>12%) and presence of JS keywords.
func isMinifiedCode(s string) bool {
	if len(s) < 16 {
		return false
	}

	// Check for JS keywords inside the string
	lower := strings.ToLower(s)
	for _, kw := range jsCodeKeywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}

	// Structural character density check (lowered from 15% to 12%)
	count := 0
	for _, c := range s {
		if strings.ContainsRune(structuralChars, c) {
			count++
		}
	}
	return float64(count)/float64(len(s)) > 0.12
}

// isRepetitive checks if a string consists mostly of a repeating pattern
func isRepetitive(s string) bool {
	if len(s) < 10 {
		return false
	}
	
	// Check single character repeat (e.g. "aaaaa...")
	charCount := make(map[rune]int)
	for _, c := range s {
		charCount[c]++
	}
	
	// If one character makes up more than 80% of the string
	for _, count := range charCount {
		if float64(count)/float64(len(s)) > 0.8 {
			return true
		}
	}
	
	return false
}

// IsSVGPath detects SVG vector path definitions (e.g. M10 20L30..., M12,2C6.48...)
func IsSVGPath(s string) bool {
	if len(s) < 10 {
		return false
	}
	if s[0] != 'M' && s[0] != 'm' {
		return false
	}

	secondChar := s[1]
	if (secondChar >= '0' && secondChar <= '9') || secondChar == '-' || secondChar == '.' || secondChar == ' ' || secondChar == ',' {
		svgCharCount := 0
		for _, c := range s {
			if (c >= '0' && c <= '9') || c == ',' || c == '.' || c == '-' || c == ' ' ||
				strings.ContainsRune("MmLlHhVvCcSsQqTtAaZz", c) {
				svgCharCount++
			}
		}
		if float64(svgCharCount)/float64(len(s)) > 0.88 {
			return true
		}
	}
	return false
}

// IsHexColor returns true if s is a CSS hex color code (#fff, #ffffff, #1a2b3cff)
func IsHexColor(s string) bool {
	if !strings.HasPrefix(s, "#") {
		return false
	}
	hexPart := s[1:]
	if len(hexPart) != 3 && len(hexPart) != 4 && len(hexPart) != 6 && len(hexPart) != 8 {
		return false
	}
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isCSSOrStyleValue checks if a string is a CSS declaration, function, or style parameter
func isCSSOrStyleValue(s string) bool {
	if strings.Contains(s, "!important") || strings.Contains(s, ";") ||
		strings.Contains(s, "var(--") || strings.Contains(s, "calc(") ||
		strings.Contains(s, "rgba(") || strings.Contains(s, "rgb(") ||
		strings.Contains(s, "hsl(") || strings.Contains(s, "hsla(") ||
		strings.Contains(s, "cubic-bezier(") || strings.Contains(s, "translate(") ||
		strings.Contains(s, "matrix(") || strings.Contains(s, "scale(") ||
		strings.Contains(s, "data-") || strings.Contains(s, "aria-") ||
		strings.Contains(s, "[&_") || strings.Contains(s, "[a&]") ||
		strings.Contains(s, "pointer-events-") || strings.Contains(s, "whitespace-") ||
		strings.Contains(s, "overflow-") {
		return true
	}
	if IsHexColor(s) {
		return true
	}
	return false
}

// splitCamelCaseWords splits a camelCase, PascalCase, or snake_case string into component words.
func splitCamelCaseWords(s string) []string {
	var words []string
	var current strings.Builder

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if r == '_' || r == '-' {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			continue
		}

		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := runes[i-1]
			// Boundary: lowercase followed by uppercase (e.g. "fooBar" -> "foo", "Bar")
			if prev >= 'a' && prev <= 'z' {
				if current.Len() > 0 {
					words = append(words, current.String())
					current.Reset()
				}
			} else if i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z' && prev >= 'A' && prev <= 'Z' {
				// Boundary: uppercase sequence followed by lowercase (e.g. "XMLHttp" -> "XML", "Http")
				if current.Len() > 0 {
					words = append(words, current.String())
					current.Reset()
				}
			}
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 {
		words = append(words, current.String())
	}

	return words
}

var commonWordDict = map[string]struct{}{
	"get": {}, "set": {}, "is": {}, "has": {}, "to": {}, "from": {}, "in": {}, "on": {}, "by": {}, "with": {}, "for": {}, "at": {}, "of": {}, "as": {}, "or": {}, "and": {}, "not": {},
	"component": {}, "components": {}, "element": {}, "elements": {}, "container": {}, "wrapper": {}, "header": {}, "footer": {}, "content": {}, "body": {}, "view": {}, "views": {},
	"button": {}, "buttons": {}, "input": {}, "inputs": {}, "form": {}, "forms": {}, "select": {}, "option": {}, "options": {}, "checkbox": {}, "radio": {}, "table": {}, "cell": {}, "row": {}, "column": {}, "columns": {},
	"dialog": {}, "modal": {}, "drawer": {}, "popup": {}, "tooltip": {}, "menu": {}, "item": {}, "items": {}, "list": {}, "screen": {}, "page": {}, "pages": {},
	"auth": {}, "authentication": {}, "login": {}, "logout": {}, "user": {}, "users": {}, "account": {}, "profile": {}, "permission": {}, "permissions": {}, "role": {}, "roles": {},
	"action": {}, "actions": {}, "state": {}, "event": {}, "events": {}, "dispatch": {}, "reducer": {}, "store": {}, "context": {}, "hook": {}, "effect": {}, "ref": {},
	"handler": {}, "handlers": {}, "handle": {}, "handles": {}, "handling": {}, "listener": {}, "listeners": {}, "callback": {}, "callbacks": {}, "promise": {}, "resolve": {}, "reject": {}, "async": {}, "await": {}, "fetch": {}, "check": {}, "checks": {}, "checking": {}, "run": {}, "start": {}, "stop": {}, "init": {}, "initialize": {}, "process": {}, "parse": {},
	"request": {}, "requests": {}, "response": {}, "responses": {}, "client": {}, "server": {}, "api": {}, "service": {}, "services": {}, "provider": {}, "providers": {}, "factory": {}, "adapter": {},
	"controller": {}, "router": {}, "route": {}, "routes": {}, "navigation": {}, "history": {}, "location": {}, "query": {}, "param": {}, "params": {},
	"data": {}, "value": {}, "values": {}, "key": {}, "keys": {}, "name": {}, "names": {}, "type": {}, "types": {}, "title": {}, "label": {}, "labels": {}, "description": {}, "text": {}, "index": {},
	"default": {}, "initial": {}, "active": {}, "disabled": {}, "enabled": {}, "visible": {}, "hidden": {}, "selected": {}, "checked": {},
	"current": {}, "previous": {}, "next": {}, "first": {}, "last": {}, "open": {}, "close": {}, "success": {}, "error": {}, "errors": {}, "failed": {}, "failure": {},
	"warning": {}, "info": {}, "loading": {}, "pending": {}, "complete": {}, "completed": {}, "finished": {}, "cancel": {}, "submit": {},
	"update": {}, "create": {}, "delete": {}, "remove": {}, "add": {}, "edit": {}, "save": {}, "load": {}, "clear": {}, "reset": {},
	"config": {}, "configuration": {}, "setting": {}, "settings": {}, "theme": {}, "style": {}, "styles": {}, "class": {}, "classes": {},
	"width": {}, "height": {}, "size": {}, "color": {}, "background": {}, "border": {}, "margin": {}, "padding": {}, "layout": {},
	"detail": {}, "details": {}, "message": {}, "messages": {}, "status": {}, "notification": {}, "notifications": {}, "alert": {}, "badge": {}, "icon": {}, "icons": {}, "image": {}, "images": {},
	"avatar": {}, "card": {}, "tab": {}, "tabs": {}, "accordion": {}, "pagination": {}, "filter": {}, "filters": {}, "sort": {}, "search": {},
	"render": {}, "mount": {}, "unmount": {}, "change": {}, "click": {}, "press": {}, "hover": {}, "focus": {}, "blur": {},
	"valid": {}, "validate": {}, "validator": {}, "validation": {}, "invalid": {}, "required": {}, "schema": {},
	"props": {}, "children": {}, "parent": {}, "sibling": {}, "node": {}, "tree": {}, "branch": {},
	"custom": {}, "global": {}, "local": {}, "internal": {}, "external": {}, "public": {}, "private": {}, "protected": {},
	"main": {}, "base": {}, "root": {}, "core": {}, "util": {}, "utils": {}, "helper": {}, "helpers": {}, "common": {}, "shared": {},
	"string": {}, "number": {}, "boolean": {}, "array": {}, "object": {}, "function": {}, "symbol": {}, "matrix": {},
	"time": {}, "date": {}, "timer": {}, "interval": {}, "timeout": {}, "duration": {}, "delay": {}, "timestamp": {},
	"group": {}, "category": {}, "section": {}, "panel": {}, "block": {}, "box": {}, "grid": {}, "flex": {}, "stack": {},
}

// IsCodeIdentifierOrDictionaryWords returns true if s is a camelCase / snake_case
// identifier composed entirely of standard programming and English dictionary terms.
func IsCodeIdentifierOrDictionaryWords(s string) bool {
	// Only analyze alphanumeric identifiers (no special chars like -, ., /, +, =)
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}

	words := splitCamelCaseWords(s)
	if len(words) < 3 {
		return false
	}

	// Check if ALL words exist in our dictionary
	matchCount := 0
	for _, w := range words {
		lowerW := strings.ToLower(w)
		if _, ok := commonWordDict[lowerW]; ok {
			matchCount++
		}
	}

	return matchCount == len(words)
}
