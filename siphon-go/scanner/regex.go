package scanner

import (
	"fmt"
	"os"
	"regexp"
	"siphon-go/core"
	"strings"
)

func ScanRegex(dlMap map[string]string) []core.Finding {
	var findings []core.Finding
	falsePosRe := regexp.MustCompile(FalsePositiveRe)

	compiled := make(map[string]*regexp.Regexp)
	for name, pat := range SecretPatterns {
		compiled[name] = regexp.MustCompile(pat)
	}

	for url, filepath := range dlMap {
		if filepath == "" || filepath == "/dev/null" {
			continue
		}
		data, err := os.ReadFile(filepath)
		if err != nil {
			continue
		}
		content := string(data)

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

				findings = append(findings, core.Finding{
					Tool:    "regex",
					Type:    name,
					URL:     url,
					Entropy: fmt.Sprintf("%.2f", entropy),
					File:    filepath,
					Match:   snippet,
					Context: contextStr,
					Line:    fmt.Sprintf("%d", lineNum),
				})
			}
		}
	}
	return findings
}
