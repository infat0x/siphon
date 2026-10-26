package scanner

import (
	"fmt"
	"os"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
)

var interestingPatterns = map[string]*regexp.Regexp{
	"Swagger/OpenAPI": regexp.MustCompile(`(?i)(?:/swagger-ui\.html|/v[1-3]/api-docs|/api-docs|/swagger\.json|/swagger\.yaml)`),
	"GraphQL":         regexp.MustCompile(`(?i)(?:/graphql|/graphiql|/altair|/playground)`),
	"Internal API":    regexp.MustCompile(`(?i)(?:/api/v[1-9]/internal|/admin/api|/v[1-9]/dev)`),
	"Actuator/Debug":  regexp.MustCompile(`(?i)(?:/actuator/health|/actuator/env|/server-status|/phpinfo\.php|/_profiler)`),
	"Cloud Metadata":  regexp.MustCompile(`(?i)(?:169\.254\.169\.254|metadata\.google\.internal)`),
}

// ScanInterestingPaths looks for sensitive logic paths left in JS bundles.
func ScanInterestingPaths(dlMap map[string]string) []core.Finding {
	var findings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, core.GlobalConfig.Threads)

	for urlStr, filePath := range dlMap {
		if filePath == "" || filePath == "/dev/null" {
			continue
		}

		wg.Add(1)
		go func(u, f string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := os.ReadFile(f)
			if err != nil {
				return
			}
			content := string(data)

			for pType, re := range interestingPatterns {
				matches := re.FindAllStringIndex(content, 100)
				for _, m := range matches {
					matchStr := content[m[0]:m[1]]
					if strings.HasPrefix(matchStr, "/") || strings.Contains(matchStr, ".") {
						lineNum := strings.Count(content[:m[0]], "\n") + 1
						mu.Lock()
						findings = append(findings, core.Finding{
							Tool:       "InterestingPaths",
							Type:       pType,
							URL:        u,
							File:       f,
							Match:      matchStr,
							Line:       fmt.Sprintf("%d", lineNum),
							Severity:   "MEDIUM",
							Confidence: 80,
						})
						mu.Unlock()
					}
				}
			}
		}(urlStr, filePath)
	}

	wg.Wait()
	return findings
}
