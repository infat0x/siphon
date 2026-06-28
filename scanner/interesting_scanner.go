package scanner

import (
	"bufio"
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
		if filePath == "/dev/null" {
			continue
		}

		wg.Add(1)
		go func(u, f string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			file, err := os.Open(f)
			if err != nil {
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			// Ensure we can read long minified lines
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024*10)

			lineNum := 1
			for scanner.Scan() {
				line := scanner.Text()
				
				// Quick length check to prevent hanging on massive non-string blocks
				if len(line) > 50000 {
					continue
				}

				for pType, re := range interestingPatterns {
					matches := re.FindAllString(line, -1)
					for _, m := range matches {
						// Filter out obvious false positives where the word is just a generic string 
						// (Usually these will be standalone paths, so we check for slash boundaries)
						if strings.HasPrefix(m, "/") || strings.Contains(m, ".") {
							mu.Lock()
							findings = append(findings, core.Finding{
								Tool:       "InterestingPaths",
								Type:       pType,
								URL:        u,
								File:       f,
								Match:      m,
								Line:       fmt.Sprintf("%d", lineNum),
								Severity:   "MEDIUM", // Typically an exposure, not a direct credential compromise
								Confidence: 80,
							})
							mu.Unlock()
						}
					}
				}
				lineNum++
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Scanner error on file %s: %v\n", f, err)
			}
		}(urlStr, filePath)
	}

	wg.Wait()
	return findings
}
