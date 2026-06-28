package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"siphon-go/core"
	"sort"
	"strings"
	"time"
)

// WriteReport creates the final text and JSON reports with severity classification.
func WriteReport(allFindings []core.Finding, reportFile string, stats *core.Stats) {
	falsePosRe := regexp.MustCompile(FalsePositiveRe)

	var highConf []core.Finding
	for _, f := range allFindings {
		if len(f.Match) >= 12 && !falsePosRe.MatchString(f.Match) {
			highConf = append(highConf, f)
		}
	}
	highConf = core.DedupFindings(highConf)

	// Sort by severity priority, then by confidence descending
	severityOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "": 5}
	sort.Slice(highConf, func(i, j int) bool {
		si := severityOrder[highConf[i].Severity]
		sj := severityOrder[highConf[j].Severity]
		if si != sj {
			return si < sj
		}
		return highConf[i].Confidence > highConf[j].Confidence
	})

	// Count by severity
	sevCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range highConf {
		sev := f.Severity
		if sev == "" {
			sev = "INFO"
		}
		sevCounts[sev]++
	}

	// Count by tool
	toolCounts := make(map[string]int)
	for _, f := range highConf {
		toolCounts[f.Tool]++
	}

	byType := make(map[string][]core.Finding)
	for _, f := range highConf {
		byType[f.Type] = append(byType[f.Type], f)
	}

	sep := "══════════════════════════════════════════════════════════════════════"
	mode := "multi-subdomain"
	if stats.SingleDomain {
		mode = "single-domain"
	}
	tlsStr := "enabled"
	if core.GlobalConfig.Insecure {
		tlsStr = "disabled (--insecure)"
	}

	lines := []string{
		sep,
		"  SIPHON-GO  —  FINAL REPORT  (v7 Ultra)",
		fmt.Sprintf("  Generated      : %s", time.Now().Format("2006-01-02  15:04:05")),
		fmt.Sprintf("  Mode           : %s", mode),
		fmt.Sprintf("  TLS verify     : %s", tlsStr),
		fmt.Sprintf("  Live hosts     : %d", stats.Live),
		fmt.Sprintf("  URLs collected : %d", stats.Urls),
		fmt.Sprintf("  JS files total : %d", stats.JsAll),
		fmt.Sprintf("  JS custom      : %d", stats.JsCustom),
		fmt.Sprintf("  JS downloaded  : %d", stats.JsDl),
		fmt.Sprintf("  DL success     : %s", stats.DlRate),
		fmt.Sprintf("  Raw findings   : %d", len(allFindings)),
		fmt.Sprintf("  High-confidence: %d", len(highConf)),
		sep,
		"",
		"  SEVERITY BREAKDOWN",
		fmt.Sprintf("    CRITICAL : %-5d", sevCounts["CRITICAL"]),
		fmt.Sprintf("    HIGH     : %-5d", sevCounts["HIGH"]),
		fmt.Sprintf("    MEDIUM   : %-5d", sevCounts["MEDIUM"]),
		fmt.Sprintf("    LOW      : %-5d", sevCounts["LOW"]),
		fmt.Sprintf("    INFO     : %-5d", sevCounts["INFO"]),
		"",
		"  SCANNER RESULTS",
	}

	// Sort tools by count descending
	var toolNames []string
	for t := range toolCounts {
		toolNames = append(toolNames, t)
	}
	sort.Slice(toolNames, func(i, j int) bool {
		return toolCounts[toolNames[i]] > toolCounts[toolNames[j]]
	})

	for _, t := range toolNames {
		line := fmt.Sprintf("    - %-18s : %d findings", t, toolCounts[t])
		lines = append(lines, line)
	}
	lines = append(lines, "")

	if len(highConf) == 0 {
		lines = append(lines,
			"  No high-confidence secrets found.",
			"  ─ Check secrets/raw/  for all scanner output files.",
			"",
		)
	} else {
		// Group by severity for display
		severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
		for _, sev := range severities {
			var sevFindings []core.Finding
			for _, f := range highConf {
				fSev := f.Severity
				if fSev == "" {
					fSev = "INFO"
				}
				if fSev == sev {
					sevFindings = append(sevFindings, f)
				}
			}
			if len(sevFindings) == 0 {
				continue
			}

			sevLabel := sev

			lines = append(lines, fmt.Sprintf("--- %s (%d findings) %s", sevLabel, len(sevFindings), strings.Repeat("-", 40)))
			lines = append(lines, "")

			// Sub-group by type within severity
			subByType := make(map[string][]core.Finding)
			for _, f := range sevFindings {
				subByType[f.Type] = append(subByType[f.Type], f)
			}

			var types []string
			for t := range subByType {
				types = append(types, t)
			}
			sort.Slice(types, func(i, j int) bool {
				return len(subByType[types[i]]) > len(subByType[types[j]])
			})

			for _, stype := range types {
				items := subByType[stype]
				plural := ""
				if len(items) > 1 {
					plural = "s"
				}
				lines = append(lines, fmt.Sprintf("┌─  %s  (%d finding%s)", stype, len(items), plural))
				for _, item := range items {
					match := item.Match
					if len(match) > 150 {
						match = match[:150]
					}
					lines = append(lines,
						fmt.Sprintf("│   Tool       : %s", item.Tool),
						fmt.Sprintf("│   URL        : %s", item.URL),
						fmt.Sprintf("│   File       : %s", item.File),
						fmt.Sprintf("│   Line       : %s", item.Line),
						fmt.Sprintf("│   Entropy    : %s", item.Entropy),
						fmt.Sprintf("│   Confidence : %d%%", item.Confidence),
						fmt.Sprintf("│   Match      : %s", match),
					)
					if item.DecodedMatch != "" {
						decoded := item.DecodedMatch
						if len(decoded) > 150 {
							decoded = decoded[:150]
						}
						lines = append(lines, fmt.Sprintf("│   Decoded    : %s", decoded))
					}
					lines = append(lines, "│")
				}
				lines = append(lines, "")
			}
		}
	}

	os.WriteFile(reportFile, []byte(strings.Join(lines, "\n")), 0644)
	core.Logf("  %s[OK]%s report      %s%s%s\n", core.GREEN, core.RESET, core.BOLD, reportFile, core.RESET)
	core.Logf("  %s[OK]%s findings    %s%d%s\n", core.GREEN, core.RESET, core.BOLD, len(highConf), core.RESET)

	// Severity summary in console
	if sevCounts["CRITICAL"] > 0 {
		core.Logf("  %s[!!]%s critical    %d\n", core.RED, core.RESET, sevCounts["CRITICAL"])
	}
	if sevCounts["HIGH"] > 0 {
		core.Logf("  %s[!]%s  high        %d\n", core.YELLOW, core.RESET, sevCounts["HIGH"])
	}
	if sevCounts["MEDIUM"] > 0 {
		core.Logf("  %s[*]%s  medium      %d\n", core.YELLOW, core.RESET, sevCounts["MEDIUM"])
	}

	// Write JSON report
	jsonReportFile := strings.TrimSuffix(reportFile, filepath.Ext(reportFile)) + ".json"
	writeJSONReport(highConf, jsonReportFile, stats, sevCounts, toolCounts)
}

// writeJSONReport outputs findings as structured JSON
func writeJSONReport(findings []core.Finding, reportFile string, stats *core.Stats, sevCounts map[string]int, toolCounts map[string]int) {
	report := map[string]interface{}{
		"version":   "v7-ultra",
		"generated": time.Now().Format(time.RFC3339),
		"stats": map[string]interface{}{
			"live_hosts":     stats.Live,
			"urls_collected": stats.Urls,
			"js_total":       stats.JsAll,
			"js_custom":      stats.JsCustom,
			"js_downloaded":  stats.JsDl,
			"dl_rate":        stats.DlRate,
			"total_findings": len(findings),
		},
		"severity_counts": sevCounts,
		"tool_counts":     toolCounts,
		"findings":        findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		os.WriteFile(reportFile, data, 0644)
		core.Logf("  %s[OK]%s json        %s%s%s\n", core.GREEN, core.RESET, core.BOLD, reportFile, core.RESET)
	}
}
