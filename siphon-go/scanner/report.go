package scanner

import (
	"fmt"
	"os"
	"regexp"
	"siphon-go/core"
	"sort"
	"strings"
	"time"
)

func WriteReport(allFindings []core.Finding, reportFile string, stats *core.Stats) {
	falsePosRe := regexp.MustCompile(FalsePositiveRe)

	var highConf []core.Finding
	for _, f := range allFindings {
		if len(f.Match) >= 12 && !falsePosRe.MatchString(f.Match) {
			highConf = append(highConf, f)
		}
	}
	highConf = core.DedupFindings(highConf)

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
		"  SIPHON-GO  —  FINAL REPORT  (v6)",
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
		sep, "",
	}

	if len(highConf) == 0 {
		lines = append(lines,
			"  No high-confidence secrets found.",
			"  ─ Check secrets/raw/regex_findings.json   for regex scanner output.",
			"  ─ Check secrets/raw/trufflehog.json        for TruffleHog output.",
			"  ─ Check secrets/raw/gitleaks.json          for Gitleaks output.",
			"  ─ Check secrets/raw/jsluice_findings.json  for jsluice output.",
			"  ─ Check secrets/raw/jsleak_findings.txt    for jsleak output.",
			"  ─ Check secrets/raw/nuclei_findings.json   for Nuclei exposure output.",
			"  ─ Check cariddi_secrets.json               for cariddi findings.",
			"  ─ Check git_dumps/                         for dumped .git repositories.",
			"",
		)
	} else {
		var types []string
		for t := range byType {
			types = append(types, t)
		}
		sort.Slice(types, func(i, j int) bool {
			return len(byType[types[i]]) > len(byType[types[j]])
		})

		for _, stype := range types {
			items := byType[stype]
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
					fmt.Sprintf("│   Tool    : %s", item.Tool),
					fmt.Sprintf("│   URL     : %s", item.URL),
					fmt.Sprintf("│   File    : %s", item.File),
					fmt.Sprintf("│   Line    : %s", item.Line),
					fmt.Sprintf("│   Entropy : %s", item.Entropy),
					fmt.Sprintf("│   Match   : %s", match),
					"│",
				)
			}
			lines = append(lines, "")
		}
	}

	os.WriteFile(reportFile, []byte(strings.Join(lines, "\n")), 0644)
	core.Logf("  %s✔%s  Report           →  %s%s%s\n", core.GREEN, core.RESET, core.BOLD, reportFile, core.RESET)
	core.Logf("  %s✔%s  High-confidence findings : %s%d%s\n", core.GREEN, core.RESET, core.BOLD, len(highConf), core.RESET)
}
