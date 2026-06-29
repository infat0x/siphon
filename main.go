package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"siphon-go/collector"
	"siphon-go/core"
	"siphon-go/downloader"
	"net/url"
	"siphon-go/scanner"
	"github.com/joho/godotenv"
	"strings"
	"sync"
	"time"
)

// requiredTools lists all external CLI tools that siphon-go depends on.
var requiredTools = []string{
	"katana", "gau", "hakrawler", "waybackurls", "subjs",
	"nuclei", "trufflehog", "gitleaks", "jsluice", "cariddi",
	"httpx", "mantra",
}

// checkAIAccess sends a test request to the OpenAI API to verify the API key is valid.
func checkAIAccess(key string) bool {
	apiURL := os.Getenv("AI_API_URL")
	if apiURL == "" {
		apiURL = "https://api.openai.com/v1/chat/completions"
	}

	// Send a minimal request. If we get 401, the key is bad. 
	// If we get 200, 400 (bad format), or 404 (model not found), the API is reachable.
	body := `{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "test"}], "max_tokens": 1}`
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+key)
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// 401 and 403 mean the key is definitely invalid or blocked.
	return resp.StatusCode != 401 && resp.StatusCode != 403
}

// CheckDependencies verifies all required tools are in $PATH.
// Prints status for each tool and prompts the user if any are missing.
func CheckDependencies() {
	var missing []string
	var rows [][]string

	for _, tool := range requiredTools {
		_, err := exec.LookPath(tool)
		if err != nil {
			missing = append(missing, tool)
			rows = append(rows, []string{"[-]", tool, "missing"})
		} else {
			rows = append(rows, []string{"[+]", tool, "ok"})
		}
	}

	// Check AI
	apiKey := os.Getenv("AI_API_KEY")
	if apiKey == "" {
		missing = append(missing, "AI (AI_API_KEY)")
		rows = append(rows, []string{"[-]", "AI (AI_API_KEY)", "missing"})
	} else if !checkAIAccess(apiKey) {
		missing = append(missing, "AI (Invalid API Key or Unreachable)")
		rows = append(rows, []string{"[-]", "AI (AI_API_KEY)", "invalid/unreachable"})
	} else {
		rows = append(rows, []string{"[+]", "AI (AI_API_KEY)", "ok"})
	}

	// Print the status table
	fmt.Println()
	for _, r := range rows {
		fmt.Printf("  %s  %-25s %s\n", r[0], r[1], r[2])
	}
	fmt.Println()

	if len(missing) == 0 {
		core.PrintSuccess("All required tools and AI are ready.")
		fmt.Print("  Do you want to continue? [y/N]: ")
	} else {
		core.PrintWarning(fmt.Sprintf("The following tools are missing: %s", strings.Join(missing, ", ")))
		core.PrintWarning("Please run install_tools.sh (and/or check your .env file).")
		fmt.Print("  Do you still want to continue? [y/N]: ")
	}

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response != "y" && response != "yes" {
		core.PrintError("Exiting...")
		os.Exit(0)
	}

	core.PrintSuccess("Continuing...")
	core.PrintDivider()
}

// banner is now handled by core.PrintBanner()

func main() {
	domain := flag.String("domain", "", "Single domain to scan")
	subs := flag.String("s", "", "Path to subdomains list")
	jsUrl := flag.String("url", "", "Single JS file URL to scan directly")
	outDir := flag.String("o", "", "Output directory (required)")
	threads := flag.Int("t", 30, "Concurrent threads")
	insecure := flag.Bool("insecure", false, "Disable TLS verification")
	scanAllJs := flag.Bool("scan-all-js", false, "Scan ALL JS files including known libs")
	skipLiveCheck := flag.Bool("skip-live-check", false, "Skip httpx")
	skipUrlCollection := flag.Bool("skip-url-collection", false, "Skip URL harvest")
	skipDownload := flag.Bool("skip-download", false, "Stop after JS extraction")
	pathFilter := flag.String("path", "", "Filter JS URLs by specific path (e.g. /admin/)")
	
	flag.Usage = func() {
		core.PrintBanner()
		fmt.Fprintf(os.Stderr, "  %sDescription:%s\n", core.BOLD, core.RESET)
		fmt.Fprintf(os.Stderr, "  Siphon is an advanced JS harvester and secret scanner.\n")
		fmt.Fprintf(os.Stderr, "  14 scan engines find hidden secrets with ultra precision.\n\n")
		
		fmt.Fprintf(os.Stderr, "  %sUsage:%s\n", core.BOLD, core.RESET)
		fmt.Fprintf(os.Stderr, "    %s -domain example.com -o results\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    %s -s subdomains.txt -o results -t 50\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    %s -url https://example.com/app.js -o results\n\n", os.Args[0])
		
		fmt.Fprintf(os.Stderr, "  %sFlags:%s\n", core.BOLD, core.RESET)
		flag.PrintDefaults()
		fmt.Println()
	}
	
	flag.Parse()

	if *outDir == "" || (*domain == "" && *subs == "" && *jsUrl == "" && *pathFilter == "") {
		flag.Usage()
		os.Exit(1)
	}

	core.InitUI()
	defer core.StopUI()

	core.PrintBanner()

	// Load .env from multiple locations (it won't overwrite existing vars, so order is priority)
	_ = godotenv.Load() // 1. Current working directory

	if exePath, err := os.Executable(); err == nil {
		_ = godotenv.Load(filepath.Join(filepath.Dir(exePath), ".env")) // 2. Binary directory
	}

	if home, err := os.UserHomeDir(); err == nil {
		_ = godotenv.Load(filepath.Join(home, ".siphon.env")) // 3. Home directory
	}

	// Pre-flight: check all required tool dependencies
	CheckDependencies()

	scanStart := time.Now()

	if *insecure {
		core.PrintWarning("--insecure active — TLS certificate errors will be ignored")
	}

	core.GlobalConfig = core.Config{
		Insecure: *insecure,
		Threads:  *threads,
	}

	dirs := map[string]string{
		"base":    *outDir,
		"live":    filepath.Join(*outDir, "live"),
		"urls":    filepath.Join(*outDir, "urls"),
		"js":      filepath.Join(*outDir, "js"),
		"dl":      filepath.Join(*outDir, "js", "downloaded"),
		"secrets": filepath.Join(*outDir, "secrets"),
		"raw":     filepath.Join(*outDir, "secrets", "raw"),
		"logs":    filepath.Join(*outDir, "logs"),
		"git":     filepath.Join(*outDir, "git_dumps"),
	}

	for _, p := range dirs {
		os.MkdirAll(p, 0755)
	}

	logDir := filepath.Join(*outDir, "logs")
	if err := core.InitLogger(logDir); err == nil {
		defer core.CloseLogger()
	} else {
		core.Logf("  %s[WARN]%s could not initialize debug logger: %v\n", core.YELLOW, core.RESET, err)
	}

	core.PrintResult("", "output", dirs["base"], "")
	core.PrintDivider()

	var jsAll []string
	var jsCustom []string
	var live []string
	stats := &core.Stats{SingleDomain: *domain != "" || *jsUrl != ""}

	if *jsUrl != "" {
		// SINGLE JS URL MODE
		urlStr := core.NormaliseHost(*jsUrl)
		core.PrintResult("", "mode", "single-url", "")
		core.PrintResult("", "target", urlStr, "")
		
		jsAll = []string{urlStr}
		jsCustom = []string{urlStr}
		live = []string{urlStr}
		
		stats.SetUrls(1)
		stats.SetLive(1)
		stats.SetJsAll(1)
		stats.SetJsCustom(1)

		os.WriteFile(filepath.Join(dirs["js"], "js_urls.txt"), []byte(urlStr+"\n"), 0644)
		os.WriteFile(filepath.Join(dirs["js"], "custom_js.txt"), []byte(urlStr+"\n"), 0644)
		
	} else {
		// NORMAL DOMAIN OR SUBS MODE
		var singleDomain bool
		var subsList []string

		if *domain != "" {
			singleDomain = true
			domainUrl := core.NormaliseHost(*domain)
			tmpSubs := filepath.Join(*outDir, "_domain_input.txt")
			os.WriteFile(tmpSubs, []byte(domainUrl+"\n"), 0644)
			subsList = []string{domainUrl}
			core.PrintResult("", "mode", "single-domain", "")
			core.PrintResult("", "target", domainUrl, "")
		} else if *pathFilter != "" && strings.HasPrefix(*pathFilter, "http") {
			// Extract domain from URL provided in pathFilter to run scan
			singleDomain = true
			
			u, err := url.Parse(*pathFilter)
			domainUrl := *pathFilter
			if err == nil {
				domainUrl = u.Scheme + "://" + u.Host
			}

			domainUrl = core.NormaliseHost(domainUrl)
			tmpSubs := filepath.Join(*outDir, "_domain_input.txt")
			os.WriteFile(tmpSubs, []byte(domainUrl+"\n"), 0644)
			subsList = []string{domainUrl}
			core.PrintResult("", "mode", "single-domain (extracted)", "")
			core.PrintResult("", "target", domainUrl, "")
		} else if *subs != "" {
			data, err := os.ReadFile(*subs)
			if err != nil {
				core.PrintError(fmt.Sprintf("File not found: %s", *subs))
				os.Exit(1)
			}
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(l)
				if l != "" {
					subsList = append(subsList, l)
				}
			}
			core.PrintResult("", "loaded hosts", len(subsList), "")
		}

		// 1. Live Hosts
		core.PrintSection(1, 5, "Live Host Detection")
		liveFile := filepath.Join(dirs["live"], "live.txt")
		if *skipLiveCheck {
			if data, err := os.ReadFile(liveFile); err == nil {
				for _, l := range strings.Split(string(data), "\n") {
					l = strings.TrimSpace(l)
					if l != "" {
						live = append(live, l)
					}
				}
			}
			core.Logf("  %s>%s skipped httpx — %d hosts loaded\n", core.DIM, core.RESET, len(live))
		} else if singleDomain {
			live = subsList
			os.WriteFile(liveFile, []byte(strings.Join(live, "\n")+"\n"), 0644)
			core.Logf("  %s>%s single-domain mode — skipping httpx probe\n", core.DIM, core.RESET)
		} else {
			core.Logf("  %s>%s running httpx...\n", core.DIM, core.RESET)
			live = scanner.RunHttpx(*subs, liveFile)
		}

		stats.SetLive(len(live))

		if len(live) == 0 {
			core.PrintError("No live hosts found")
			os.Exit(0)
		}
		
		core.PrintSuccess(fmt.Sprintf("Live Host Detection complete [%d hosts]", len(live)))

		// 2. URL Collection
		core.PrintSection(2, 5, "URL Collection (Passive+Active)")
		urlsFile := filepath.Join(dirs["urls"], "all_urls.txt")
		var allUrls []string

		if *skipUrlCollection {
			if data, err := os.ReadFile(urlsFile); err == nil {
				for _, l := range strings.Split(string(data), "\n") {
					l = strings.TrimSpace(l)
					if l != "" {
						allUrls = append(allUrls, l)
					}
				}
			}
			core.Logf("  %s>%s skipped collection — %d URLs loaded\n", core.DIM, core.RESET, len(allUrls))
		} else {
			var mu sync.Mutex
			var wg sync.WaitGroup

			tools := []struct {
				name string
				fn   func([]string) []string
			}{
				{"Gau", collector.RunGau},
				{"Katana", collector.RunKatana},
				{"Waybackurls", collector.RunWaybackurls},
				{"Hakrawler", collector.RunHakrawler},
			}

			for _, t := range tools {
				wg.Add(1)
				go func(name string, tool func([]string) []string) {
					defer wg.Done()
					sp := core.StartSpinner(fmt.Sprintf("Running %s...", name))
					res := tool(live)
					sp.Success(fmt.Sprintf("%s finished (%d URLs)", name, len(res)))
					
					mu.Lock()
					allUrls = append(allUrls, res...)
					mu.Unlock()
				}(t.name, t.fn)
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				sp := core.StartSpinner("Running Active HTML Scrape...")
				res := collector.ActiveHTMLScrape(live)
				sp.Success(fmt.Sprintf("Active HTML Scrape finished (%d URLs)", len(res)))
				
				mu.Lock()
				allUrls = append(allUrls, res...)
				mu.Unlock()
			}()

			wg.Wait()

			allUrls = core.Dedup(allUrls)
			os.WriteFile(urlsFile, []byte(strings.Join(allUrls, "\n")+"\n"), 0644)
			core.PrintResult("", "unique urls", len(allUrls), "")
		}
		stats.SetUrls(len(allUrls))
		core.PrintSuccess(fmt.Sprintf("URL Collection complete [%d URLs]", len(allUrls)))

		// 3. JS Extraction & Filter
		core.PrintSection(3, 5, "JavaScript Extraction")
		
		var jsSet []string

		if *pathFilter != "" {
			core.Logf("\n  %s>%s %spath filter active:%s scraping %s%s%s for JS targets...\n", core.CYAN, core.RESET, core.BOLD, core.RESET, core.YELLOW, *pathFilter, core.RESET)
			var targetPaths []string
			if strings.HasPrefix(*pathFilter, "http") {
				targetPaths = append(targetPaths, *pathFilter)
			} else {
				for _, h := range live {
					h = strings.TrimRight(h, "/")
					p := *pathFilter
					if !strings.HasPrefix(p, "/") {
						p = "/" + p
					}
					targetPaths = append(targetPaths, h+p)
				}
			}
			
			jsSet = append(jsSet, collector.ActiveHTMLScrape(targetPaths)...)

			bruteUrls := collector.BruteJSPaths(live, *pathFilter)
			jsSet = append(jsSet, bruteUrls...)
		} else {
			for _, u := range allUrls {
				lu := strings.ToLower(u)
				if strings.HasSuffix(lu, ".js") || strings.Contains(lu, ".js?") || strings.Contains(lu, ".js#") {
					jsSet = append(jsSet, u)
				}
			}

			// Deep parse the initial passive JS links to find chunks/dynamic imports
			deepJs := collector.ExtractDeepJS(jsSet)
			jsSet = append(jsSet, deepJs...)

			// Small targeted brute force on live endpoints
			bruteUrls := collector.BruteJSPaths(live, "")
			jsSet = append(jsSet, bruteUrls...)
		}

		// Clean up formatting
		jsSet = core.Dedup(jsSet)

		// Discover live source maps
		sourceMaps := collector.CheckSourceMaps(jsSet)
		jsSet = append(jsSet, sourceMaps...)

		jsAll = core.Dedup(jsSet)
		jsCustom = downloader.FilterJS(jsAll)

		os.WriteFile(filepath.Join(dirs["js"], "js_urls.txt"), []byte(strings.Join(jsAll, "\n")+"\n"), 0644)
		os.WriteFile(filepath.Join(dirs["js"], "custom_js.txt"), []byte(strings.Join(jsCustom, "\n")+"\n"), 0644)

		stats.SetJsAll(len(jsAll))
		stats.SetJsCustom(len(jsCustom))
	} // end else mode

	if *skipDownload {
		core.Logln("Stopping after JS extraction.")
		os.Exit(0)
	}

	targets := jsCustom
	if *scanAllJs {
		targets = jsAll
	}
	core.PrintSuccess(fmt.Sprintf("JS Extraction complete [%d all / %d custom]", len(jsAll), len(jsCustom)))

	// 4. Download JS
	core.PrintSection(4, 5, "Downloading JavaScript Files")
	dlPb := core.StartProgressBar(len(targets), "Downloading")

	dlMap := downloader.DownloadJS(targets, dirs["dl"], *threads, dlPb)
	if dlPb != nil {
		dlPb.Stop()
	}
	
	stats.SetJsDl(len(dlMap))
	stats.SetDlRate(fmt.Sprintf("%.1f%%", 100.0*float64(len(dlMap))/float64(len(targets))))
	
	core.PrintSuccess(fmt.Sprintf("Download complete [%d files]", len(dlMap)))

	scanner.CheckGitExposure(live, dirs["git"], *threads)

	core.PrintScanEngineStart(15)
	core.PrintSection(5, 5, "Secret Scanning")

	var allFindings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	runScanner := func(name string, f func() []core.Finding) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sp := core.StartSpinner(fmt.Sprintf("Scanning with %s...", name))
			res := f()
			
			mu.Lock()
			allFindings = append(allFindings, res...)
			mu.Unlock()
			sp.Success(fmt.Sprintf("%-16s finished (%d findings)", name, len(res)))
		}()
	}

	logDir = dirs["logs"]

	runScanner("Regex", func() []core.Finding { return scanner.ScanRegex(dlMap) })
	runScanner("Trufflehog", func() []core.Finding { return scanner.ScanTrufflehog(dirs["dl"], dirs["raw"], logDir) })
	runScanner("Gitleaks", func() []core.Finding { return scanner.ScanGitleaks(dirs["dl"], dirs["raw"], logDir) })
	runScanner("Jsluice", func() []core.Finding { return scanner.ScanJsluice(dlMap, dirs["raw"], logDir) })
	runScanner("Cariddi", func() []core.Finding { return scanner.ScanCariddi(dlMap, dirs["raw"], logDir) })
	runScanner("Subjs", func() []core.Finding { return scanner.ScanSubjs(dlMap, dirs["raw"], logDir) })
	runScanner("Nuclei", func() []core.Finding { return scanner.ScanNuclei(targets, dirs["raw"], logDir) })

	// ── New Native Engines ────────────────────────────────────────────────
	runScanner("Entropy", func() []core.Finding { return scanner.ScanEntropy(dlMap) })
	runScanner("Base64/Encoded", func() []core.Finding { return scanner.ScanBase64(dlMap) })
	runScanner("InlineAssign", func() []core.Finding { return scanner.ScanInlineAssign(dlMap) })
	runScanner("SourceMaps", func() []core.Finding { return scanner.ScanSourceMaps(dlMap, dirs["raw"]) })
	runScanner("ConfigLeaks", func() []core.Finding { return scanner.ScanConfigLeaks(live, dlMap, dirs["raw"]) })
	runScanner("Mantra", func() []core.Finding { return scanner.ScanMantra(dlMap, dirs["raw"], logDir) })
	runScanner("InterestingPaths", func() []core.Finding { return scanner.ScanInterestingPaths(dlMap) })

	wg.Wait()
	reverseMap := make(map[string]string)
	for u, p := range dlMap {
		if p != "/dev/null" {
			reverseMap[filepath.Base(p)] = u
		}
	}

	for i := range allFindings {
		fFile := filepath.Base(allFindings[i].File)
		if origURL, ok := reverseMap[fFile]; ok {
			allFindings[i].URL = origURL
		}
	}

	// Secret Scanning old log removed; PrintFinalStats will show the final stats.
	reportPath, _ := filepath.Abs(filepath.Join(dirs["secrets"], "final_report.txt"))
	scanner.WriteReport(allFindings, reportPath, stats)

	// Count severities for final stats
	critical, high, medium := 0, 0, 0
	for _, f := range allFindings {
		switch f.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}
	core.PrintFinalStats(len(allFindings), critical, high, medium, time.Since(scanStart), reportPath)

	// Interactive AI Prompt
	fmt.Println()
	core.PrintWarning("WARNING: Analyzing the report with AI will send the found secrets to AI servers!")
	fmt.Printf("  [?] Do you still want to analyze with AI? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))

	if ans == "y" || ans == "yes" {
		aiOutputPath := filepath.Join(dirs["secrets"], "ai_summary.txt")
		core.AnalyzeReportWithAI(allFindings, aiOutputPath)
	}
}
