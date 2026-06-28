package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"siphon-go/collector"
	"siphon-go/core"
	"siphon-go/downloader"
	"net/url"
	"siphon-go/scanner"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

// requiredTools lists all external CLI tools that siphon-go depends on.
var requiredTools = []string{
	"katana", "gau", "hakrawler", "waybackurls", "subjs",
	"nuclei", "trufflehog", "gitleaks", "jsluice", "cariddi",
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
			rows = append(rows, []string{"❌", tool, "Missing"})
		} else {
			rows = append(rows, []string{"✅", tool, "OK"})
		}
	}

	// Print the status table
	fmt.Println()
	for _, r := range rows {
		fmt.Printf("  %s  %-20s %s\n", r[0], r[1], r[2])
	}
	fmt.Println()

	if len(missing) == 0 {
		core.PrintSuccess("All dependencies found")
		core.PrintDivider()
		return
	}

	// Some tools are missing — prompt user
	core.PrintWarning(fmt.Sprintf("%d/%d tools missing: %s", len(missing), len(requiredTools), strings.Join(missing, ", ")))
	fmt.Print("  ⚠️  Some required tools are missing. Do you want to continue anyway? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response != "y" && response != "yes" {
		core.PrintError("Exiting — please install missing tools first.")
		os.Exit(0)
	}

	core.PrintSuccess("Continuing with missing tools...")
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
		core.Logf("  %s⚠%s  Could not initialize debug logger: %v\n", core.YELLOW, core.RESET, err)
	}

	core.PrintResult("📂", "Output", dirs["base"], "")
	core.PrintDivider()

	var jsAll []string
	var jsCustom []string
	var live []string
	stats := &core.Stats{SingleDomain: *domain != "" || *jsUrl != ""}

	if *jsUrl != "" {
		// SINGLE JS URL MODE
		urlStr := core.NormaliseHost(*jsUrl)
		core.PrintResult("🎯", "Mode", "single-url", "\033[38;5;39m")
		core.PrintResult("🌐", "Target", urlStr, "\033[38;5;51m")
		
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
			core.PrintResult("🎯", "Mode", "single-domain", "\033[38;5;39m")
			core.PrintResult("🌐", "Target", domainUrl, "\033[38;5;51m")
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
			core.PrintResult("🎯", "Mode", "single-domain (extracted)", "\033[38;5;39m")
			core.PrintResult("🌐", "Target", domainUrl, "\033[38;5;51m")
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
			core.PrintResult("📜", "Loaded hosts", len(subsList), "")
		}

		// 1. Live Hosts
		core.PrintSection(1, 5, "Live Host Detection")
		var pbHost *pterm.ProgressbarPrinter
		liveFile := filepath.Join(dirs["live"], "live.txt")

		if *skipLiveCheck {
			pbHost = core.StartProgressBar(1, "1. Live Host Detection")
			if data, err := os.ReadFile(liveFile); err == nil {
				for _, l := range strings.Split(string(data), "\n") {
					l = strings.TrimSpace(l)
					if l != "" {
						live = append(live, l)
					}
				}
			}
			core.Logf("\n[1/5] Skipped httpx — %d hosts from live.txt\n", len(live))
			pbHost.Add(1)
		} else if singleDomain {
			pbHost = core.StartProgressBar(1, "1. Live Host Detection")
			live = subsList
			os.WriteFile(liveFile, []byte(strings.Join(live, "\n")+"\n"), 0644)
			core.Logf("\n[1/5] Single-domain mode — skipping httpx probe\n")
			pbHost.Add(1)
		} else {
			pbHost = core.StartProgressBar(1, "Live Host Detection (Running httpx)")
			live = scanner.RunHttpx(*subs, liveFile)
			pbHost.Add(1)
		}

		stats.SetLive(len(live))
		if len(live) == 0 {
			core.PrintError("No live hosts found")
			os.Exit(0)
		}
		
		core.PrintSuccess(fmt.Sprintf("Live Host Detection complete [%d hosts]", len(live)))

		// 2. URL Collection
		core.PrintSection(2, 5, "URL Collection (Passive+Active)")
		pbUrl, _ := pterm.DefaultProgressbar.WithTotal(7).WithTitle("Collection").WithWriter(core.Multi.NewWriter()).Start()
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
			pbUrl.Add(7)
			core.Logf("\n[2/5] Skipped collection — %d URLs loaded\n", len(allUrls))
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
					if pbUrl != nil {
						pbUrl.Add(1)
					}
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
				if pbUrl != nil {
					pbUrl.Add(1)
				}
			}()

			wg.Wait()

			allUrls = core.Dedup(allUrls)
			os.WriteFile(urlsFile, []byte(strings.Join(allUrls, "\n")+"\n"), 0644)
			core.PrintResult("🔗", "Unique URLs", len(allUrls), "\033[38;5;220m")
		}
		stats.SetUrls(len(allUrls))
		core.PrintSuccess(fmt.Sprintf("URL Collection complete [%d URLs]", len(allUrls)))

		// 3. JS Extraction & Filter
		core.PrintSection(3, 5, "JavaScript Extraction")
		pbExtract, _ := pterm.DefaultProgressbar.WithTotal(2).WithTitle("Extraction").WithWriter(core.Multi.NewWriter()).Start()
		
		var jsSet []string

		if *pathFilter != "" {
			core.Logf("\n  %s→%s  %sPath Filter active:%s Scraping HTML of %s%s%s directly for JS targets...\n", core.CYAN, core.RESET, core.BOLD, core.RESET, core.YELLOW, *pathFilter, core.RESET)
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
			pbExtract.Add(1)

			bruteUrls := collector.BruteJSPaths(live, *pathFilter)
			jsSet = append(jsSet, bruteUrls...)
			pbExtract.Add(1)
		} else {
			for _, u := range allUrls {
				lu := strings.ToLower(u)
				if strings.HasSuffix(lu, ".js") || strings.Contains(lu, ".js?") || strings.Contains(lu, ".js#") {
					jsSet = append(jsSet, u)
				}
			}
			pbExtract.Add(1)

			bruteUrls := collector.BruteJSPaths(live, "")
			jsSet = append(jsSet, bruteUrls...)
			pbExtract.Add(1)
		}

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
	
	stats.SetJsDl(len(dlMap))
	stats.SetDlRate(fmt.Sprintf("%.1f%%", 100.0*float64(len(dlMap))/float64(len(targets))))
	
	core.PrintSuccess(fmt.Sprintf("Download complete [%d files]", len(dlMap)))

	scanner.CheckGitExposure(live, dirs["git"], *threads)

	core.PrintScanEngineStart(14)
	core.PrintSection(5, 5, "Secret Scanning")
	
	pbScan, _ := pterm.DefaultProgressbar.WithTotal(14).WithTitle("Scanning").WithWriter(core.Multi.NewWriter()).Start()

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
			if pbScan != nil {
				pbScan.Add(1)
			}
			sp.Success(fmt.Sprintf("%s finished (%d findings)", name, len(res)))
		}()
	}

	logDir = dirs["logs"]

	runScanner("Regex", func() []core.Finding { return scanner.ScanRegex(dlMap) })
	runScanner("Trufflehog", func() []core.Finding { return scanner.ScanTrufflehog(dirs["dl"], dirs["raw"], logDir) })
	runScanner("Gitleaks", func() []core.Finding { return scanner.ScanGitleaks(dirs["dl"], dirs["raw"], logDir) })
	runScanner("Jsleak", func() []core.Finding { return scanner.ScanJsleak(dlMap, dirs["raw"], logDir) })
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
	scanner.WriteReport(allFindings, filepath.Join(dirs["secrets"], "final_report.txt"), stats)

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
	core.PrintFinalStats(len(allFindings), critical, high, medium, time.Since(scanStart))
}
