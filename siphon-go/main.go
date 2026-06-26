package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"siphon-go/collector"
	"siphon-go/core"
	"siphon-go/downloader"
	"siphon-go/scanner"
	"strings"
	"sync"
)

func banner() {
	fmt.Printf("%s%s\n", core.CYAN, core.BOLD)
	fmt.Println("   =========================================================")
	fmt.Println("  //                                                       \\\\")
	fmt.Println(" ||   ███████╗██╗██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗        ||")
	fmt.Println(" ||   ██╔════╝██║██╔══██╗██║  ██║██╔═══██╗████╗  ██║        ||")
	fmt.Println(" ||   ███████╗██║██████╔╝███████║██║   ██║██╔██╗ ██║        ||")
	fmt.Println(" ||   ╚════██║██║██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║        ||")
	fmt.Println(" ||   ███████║██║██║     ██║  ██║╚██████╔╝██║ ╚████║        ||")
	fmt.Println(" ||   ╚══════╝╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝        ||")
	fmt.Println("  \\\\=======================================================//")
	fmt.Printf("%s   v6  •  Siphon-Go  •  Full 1-to-1 Native Port%s\n\n", core.DIM, core.RESET)
}

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
	
	flag.Usage = func() {
		banner()
		fmt.Fprintf(os.Stderr, "Description:\n")
		fmt.Fprintf(os.Stderr, "  Siphon is an advanced JS harvester and secret scanner.\n")
		fmt.Fprintf(os.Stderr, "  It uses multiple collectors to find hidden assets and scans them with powerful heuristics.\n\n")
		
		fmt.Fprintf(os.Stderr, "Usage Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -domain example.com -o results\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -s subdomains.txt -o results -t 50\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://example.com/app.js -o results\n\n", os.Args[0])
		
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	
	flag.Parse()

	if *outDir == "" || (*domain == "" && *subs == "" && *jsUrl == "") {
		flag.Usage()
		os.Exit(1)
	}

	core.InitUI()
	core.UI.Start()
	defer core.UI.Stop()

	banner()

	if *insecure {
		core.Logf("  %s⚠%s  --insecure active — TLS certificate errors will be ignored.\n", core.YELLOW, core.RESET)
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

	for _, d := range dirs {
		os.MkdirAll(d, 0755)
	}

	core.Logf("  %s→%s  Output root: %s%s%s\n", core.CYAN, core.RESET, core.BOLD, dirs["base"], core.RESET)

	var jsAll []string
	var jsCustom []string
	var live []string
	stats := &core.Stats{SingleDomain: *domain != "" || *jsUrl != ""}

	if *jsUrl != "" {
		// SINGLE JS URL MODE
		urlStr := core.NormaliseHost(*jsUrl)
		core.Logf("  %s→%s  Mode   : %ssingle-url%s  →  %s\n", core.CYAN, core.RESET, core.BOLD, core.RESET, urlStr)
		
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
			core.Logf("  %s→%s  Mode   : %ssingle-domain%s  →  %s\n", core.CYAN, core.RESET, core.BOLD, core.RESET, domainUrl)
		} else if *subs != "" {
			data, err := os.ReadFile(*subs)
			if err != nil {
				core.Logf("File not found: %s\n", *subs)
				os.Exit(1)
			}
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(l)
				if l != "" {
					subsList = append(subsList, l)
				}
			}
			core.Logf("  %s→%s  %s%d%s host(s) loaded\n", core.CYAN, core.RESET, core.BOLD, len(subsList), core.RESET)
		}

		// 1. Live Hosts
		core.UI.UpdateStage(0, core.StageRunning, "")
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
			core.Logf("\n[1/5] Skipped httpx — %d hosts from live.txt\n", len(live))
		} else if singleDomain {
			live = []string{core.NormaliseHost(*domain)}
			os.WriteFile(liveFile, []byte(strings.Join(live, "\n")+"\n"), 0644)
			core.Logf("\n[1/5] Single-domain mode — skipping httpx probe\n")
		} else {
			live = scanner.RunHttpx(*subs, liveFile)
		}

		stats.SetLive(len(live))
		if len(live) == 0 {
			core.Logln("No live hosts found. Exiting.")
			os.Exit(0)
		}
		
		core.UI.UpdateStage(0, core.StageDone, fmt.Sprintf("%d hosts", len(live)))

		// 2. URL Collection
		core.UI.UpdateStage(1, core.StageRunning, "")
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
			core.Logf("\n[2/5] Skipped collection — %d URLs loaded\n", len(allUrls))
		} else {
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, *threads)

			for _, host := range live {
				tools := []func(string) []string{
					collector.RunGau, collector.RunKatana, collector.RunWaybackurls,
					collector.RunHakrawler, collector.RunSubjs,
				}
				for _, t := range tools {
					wg.Add(1)
					go func(tool func(string) []string, h string) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()
						res := tool(h)
						mu.Lock()
						allUrls = append(allUrls, res...)
						mu.Unlock()
					}(t, host)
				}
			}
			wg.Wait()

			scripts := collector.ActiveHTMLScrape(live)
			allUrls = append(allUrls, scripts...)

			for _, host := range live {
				cUrls, _ := collector.RunCariddi(host)
				allUrls = append(allUrls, cUrls...)
			}

			allUrls = core.Dedup(allUrls)
			os.WriteFile(urlsFile, []byte(strings.Join(allUrls, "\n")+"\n"), 0644)
			core.Logf("  %s✔%s  Total unique URLs    %s%d%s\n", core.GREEN, core.RESET, core.BOLD, len(allUrls), core.RESET)
		}
		stats.SetUrls(len(allUrls))
		core.UI.UpdateStage(1, core.StageDone, fmt.Sprintf("%d URLs", len(allUrls)))

		// 3. JS Extraction & Filter
		core.UI.UpdateStage(2, core.StageRunning, "")
		
		var jsSet []string
		for _, u := range allUrls {
			lu := strings.ToLower(u)
			if strings.HasSuffix(lu, ".js") || strings.Contains(lu, ".js?") || strings.Contains(lu, ".js#") {
				jsSet = append(jsSet, u)
			}
		}

		bruteUrls := collector.BruteJSPaths(live)
		jsSet = append(jsSet, bruteUrls...)

		jsAll = core.Dedup(jsSet)
		jsCustom = downloader.FilterJS(jsAll)

		os.WriteFile(filepath.Join(dirs["js"], "js_urls.txt"), []byte(strings.Join(jsAll, "\n")+"\n"), 0644)
		os.WriteFile(filepath.Join(dirs["js"], "custom_js.txt"), []byte(strings.Join(jsCustom, "\n")+"\n"), 0644)

		stats.SetJsAll(len(jsAll))
		stats.SetJsCustom(len(jsCustom))
		core.UI.UpdateStage(2, core.StageDone, fmt.Sprintf("%d custom, %d all", len(jsCustom), len(jsAll)))
	} // end else mode

	if *skipDownload {
		core.Logln("Stopping after JS extraction.")
		os.Exit(0)
	}

	core.UI.UpdateStage(3, core.StageRunning, "")

	targets := jsCustom
	if *scanAllJs {
		targets = jsAll
	}

	if len(targets) == 0 {
		core.Logln("No JS targets.")
		os.Exit(0)
	}

	dlMap := downloader.DownloadJS(targets, dirs["dl"], *threads, nil)
	
	stats.SetJsDl(len(dlMap))
	stats.SetDlRate(fmt.Sprintf("%.1f%%", 100.0*float64(len(dlMap))/float64(len(targets))))
	
	core.UI.UpdateStage(3, core.StageDone, fmt.Sprintf("%d files", len(dlMap)))

	scanner.CheckGitExposure(live, dirs["git"], *threads)

	core.UI.UpdateStage(4, core.StageRunning, "")
	core.UI.UpdateProgress(4, 0, 7)

	var allFindings []core.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	var completedScanners int

	runScanner := func(name string, f func() []core.Finding) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := f()
			mu.Lock()
			allFindings = append(allFindings, res...)
			completedScanners++
			core.UI.UpdateProgress(4, completedScanners, 7)
			mu.Unlock()
			core.Logf("  %s✔%s  %-16s %5d findings\n", core.GREEN, core.RESET, name, len(res))
		}()
	}

	runScanner("regex", func() []core.Finding { return scanner.ScanRegex(dlMap) })
	runScanner("trufflehog", func() []core.Finding { return scanner.ScanTrufflehog(dirs["dl"], dirs["raw"]) })
	runScanner("gitleaks", func() []core.Finding { return scanner.ScanGitleaks(dirs["dl"], dirs["raw"]) })
	runScanner("gf", func() []core.Finding { return scanner.ScanGf(dlMap, dirs["raw"]) })
	runScanner("jsleak", func() []core.Finding { return scanner.ScanJsleak(dlMap, dirs["raw"]) })
	runScanner("jsluice", func() []core.Finding { return scanner.ScanJsluice(dlMap, dirs["raw"]) })
	runScanner("nuclei", func() []core.Finding { return scanner.ScanNuclei(targets, dirs["raw"]) })

	wg.Wait()
	core.UI.UpdateStage(4, core.StageDone, fmt.Sprintf("%d total findings", len(allFindings)))

	scanner.WriteReport(allFindings, filepath.Join(dirs["secrets"], "final_report.txt"), stats)
}
