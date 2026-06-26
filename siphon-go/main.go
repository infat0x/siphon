package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"siphon-go/collector"
	"siphon-go/core"
	"siphon-go/downloader"
	"net/url"
	"siphon-go/scanner"
	"strings"
	"sync"

	"github.com/pterm/pterm"
)

func banner() {
	fmt.Printf("%s%s\n", core.MAGENTA, core.BOLD)
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
	pathFilter := flag.String("path", "", "Filter JS URLs by specific path (e.g. /admin/)")
	
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

	if *outDir == "" || (*domain == "" && *subs == "" && *jsUrl == "" && *pathFilter == "") {
		flag.Usage()
		os.Exit(1)
	}

	core.InitUI()
	defer core.StopUI()

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

	for _, p := range dirs {
		os.MkdirAll(p, 0755)
	}

	logDir := filepath.Join(*outDir, "logs")
	if err := core.InitLogger(logDir); err == nil {
		defer core.CloseLogger()
	} else {
		core.Logf("  %s⚠%s  Could not initialize debug logger: %v\n", core.YELLOW, core.RESET, err)
	}

	core.Logf("  %s→%s  Output root: %s%s%s\n", core.MAGENTA, core.RESET, core.BOLD, dirs["base"], core.RESET)

	var jsAll []string
	var jsCustom []string
	var live []string
	stats := &core.Stats{SingleDomain: *domain != "" || *jsUrl != ""}

	if *jsUrl != "" {
		// SINGLE JS URL MODE
		urlStr := core.NormaliseHost(*jsUrl)
		core.Logf("  %s→%s  Mode   : %ssingle-url%s  →  %s\n", core.MAGENTA, core.RESET, core.BOLD, core.RESET, urlStr)
		
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
			core.Logf("  %s→%s  Mode   : %ssingle-domain%s  →  %s\n", core.MAGENTA, core.RESET, core.BOLD, core.RESET, domainUrl)
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
			core.Logf("  %s→%s  Mode   : %ssingle-domain%s (extracted from path)  →  %s\n", core.MAGENTA, core.RESET, core.BOLD, core.RESET, domainUrl)
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
			core.Logf("  %s→%s  %s%d%s host(s) loaded\n", core.MAGENTA, core.RESET, core.BOLD, len(subsList), core.RESET)
		}

		// 1. Live Hosts
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
			pbHost = core.StartProgressBar(1, "1. Live Host Detection (Running httpx)")
			live = scanner.RunHttpx(*subs, liveFile)
			pbHost.Add(1)
		}

		stats.SetLive(len(live))
		if len(live) == 0 {
			core.Logln("No live hosts found")
			os.Exit(0)
		}
		
		core.Logf("  %s✔%s  1. Live Host Detection [%d hosts]\n", core.GREEN, core.RESET, len(live))

		// 2. URL Collection
		pbUrl, _ := pterm.DefaultProgressbar.WithTotal(7).WithTitle("2. URL Collection (Passive+Active)").WithWriter(core.Multi.NewWriter()).Start()
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
				{"Subjs", collector.RunSubjs},
				{"Cariddi", func(urls []string) []string {
					res, _ := collector.RunCariddi(urls)
					return res
				}},
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
			core.Logf("  %s✔%s  Total unique URLs    %s%d%s\n", core.GREEN, core.RESET, core.BOLD, len(allUrls), core.RESET)
		}
		stats.SetUrls(len(allUrls))
		core.Logf("  %s✔%s  2. URL Collection [%d URLs]\n", core.GREEN, core.RESET, len(allUrls))

		// 3. JS Extraction & Filter
		pbExtract, _ := pterm.DefaultProgressbar.WithTotal(2).WithTitle("3. JS Extraction").WithWriter(core.Multi.NewWriter()).Start()
		
		var jsSet []string

		if *pathFilter != "" {
			core.Logf("\n  %s→%s  Path Filter active: Scraping HTML of specific path directly for JS targets...\n", core.MAGENTA, core.RESET)
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
		core.Logf("  %s✔%s  3. JS Extraction [%d custom, %d all]\n", core.GREEN, core.RESET, len(jsCustom), len(jsAll))
	} // end else mode

	if *skipDownload {
		core.Logln("Stopping after JS extraction.")
		os.Exit(0)
	}

	targets := jsCustom
	if *scanAllJs {
		targets = jsAll
	}

	if len(targets) == 0 {
		core.Logln("No JS targets.")
		os.Exit(0)
	}

	dlPb := core.StartProgressBar(len(targets), "4. Downloading JS")

	dlMap := downloader.DownloadJS(targets, dirs["dl"], *threads, dlPb)
	
	stats.SetJsDl(len(dlMap))
	stats.SetDlRate(fmt.Sprintf("%.1f%%", 100.0*float64(len(dlMap))/float64(len(targets))))
	
	scanner.CheckGitExposure(live, dirs["git"], *threads)

	pbScan, _ := pterm.DefaultProgressbar.WithTotal(6).WithTitle("5. Secret Scanning").WithWriter(core.Multi.NewWriter()).Start()

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

	runScanner("Regex", func() []core.Finding { return scanner.ScanRegex(dlMap) })
	runScanner("Trufflehog", func() []core.Finding { return scanner.ScanTrufflehog(dirs["dl"], dirs["raw"]) })
	runScanner("Gitleaks", func() []core.Finding { return scanner.ScanGitleaks(dirs["dl"], dirs["raw"]) })
	runScanner("Gf", func() []core.Finding { return scanner.ScanGf(dlMap, dirs["raw"]) })
	runScanner("Jsleak", func() []core.Finding { return scanner.ScanJsleak(dlMap, dirs["raw"]) })
	runScanner("Jsluice", func() []core.Finding { return scanner.ScanJsluice(dlMap, dirs["raw"]) })
	runScanner("Nuclei", func() []core.Finding { return scanner.ScanNuclei(targets, dirs["raw"]) })

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

	core.Logf("  %s✔%s  5. Secret Scanning [%d total findings]\n", core.GREEN, core.RESET, len(allFindings))

	scanner.WriteReport(allFindings, filepath.Join(dirs["secrets"], "final_report.txt"), stats)
}
