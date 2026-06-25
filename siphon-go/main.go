package main

import (
	"flag"
	"fmt"
	"log"
	"siphon-go/collector"
	"siphon-go/core"
	"siphon-go/downloader"
	"siphon-go/scanner"
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
	fmt.Printf("%s   v6  •  Siphon-Go  •  Native Go downloader%s\n\n", core.DIM, core.RESET)
}

func main() {
	domain := flag.String("domain", "", "Single domain to scan")
	subs := flag.String("subs", "", "Path to subdomains list")
	outDir := flag.String("o", "out", "Output directory")
	threads := flag.Int("t", 30, "Concurrent threads")
	insecure := flag.Bool("insecure", false, "Disable TLS verification")
	flag.Parse()

	banner()

	if *domain == "" && *subs == "" {
		log.Fatal("Must provide -domain or -subs")
	}

	core.GlobalConfig = core.Config{
		Insecure: *insecure,
		Threads:  *threads,
	}

	fmt.Printf("Starting Siphon-Go to %s\n", *outDir)
	
	var urls []string
	if *domain != "" {
		urls = collector.RunGau(*domain)
		urls = append(urls, collector.RunKatana(*domain)...)
		urls = append(urls, collector.RunWaybackurls(*domain)...)
	}

	urls = core.Dedup(urls)
	fmt.Printf("Collected %d URLs\n", len(urls))

	var jsUrls []string
	for _, u := range urls {
		if len(u) > 3 && u[len(u)-3:] == ".js" {
			jsUrls = append(jsUrls, u)
		}
	}
	customJs := downloader.FilterJS(jsUrls)
	fmt.Printf("Found %d JS files, %d custom JS files\n", len(jsUrls), len(customJs))

	dlMap := downloader.DownloadJS(customJs, *outDir, *threads)
	fmt.Printf("Downloaded %d JS files successfully\n", len(dlMap))

	findings := scanner.ScanRegex(dlMap)
	fmt.Printf("Regex Scanner found %d secrets\n", len(findings))
}
