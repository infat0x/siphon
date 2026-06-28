package collector

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)

var (
	// Matches basic chunk or bundle files like vendor.abcdef.js, main.js, 1.chunk.js
	deepJsLinkRe = regexp.MustCompile(`[a-zA-Z0-9_.\-]+\.js`)
	
	// Sometimes paths are in quotes e.g. "static/js/main.chunk.js"
	quotedPathRe = regexp.MustCompile(`["'](/[a-zA-Z0-9_.\-/\~]+\.js)["']`)
)

// ExtractDeepJS takes a list of initial JS files, downloads them, and looks for dynamic imports / chunks inside them.
func ExtractDeepJS(initialJsUrls []string) []string {
	if len(initialJsUrls) == 0 {
		return nil
	}
	
	var found []string
	var mu sync.Mutex

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		MaxIdleConns:    200,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	sem := make(chan struct{}, core.GlobalConfig.Threads)
	var wg sync.WaitGroup

	core.Logf("  %s→%s  Deep parsing %d JS files for chunks/dynamic imports...\n", core.MAGENTA, core.RESET, len(initialJsUrls))

	for _, urlStr := range initialJsUrls {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
				if err == nil && len(bodyBytes) > 0 {
					bodyStr := string(bodyBytes)
					
					// Get base URL for resolving relative links
					lastSlash := strings.LastIndex(target, "/")
					baseURL := target
					if lastSlash != -1 {
						baseURL = target[:lastSlash+1]
					}
					
					// Find simple file names like "0.chunk.js"
					matches := deepJsLinkRe.FindAllString(bodyStr, -1)
					
					// Find quoted paths like "/static/js/vendor.js"
					qMatches := quotedPathRe.FindAllStringSubmatch(bodyStr, -1)

					mu.Lock()
					for _, m := range matches {
						if !strings.HasPrefix(m, "http") {
							found = append(found, baseURL+m)
						}
					}
					for _, qm := range qMatches {
						if len(qm) > 1 {
							path := qm[1]
							if strings.HasPrefix(path, "/") {
								// Try to reconstruct domain root
								parts := strings.Split(baseURL, "/")
								if len(parts) >= 3 {
									root := parts[0] + "//" + parts[2]
									found = append(found, root+path)
								}
							}
						}
					}
					mu.Unlock()
				}
			}
		}(urlStr)
	}

	wg.Wait()
	
	// Also append the original URLs
	found = append(found, initialJsUrls...)
	
	return core.Dedup(found)
}

// CheckSourceMaps takes a list of JS URLs, checks if .js.map exists, and returns the live map URLs.
func CheckSourceMaps(jsUrls []string) []string {
	if len(jsUrls) == 0 {
		return nil
	}

	var liveMaps []string
	var mu sync.Mutex

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		MaxIdleConns:    200,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	sem := make(chan struct{}, core.GlobalConfig.Threads*2)
	var wg sync.WaitGroup

	core.Logf("  %s→%s  Checking for source maps (.js.map) on %d files...\n", core.MAGENTA, core.RESET, len(jsUrls))

	for _, urlStr := range jsUrls {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			mapUrl := target + ".map"
			
			req, err := http.NewRequest("HEAD", mapUrl, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				// Sometimes 403 indicates it exists but is forbidden, we still record it just in case
				if resp.StatusCode == 200 {
					mu.Lock()
					liveMaps = append(liveMaps, mapUrl)
					mu.Unlock()
				}
			}
		}(urlStr)
	}

	wg.Wait()
	return liveMaps
}
