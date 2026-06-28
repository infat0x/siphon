package collector

import (
	"crypto/tls"
	"io"
	"net/http"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)


var CommonJSPaths = []string{
	// ── Core config & generic roots ──
	"/app.js", "/main.js", "/index.js", "/config.js", "/env.js",
	"/settings.js", "/constants.js", "/api.js", "/utils.js",

	// ── Hidden / framework config variants ──
	"/env.production.js", "/config.production.js",
	"/static/js/main.js", "/assets/js/app.js", "/dist/app.js",

	// ── Framework manifests ──
	"/asset-manifest.json", "/precache-manifest.js",

	// ── Specific high-value endpoints ──
	"/js/app.js", "/js/main.js", "/js/config.js", "/js/api.js",
	"/admin/app.js", "/admin/js/app.js", "/admin/js/config.js",
	"/admin/main.js", "/api/v1/app.js", "/api/v2/app.js",
}

func BruteJSPaths(liveHosts []string, pathFilter string) []string {
	var found []string
	var mu sync.Mutex

	if pathFilter != "" {
		if strings.HasPrefix(pathFilter, "http") {
			// Extract path from full URL
			if strings.Count(pathFilter, "/") >= 3 {
				parts := strings.SplitN(pathFilter, "/", 4)
				if len(parts) > 3 {
					pathFilter = "/" + parts[3]
				} else {
					pathFilter = ""
				}
			} else {
				pathFilter = ""
			}
		}

		if pathFilter != "" && !strings.HasPrefix(pathFilter, "/") {
			pathFilter = "/" + pathFilter
		}
		pathFilter = strings.TrimRight(pathFilter, "/")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		MaxIdleConns:    200,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, core.GlobalConfig.Threads*2)
	var wg sync.WaitGroup

	core.Logf("  %s→%s  Brute-force %d common JS paths...\n", core.MAGENTA, core.RESET, len(CommonJSPaths))

	for _, host := range liveHosts {
		host = strings.TrimRight(host, "/")
		for _, path := range CommonJSPaths {
			fullPath := pathFilter + path
			wg.Add(1)
			go func(urlStr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Use GET instead of HEAD so we can read body for HTML if needed
				req, err := http.NewRequest("GET", urlStr, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0")
				resp, err := client.Do(req)
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						ct := resp.Header.Get("Content-Type")
						if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") || strings.HasSuffix(urlStr, ".js") {
							mu.Lock()
							found = append(found, urlStr)
							mu.Unlock()
						} else if strings.Contains(ct, "text/html") {
							bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
							if err == nil && len(bodyBytes) > 0 {
								htmlStr := string(bodyBytes)
								srcs := parseScriptTags(urlStr, htmlStr)
								if len(srcs) > 0 {
									mu.Lock()
									found = append(found, srcs...)
									mu.Unlock()
								}
							}
						}
					}
				}
			}(host + fullPath)
		}
	}

	wg.Wait()
	return found
}
