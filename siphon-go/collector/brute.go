package collector

import (
	"crypto/tls"
	"net/http"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)

var CommonJSPaths = []string{
	"/app.js", "/main.js", "/index.js", "/bundle.js", "/init.js",
	"/config.js", "/settings.js", "/env.js", "/constants.js",
	"/api.js", "/utils.js", "/helpers.js", "/common.js", "/global.js",
	"/auth.js", "/router.js", "/routes.js", "/store.js", "/services.js",
	"/vendors.js", "/chunk.js", "/core.js", "/base.js",
	"/js/app.js", "/js/main.js", "/js/index.js", "/js/config.js",
	"/js/api.js", "/js/utils.js", "/js/helpers.js", "/js/auth.js",
	"/js/bundle.js", "/js/vendors.js",
	"/static/js/app.js", "/static/js/main.js", "/static/js/index.js", "/static/js/bundle.js",
	"/assets/js/app.js", "/assets/js/main.js", "/assets/js/config.js",
	"/assets/js/api.js", "/assets/js/utils.js", "/assets/application.js",
	"/dist/app.js", "/dist/main.js", "/dist/bundle.js", "/dist/index.js",
	"/build/app.js", "/build/main.js", "/build/bundle.js", "/build/static/js/main.js",
	"/public/js/app.js", "/public/js/main.js",
	"/src/app.js", "/src/main.js", "/src/index.js",
	"/scripts/app.js", "/scripts/main.js", "/scripts/bundle.js",
	"/app/app.js", "/app/main.js", "/admin/app.js", "/admin/main.js",
	"/v1/app.js", "/v2/app.js", "/api/config.js", "/api/v1/config.js",
	"/config/config.js", "/config/index.js", "/env.production.js",
	"/_next/static/chunks/main.js", "/_next/static/chunks/app-pages.js",
	"/_next/static/chunks/pages/_app.js", "/_next/static/chunks/webpack.js",
	"/_nuxt/app.js", "/_nuxt/entry.js",
	"/wp-content/themes/app.js", "/wp-includes/js/api.js",
	"/build/static/js/main.chunk.js", "/build/static/js/2.chunk.js",
	"/assets/index.js", "/assets/vendor.js",
}

func BruteJSPaths(liveHosts []string) []string {
	var found []string
	var mu sync.Mutex

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
			wg.Add(1)
			go func(urlStr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				req, err := http.NewRequest("HEAD", urlStr, nil)
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
						}
					}
				}
			}(host + path)
		}
	}

	wg.Wait()
	return found
}
