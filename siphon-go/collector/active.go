package collector

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)

var (
	scriptRe         = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	inlineAbsoluteRe = regexp.MustCompile(`(https?://[a-zA-Z0-9.\-/_]+/[a-zA-Z0-9.\-_]+\.js(?:\?[a-zA-Z0-9=&_\.\-]+)?)`)
	inlineRelativeRe = regexp.MustCompile(`['"](/[a-zA-Z0-9.\-/_]+\.js(?:\?[a-zA-Z0-9=&_\.\-]+)?)['"]`)
)

func parseScriptTags(baseURL string, html string) []string {
	var srcs []string

	matches := scriptRe.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if !strings.HasPrefix(m[1], "data:") {
			srcs = append(srcs, strings.TrimSpace(m[1]))
		}
	}

	matchesAbs := inlineAbsoluteRe.FindAllStringSubmatch(html, -1)
	for _, m := range matchesAbs {
		srcs = append(srcs, m[1])
	}
	matchesRel := inlineRelativeRe.FindAllStringSubmatch(html, -1)
	for _, m := range matchesRel {
		srcs = append(srcs, m[1])
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	var out []string
	seen := make(map[string]struct{})

	for _, src := range srcs {
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}

		if strings.HasPrefix(src, "//") {
			src = parsed.Scheme + ":" + src
		} else if !strings.HasPrefix(src, "http") {
			relUrl, err := url.Parse(src)
			if err != nil {
				continue
			}
			src = parsed.ResolveReference(relUrl).String()
		}
		out = append(out, src)
	}

	return out
}

func ActiveHTMLScrape(liveHosts []string) []string {
	var found []string
	var mu sync.Mutex

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	sem := make(chan struct{}, core.GlobalConfig.Threads)
	var wg sync.WaitGroup

	for _, host := range liveHosts {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", urlStr, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
			if err != nil {
				return
			}

			srcs := parseScriptTags(urlStr, string(body))

			mu.Lock()
			found = append(found, srcs...)
			mu.Unlock()

		}(host)
	}

	wg.Wait()
	return core.Dedup(found)
}
