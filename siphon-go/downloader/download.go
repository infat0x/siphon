package downloader

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"siphon-go/core"
	"sync"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
}

func fetch(client *http.Client, urlStr string) ([]byte, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgents[time.Now().UnixNano()%int64(len(userAgents))])
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 15*1024*1024))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func DownloadJS(urls []string, dlDir string, threads int) map[string]string {
	downloaded := make(map[string]string)
	var mu sync.Mutex
	seenHashes := make(map[string]struct{})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
	}

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, u := range urls {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var data []byte
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				data, err = fetch(client, urlStr)
				if err == nil && len(data) > 50 && core.IsValidJS(data) {
					break
				}
				time.Sleep(time.Duration(1<<attempt) * time.Second)
			}

			if data != nil && len(data) > 50 && core.IsValidJS(data) {
				hash := core.SHA256(data)
				mu.Lock()
				if _, ok := seenHashes[hash]; ok {
					downloaded[urlStr] = "/dev/null"
					mu.Unlock()
					return
				}
				seenHashes[hash] = struct{}{}
				mu.Unlock()

				uid := core.SHA256([]byte(urlStr))[:6]
				fname := fmt.Sprintf("%s_download.js", uid)
				fpath := filepath.Join(dlDir, fname)
				os.WriteFile(fpath, data, 0644)

				mu.Lock()
				downloaded[urlStr] = fpath
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return downloaded
}
