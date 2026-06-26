package downloader

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"siphon-go/core"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
}

func attemptDownload(client *http.Client, urlStr, dlDir string, seenHashes map[string]struct{}, mu *sync.Mutex) (string, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgents[time.Now().UnixNano()%int64(len(userAgents))])
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code: %d", resp.StatusCode)
	}

	head := make([]byte, 512)
	n, err := io.ReadFull(resp.Body, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", err
	}

	if n < 50 || !core.IsValidJS(head[:n]) {
		return "", fmt.Errorf("invalid JS or too small")
	}

	uid := core.SHA256([]byte(urlStr))[:6]
	tempFpath := filepath.Join(dlDir, fmt.Sprintf("%s_temp.js", uid))
	out, err := os.Create(tempFpath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	hasher := sha256.New()
	hasher.Write(head[:n])
	out.Write(head[:n])

	reader := io.TeeReader(io.LimitReader(resp.Body, 15*1024*1024-int64(n)), hasher)
	_, err = io.Copy(out, reader)
	if err != nil {
		os.Remove(tempFpath)
		return "", err
	}

	hashStr := hex.EncodeToString(hasher.Sum(nil))

	mu.Lock()
	if _, ok := seenHashes[hashStr]; ok {
		mu.Unlock()
		os.Remove(tempFpath) // Delete duplicate
		return "/dev/null", nil
	}
	seenHashes[hashStr] = struct{}{}
	mu.Unlock()

	finalFpath := filepath.Join(dlDir, fmt.Sprintf("%s_download.js", uid))
	os.Rename(tempFpath, finalFpath)

	return finalFpath, nil
}

func DownloadJS(urls []string, dlDir string, threads int, pb *pterm.ProgressbarPrinter) map[string]string {
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
			defer func() {
				if pb != nil {
					pb.Add(1)
				}
			}()

			var finalPath string
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				finalPath, err = attemptDownload(client, urlStr, dlDir, seenHashes, &mu)
				if err == nil {
					break
				}
				time.Sleep(time.Duration(1<<attempt) * time.Second)
			}

			if finalPath != "" && finalPath != "/dev/null" {
				mu.Lock()
				downloaded[urlStr] = finalPath
				mu.Unlock()
			} else if finalPath == "/dev/null" {
				mu.Lock()
				downloaded[urlStr] = "/dev/null"
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return downloaded
}
