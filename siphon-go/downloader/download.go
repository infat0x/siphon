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

var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 128*1024) // 128KB buffer for faster I/O
		return &b
	},
}

func attemptDownload(client *http.Client, urlStr, dlDir string, seenHashes *sync.Map) (string, error) {
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
		core.Debug("Download failed for %s with status %d", urlStr, resp.StatusCode)
		return "", fmt.Errorf("status code: %d", resp.StatusCode)
	}

	head := make([]byte, 512)
	n, err := io.ReadFull(resp.Body, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		core.Debug("Failed reading head for %s: %v", urlStr, err)
		return "", err
	}

	if n < 50 || !core.IsValidJS(head[:n]) {
		core.Debug("Invalid JS or too small for %s (size %d)", urlStr, n)
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
	
	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)

	_, err = io.CopyBuffer(out, reader, *bufPtr)
	if err != nil {
		os.Remove(tempFpath)
		return "", err
	}

	hashStr := hex.EncodeToString(hasher.Sum(nil))

	if _, loaded := seenHashes.LoadOrStore(hashStr, struct{}{}); loaded {
		os.Remove(tempFpath) // Delete duplicate
		return "/dev/null", nil
	}

	finalFpath := filepath.Join(dlDir, fmt.Sprintf("%s_download.js", uid))
	os.Rename(tempFpath, finalFpath)

	return finalFpath, nil
}

func DownloadJS(urls []string, dlDir string, threads int, pb *pterm.ProgressbarPrinter) map[string]string {
	var downloaded sync.Map
	var seenHashes sync.Map

	// Set MaxConnsPerHost to 0 (unlimited) or at least `threads` so we don't bottleneck
	// when downloading many files from the same target server.
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 1000,
		MaxConnsPerHost:     0, // 0 means no limit
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	urlChan := make(chan string, len(urls))
	for _, u := range urls {
		urlChan <- u
	}
	close(urlChan)

	var wg sync.WaitGroup
	
	// Create exactly `threads` number of workers
	workerCount := threads
	if workerCount > len(urls) {
		workerCount = len(urls)
	}

	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for urlStr := range urlChan {
				finalPath, _ := attemptDownload(client, urlStr, dlDir, &seenHashes)

				if finalPath != "" {
					downloaded.Store(urlStr, finalPath)
				}

				if pb != nil {
					pb.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	result := make(map[string]string)
	downloaded.Range(func(key, value interface{}) bool {
		result[key.(string)] = value.(string)
		return true
	})
	return result
}
