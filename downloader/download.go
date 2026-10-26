package downloader

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"siphon-go/core"
	"strings"
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgents[time.Now().UnixNano()%int64(len(userAgents))])
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", urlStr)
	core.ApplyCustomHeaders(req)

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

	insecureTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 1000,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     10 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}

	if core.GlobalConfig.Proxy != "" {
		if proxyURL, err := url.Parse(core.GlobalConfig.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			insecureTransport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	insecureClient := &http.Client{
		Transport: insecureTransport,
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
				core.WaitRateLimit()
				finalPath, err := attemptDownload(client, urlStr, dlDir, &seenHashes)

				// Protocol Fallback: if primary attempt failed, try alternate protocol or insecure client
				if err != nil || finalPath == "" {
					fallbackURL := ""
					if strings.HasPrefix(urlStr, "https://") {
						fallbackURL = "http://" + strings.TrimPrefix(urlStr, "https://")
					} else if strings.HasPrefix(urlStr, "http://") {
						fallbackURL = "https://" + strings.TrimPrefix(urlStr, "http://")
					}
					
					var fallbackPath string
					var fallbackErr error
					
					if fallbackURL != "" {
						core.Debug("Fallback attempt (Alternate Protocol): %s -> %s", urlStr, fallbackURL)
						fallbackPath, fallbackErr = attemptDownload(client, fallbackURL, dlDir, &seenHashes)
					}
					
					if fallbackErr == nil && fallbackPath != "" {
						finalPath = fallbackPath
					} else {
						// Auto-Insecure Fallback for original URL
						core.Debug("Fallback attempt (Insecure TLS): %s", urlStr)
						insecurePath, insecureErr := attemptDownload(insecureClient, urlStr, dlDir, &seenHashes)
						if insecureErr == nil && insecurePath != "" {
							finalPath = insecurePath
						} else if fallbackURL != "" {
							// Auto-Insecure Fallback for alternate protocol
							core.Debug("Fallback attempt (Alternate Protocol + Insecure TLS): %s", fallbackURL)
							insecureFallbackPath, insecureFallbackErr := attemptDownload(insecureClient, fallbackURL, dlDir, &seenHashes)
							if insecureFallbackErr == nil && insecureFallbackPath != "" {
								finalPath = insecureFallbackPath
							} else {
								core.Debug("All fallbacks failed for %s", urlStr)
							}
						}
					}
				}

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
