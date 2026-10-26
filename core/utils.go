package core

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ANSI Colors
const (
	RESET     = "\033[0m"
	BOLD      = "\033[1m"
	DIM       = "\033[2m"
	UNDERLINE = "\033[4m"
	
	// Foreground Colors
	RED       = "\033[91m"
	GREEN     = "\033[92m"
	YELLOW    = "\033[93m"
	BLUE      = "\033[94m"
	MAGENTA   = "\033[95m"
	CYAN      = "\033[96m"
	WHITE     = "\033[97m"

	// Background Colors
	BG_RED    = "\033[41m"
	BG_GREEN  = "\033[42m"
	BG_YELLOW = "\033[43m"
	BG_BLUE   = "\033[44m"
	BG_MAGENTA= "\033[45m"
	BG_CYAN   = "\033[46m"
)

func Dedup(slice []string) []string {
	seen := make(map[string]struct{})
	var res []string
	for _, val := range slice {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			res = append(res, val)
		}
	}
	return res
}

func DedupFindings(lst []Finding) []Finding {
	seen := make(map[string]struct{})
	var out []Finding
	for _, f := range lst {
		matchClean := strings.TrimSpace(f.Match)
		key := fmt.Sprintf("%s|%s|%s", f.Type, f.URL, matchClean)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}

func NormaliseHost(host string) string {
	host = strings.TrimSpace(host)
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	return strings.TrimRight(host, "/")
}

func BareDomain(host string) string {
	host = NormaliseHost(host)
	u, err := url.Parse(host)
	if err == nil && u.Host != "" {
		return u.Host
	}
	h := strings.ReplaceAll(host, "https://", "")
	h = strings.ReplaceAll(h, "http://", "")
	return strings.TrimRight(h, "/")
}

func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		prob := count / length
		entropy -= prob * math.Log2(prob)
	}
	return entropy
}

func SHA256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

var htmlErrorRe = regexp.MustCompile(`(?i)<html|<!doctype\s+html|<title>4\d{2}|<title>5\d{2}|Access Denied|403 Forbidden|404 Not Found|<body`)

func IsValidJS(content []byte) bool {
	length := 512
	if len(content) < length {
		length = len(content)
	}
	head := string(content[:length])
	return !htmlErrorRe.MatchString(head)
}

// GetHTTPTransport returns an http.Transport configured with TLS settings and Proxy if specified.
func GetHTTPTransport() *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: GlobalConfig.Insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	if GlobalConfig.Proxy != "" {
		if proxyURL, err := url.Parse(GlobalConfig.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return tr
}

// GetHTTPClient returns an http.Client with configured transport and specified timeout.
func GetHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: GetHTTPTransport(),
		Timeout:   timeout,
	}
}

// WaitRateLimit pauses execution if GlobalConfig.Delay is configured.
func WaitRateLimit() {
	if GlobalConfig.Delay > 0 {
		time.Sleep(time.Duration(GlobalConfig.Delay) * time.Millisecond)
	}
}

// ApplyCustomHeaders attaches all user-defined headers from GlobalConfig to an HTTP request.
func ApplyCustomHeaders(req *http.Request) {
	if req == nil {
		return
	}
	for _, h := range GlobalConfig.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

// CheckAuthStatus probes targetURL with the configured custom headers.
// It returns (true, statusText) when authenticated, or (false, statusText) when unauthenticated.
func CheckAuthStatus(targetURL string) (bool, string) {
	if len(GlobalConfig.Headers) == 0 {
		return false, "UNAUTH (no credentials)"
	}
	if strings.TrimSpace(targetURL) == "" {
		return false, "UNAUTH (no target)"
	}

	targetURL = NormaliseHost(targetURL)

	tr := GetHTTPTransport()

	var redirectedToLogin bool

	client := &http.Client{
		Transport: tr,
		Timeout:   7 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			loc := strings.ToLower(req.URL.String())
			if strings.Contains(loc, "login") ||
				strings.Contains(loc, "signin") ||
				strings.Contains(loc, "sign-in") ||
				strings.Contains(loc, "oauth") ||
				strings.Contains(loc, "auth.") ||
				strings.Contains(loc, "cognito") ||
				strings.Contains(loc, "okta") ||
				strings.Contains(loc, "/auth/") {
				redirectedToLogin = true
				return http.ErrUseLastResponse
			}
			ApplyCustomHeaders(req)
			return nil
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false, fmt.Sprintf("UNAUTH (error: %v)", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	ApplyCustomHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		// Fallback to HTTP if HTTPS failed
		if strings.HasPrefix(targetURL, "https://") {
			httpURL := "http://" + strings.TrimPrefix(targetURL, "https://")
			if reqHTTP, errHTTP := http.NewRequest("GET", httpURL, nil); errHTTP == nil {
				reqHTTP.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
				reqHTTP.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				ApplyCustomHeaders(reqHTTP)
				if respHTTP, errHTTPResp := client.Do(reqHTTP); errHTTPResp == nil {
					resp = respHTTP
					err = nil
				}
			}
		}
		if err != nil {
			return false, "UNAUTH (connection failed)"
		}
	}
	defer resp.Body.Close()

	if redirectedToLogin {
		return false, "UNAUTH (redirected to login)"
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return false, "UNAUTH (HTTP 401 Unauthorized)"
	}
	if resp.StatusCode == http.StatusForbidden {
		return false, "UNAUTH (HTTP 403 Forbidden)"
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := strings.ToLower(resp.Header.Get("Location"))
		if strings.Contains(loc, "login") ||
			strings.Contains(loc, "signin") ||
			strings.Contains(loc, "sign-in") ||
			strings.Contains(loc, "oauth") ||
			strings.Contains(loc, "auth.") ||
			strings.Contains(loc, "cognito") ||
			strings.Contains(loc, "okta") ||
			strings.Contains(loc, "/auth/") {
			return false, "UNAUTH (redirected to login)"
		}
	}

	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	bodySnippet := strings.ToLower(string(buf[:n]))

	if strings.Contains(bodySnippet, "<title>sign in</title>") ||
		strings.Contains(bodySnippet, "<title>login</title>") ||
		strings.Contains(bodySnippet, "<title>log in</title>") ||
		strings.Contains(bodySnippet, "action=\"/login") ||
		strings.Contains(bodySnippet, "action=\"/signin") {
		return false, "UNAUTH (login page detected)"
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, fmt.Sprintf("AUTH (HTTP %d OK)", resp.StatusCode)
	}

	return false, fmt.Sprintf("UNAUTH (HTTP %d)", resp.StatusCode)
}
