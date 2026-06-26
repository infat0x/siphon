package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
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
		matchPart := f.Match
		if len(matchPart) > 80 {
			matchPart = matchPart[:80]
		}
		key := fmt.Sprintf("%s|%s", f.Type, matchPart)
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


