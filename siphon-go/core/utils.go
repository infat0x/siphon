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
	RESET   = "\033[0m"
	BOLD    = "\033[1m"
	GREEN   = "\033[92m"
	YELLOW  = "\033[93m"
	RED     = "\033[91m"
	CYAN    = "\033[96m"
	DIM     = "\033[2m"
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

// ProgressBar implementation
type ProgressBar struct {
	Total     int32
	Current   int32
	StartTime time.Time
	Message   string
	stop      chan struct{}
}

func NewProgressBar(total int, msg string) *ProgressBar {
	return &ProgressBar{
		Total:     int32(total),
		Message:   msg,
		StartTime: time.Now(),
		stop:      make(chan struct{}),
	}
}

func (p *ProgressBar) Start() {
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.render()
			case <-p.stop:
				p.render()
				fmt.Println()
				return
			}
		}
	}()
}

func (p *ProgressBar) Increment() {
	atomic.AddInt32(&p.Current, 1)
}

func (p *ProgressBar) Stop() {
	close(p.stop)
}

func (p *ProgressBar) render() {
	cur := atomic.LoadInt32(&p.Current)
	tot := atomic.LoadInt32(&p.Total)
	if tot == 0 {
		return
	}

	percent := float64(cur) / float64(tot) * 100.0
	elapsed := time.Since(p.StartTime).Seconds()

	var timeLeft string
	if cur > 0 {
		totalEstimated := elapsed / (float64(cur) / float64(tot))
		left := totalEstimated - elapsed
		if left < 0 {
			left = 0
		}
		timeLeft = fmt.Sprintf("%.0fs left", left)
	} else {
		timeLeft = "calculating..."
	}

	barLen := 30
	filled := int(float64(barLen) * (float64(cur) / float64(tot)))
	if filled > barLen {
		filled = barLen
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)

	// Use \r to overwrite line, and \033[K to clear to end of line
	fmt.Printf("\r  %s%s%s %s [%d/%d] %.1f%% • %s \033[K", CYAN, p.Message, RESET, bar, cur, tot, percent, timeLeft)
}
