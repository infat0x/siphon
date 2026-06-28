package core

import "sync"

// Finding represents a single discovered secret or exposure.
type Finding struct {
	Tool         string `json:"tool"`
	Type         string `json:"type"`
	URL          string `json:"url"`
	File         string `json:"file"`
	Match        string `json:"match"`
	Line         string `json:"line"`
	Entropy      string `json:"entropy"`
	Context      string `json:"context,omitempty"`
	Severity     string `json:"severity,omitempty"`     // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Confidence   int    `json:"confidence,omitempty"`    // 0-100
	DecodedMatch string `json:"decoded_match,omitempty"` // Decoded value for base64/hex/url-encoded secrets
}

// Config holds global flags.
type Config struct {
	Insecure bool
	Threads  int
}

var GlobalConfig Config

// Stats tracks execution metrics safely.
type Stats struct {
	SingleDomain bool
	Live         int
	Urls         int
	JsAll        int
	JsCustom     int
	JsDl         int
	DlRate       string
	mu           sync.Mutex
}

func (s *Stats) SetLive(v int)      { s.mu.Lock(); defer s.mu.Unlock(); s.Live = v }
func (s *Stats) SetUrls(v int)      { s.mu.Lock(); defer s.mu.Unlock(); s.Urls = v }
func (s *Stats) SetJsAll(v int)     { s.mu.Lock(); defer s.mu.Unlock(); s.JsAll = v }
func (s *Stats) SetJsCustom(v int)  { s.mu.Lock(); defer s.mu.Unlock(); s.JsCustom = v }
func (s *Stats) SetJsDl(v int)      { s.mu.Lock(); defer s.mu.Unlock(); s.JsDl = v }
func (s *Stats) SetDlRate(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.DlRate = v }
