package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)

// ValidateGitHubToken tests whether a GitHub token is active and returns identity info.
func ValidateGitHubToken(token string) (bool, string) {
	client := core.GetHTTPClient(8 * time.Second)
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "siphon-scanner")

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		var data map[string]interface{}
		login := "active"
		if json.Unmarshal(body, &data) == nil {
			if l, ok := data["login"].(string); ok {
				login = l
			}
		}
		return true, fmt.Sprintf("GitHub user: %s (HTTP 200)", login)
	}
	return false, ""
}

// ValidateSlackToken tests whether a Slack API token is active.
func ValidateSlackToken(token string) (bool, string) {
	client := core.GetHTTPClient(8 * time.Second)
	req, err := http.NewRequest("POST", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var data map[string]interface{}
	if json.Unmarshal(body, &data) == nil {
		if ok, _ := data["ok"].(bool); ok {
			team := fmt.Sprintf("%v", data["team"])
			user := fmt.Sprintf("%v", data["user"])
			return true, fmt.Sprintf("Slack workspace: %s | User: %s", team, user)
		}
	}
	return false, ""
}

// ValidateStripeKey tests whether a Stripe API key is active.
func ValidateStripeKey(key string) (bool, string) {
	client := core.GetHTTPClient(8 * time.Second)
	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return false, ""
	}
	basicAuth := base64.StdEncoding.EncodeToString([]byte(key + ":"))
	req.Header.Set("Authorization", "Basic "+basicAuth)

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, "Stripe API Key active (balance accessible)"
	}
	return false, ""
}

// ValidateGoogleAPIKey tests whether a Google API Key is valid and active on Maps Geocode API.
func ValidateGoogleAPIKey(key string) (bool, string) {
	client := core.GetHTTPClient(8 * time.Second)
	reqURL := "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=" + url.QueryEscape(key)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return false, ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var data map[string]interface{}
	if json.Unmarshal(body, &data) == nil {
		status, _ := data["status"].(string)
		if status == "OK" || status == "ZERO_RESULTS" {
			return true, fmt.Sprintf("Google Maps API active (status: %s)", status)
		}
	}
	return false, ""
}

// ValidateSendGridKey tests whether a SendGrid API Key is valid.
func ValidateSendGridKey(key string) (bool, string) {
	client := core.GetHTTPClient(8 * time.Second)
	req, err := http.NewRequest("GET", "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, "SendGrid API Key active (scopes verified)"
	}
	return false, ""
}

// ValidateNPMToken tests whether an NPM token is valid.
func ValidateNPMToken(token string) (bool, string) {
	client := core.GetHTTPClient(8 * time.Second)
	req, err := http.NewRequest("GET", "https://registry.npmjs.org/-/whoami", nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		var data map[string]interface{}
		user := "active"
		if json.Unmarshal(body, &data) == nil {
			if u, ok := data["username"].(string); ok {
				user = u
			}
		}
		return true, fmt.Sprintf("NPM user: %s (HTTP 200)", user)
	}
	return false, ""
}

// ValidateFinding attempts to actively verify a candidate secret finding.
func ValidateFinding(f *core.Finding) {
	match := strings.TrimSpace(f.Match)

	// Clean quotes if present
	match = strings.Trim(match, "\"'` ")

	var valid bool
	var info string

	switch {
	case strings.HasPrefix(match, "ghp_") || strings.HasPrefix(match, "github_pat_"):
		valid, info = ValidateGitHubToken(match)
	case strings.HasPrefix(match, "xoxb-") || strings.HasPrefix(match, "xoxp-") || strings.HasPrefix(match, "xoxa-"):
		valid, info = ValidateSlackToken(match)
	case strings.HasPrefix(match, "sk_live_") || strings.HasPrefix(match, "rk_live_"):
		valid, info = ValidateStripeKey(match)
	case strings.HasPrefix(match, "AIzaSy") || (strings.HasPrefix(match, "AIza") && len(match) == 39):
		valid, info = ValidateGoogleAPIKey(match)
	case strings.HasPrefix(match, "SG.") && len(match) > 30:
		valid, info = ValidateSendGridKey(match)
	case strings.HasPrefix(match, "npm_") && len(match) == 40:
		valid, info = ValidateNPMToken(match)
	}

	if valid {
		f.Validated = true
		f.Confidence = 100
		f.Severity = "CRITICAL"
		f.ValidationInfo = info
		core.Logf("  %s[VERIFIED LIVE]%s %s -> %s\n", core.GREEN, core.RESET, f.Type, info)
	}
}

// ValidateFindings runs parallel validation probes on all findings when -validate is enabled.
func ValidateFindings(findings []core.Finding) []core.Finding {
	if !core.GlobalConfig.Validate || len(findings) == 0 {
		return findings
	}

	core.Logf("\n  %s[VALIDATE]%s Running live verification probes on discovered secrets...\n", core.MAGENTA, core.RESET)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i := range findings {
		m := strings.TrimSpace(findings[i].Match)
		m = strings.Trim(m, "\"'` ")

		// Only check items with supported prefixes
		if strings.HasPrefix(m, "ghp_") || strings.HasPrefix(m, "github_pat_") ||
			strings.HasPrefix(m, "xoxb-") || strings.HasPrefix(m, "xoxp-") ||
			strings.HasPrefix(m, "sk_live_") || strings.HasPrefix(m, "rk_live_") ||
			strings.HasPrefix(m, "AIza") || strings.HasPrefix(m, "SG.") ||
			strings.HasPrefix(m, "npm_") {

			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				ValidateFinding(&findings[idx])
			}(i)
		}
	}

	wg.Wait()
	return findings
}
