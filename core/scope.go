package core

import (
	"net/url"
	"path/filepath"
	"strings"
)

// IsInScope checks whether targetURL matches the defined scope pattern.
// Scope can be a single domain ("example.com"), wildcard ("*.example.com"),
// or comma-separated list of scopes ("*.example.com,api.test.com").
// If scope is empty, IsInScope returns true (unrestricted).
func IsInScope(targetURL string, scope string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return true
	}

	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return false
	}

	u, err := url.Parse(targetURL)
	host := ""
	if err == nil && u.Host != "" {
		host = u.Hostname()
	} else {
		// If URL parsing fails or no scheme, strip protocol manually
		h := strings.TrimPrefix(targetURL, "https://")
		h = strings.TrimPrefix(h, "http://")
		if idx := strings.Index(h, "/"); idx != -1 {
			h = h[:idx]
		}
		if idx := strings.Index(h, ":"); idx != -1 {
			h = h[:idx]
		}
		host = h
	}

	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	// Support comma-separated scopes
	scopes := strings.Split(scope, ",")
	for _, sc := range scopes {
		sc = strings.ToLower(strings.TrimSpace(sc))
		if sc == "" {
			continue
		}

		// Exact match
		if host == sc {
			return true
		}

		// Wildcard match (e.g. *.example.com)
		if strings.HasPrefix(sc, "*.") {
			rootDomain := strings.TrimPrefix(sc, "*.")
			if host == rootDomain || strings.HasSuffix(host, "."+rootDomain) {
				return true
			}
		} else if strings.HasPrefix(sc, "*") {
			pattern := sc
			if matched, _ := filepath.Match(pattern, host); matched {
				return true
			}
		} else {
			// Plain domain also covers subdomains (e.g. "example.com" covers "api.example.com")
			if strings.HasSuffix(host, "."+sc) {
				return true
			}
		}
	}

	return false
}

// FilterInScope filters a slice of URLs, returning only those in scope.
func FilterInScope(urls []string, scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return urls
	}
	var inScope []string
	seen := make(map[string]struct{})
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			if IsInScope(u, scope) {
				inScope = append(inScope, u)
			}
		}
	}
	return inScope
}
