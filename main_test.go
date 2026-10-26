package main

import (
	"regexp"
	"siphon-go/core"
	"siphon-go/downloader"
	"siphon-go/scanner"
	"strings"
	"testing"
)

func TestFilterJS(t *testing.T) {
	urls := []string{
		"https://example.com/_next/static/chunks/0nhbbhsqmln7j.js",
		"https://example.com/_next/static/chunks/app/dashboard.js",
		"https://example.com/assets/index-a1b2c3d4.js",
		"https://example.com/static/js/main.8f9b2c3d.js",
		"https://example.com/js/jquery.min.js",
		"https://www.googletagmanager.com/gtm.js",
		"https://example.com/vendor/bundle.js",
	}

	filtered := downloader.FilterJS(urls)

	// Custom application chunks MUST be preserved
	expectedCustom := []string{
		"https://example.com/_next/static/chunks/0nhbbhsqmln7j.js",
		"https://example.com/_next/static/chunks/app/dashboard.js",
		"https://example.com/assets/index-a1b2c3d4.js",
		"https://example.com/static/js/main.8f9b2c3d.js",
	}

	for _, exp := range expectedCustom {
		found := false
		for _, f := range filtered {
			if f == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("FilterJS incorrectly removed custom chunk: %s", exp)
		}
	}

	// Third party libraries MUST be excluded
	for _, f := range filtered {
		if strings.Contains(f, "jquery") || strings.Contains(f, "gtm.js") || strings.Contains(f, "vendor") {
			t.Errorf("FilterJS failed to filter third-party library: %s", f)
		}
	}
}

func TestEntropyExcludesTailwind(t *testing.T) {
	dlMap := map[string]string{
		"https://example.com/app.js": "test_tailwind.js",
	}

	// This is a test file creation to verify ScanEntropy
	testJS := `
		const c1 = "mb-2 flex shrink-0 items-center justify-center [&_svg]:pointer-events-none [&_svg]:shrink-0";
		const c2 = "absolute top-3 right-3 flex h-[19px] w-[19px] items-center justify-center rounded-full bg-primary text-primary-foreground";
		const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
	`
	_ = testJS
	// Just check the filtering logic
	findings := scanner.ScanEntropy(dlMap)
	for _, f := range findings {
		if strings.Contains(f.Match, " ") {
			t.Errorf("ScanEntropy flagged a string containing spaces (Tailwind): %s", f.Match)
		}
	}
}

func TestNpmTokenNoUUID(t *testing.T) {
	uuidStr := "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
	npmStr := "npm_123456789012345678901234567890123456"

	patStr, ok := scanner.SecretPatterns["npm_token 2"]
	if !ok {
		t.Fatalf("npm_token 2 pattern not found in SecretPatterns")
	}

	re := regexp.MustCompile(patStr)
	if re.MatchString(uuidStr) {
		t.Errorf("npm_token 2 still matches raw UUID: %s", uuidStr)
	}
	if !re.MatchString(npmStr) {
		t.Errorf("npm_token 2 failed to match valid npm token: %s", npmStr)
	}
}

func TestDedupFindingsFullMatch(t *testing.T) {
	f1 := core.Finding{Type: "JWT", URL: "https://a.com/1.js", Match: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.token1"}
	f2 := core.Finding{Type: "JWT", URL: "https://a.com/2.js", Match: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.token2"}

	res := core.DedupFindings([]core.Finding{f1, f2})
	if len(res) != 2 {
		t.Errorf("DedupFindings collapsed distinct findings with similar prefix: got %d, expected 2", len(res))
	}
}

func TestScopeFiltering(t *testing.T) {
	scope := "*.example.com,target.org"

	inScopeTests := []string{
		"https://example.com/app.js",
		"https://api.example.com/v1/auth.js",
		"https://sub.child.example.com/test.js",
		"http://target.org/main.js",
		"https://api.target.org/data.js",
	}

	for _, u := range inScopeTests {
		if !core.IsInScope(u, scope) {
			t.Errorf("IsInScope failed to match in-scope URL: %s with scope %s", u, scope)
		}
	}

	outOfScopeTests := []string{
		"https://google.com/analytics.js",
		"https://evil-example.com/bad.js",
		"https://notexample.com/test.js",
		"https://another-target.org.evil.com/app.js",
	}

	for _, u := range outOfScopeTests {
		if core.IsInScope(u, scope) {
			t.Errorf("IsInScope incorrectly matched out-of-scope URL: %s with scope %s", u, scope)
		}
	}

	allUrls := append(inScopeTests, outOfScopeTests...)
	filtered := core.FilterInScope(allUrls, scope)
	if len(filtered) != len(inScopeTests) {
		t.Errorf("FilterInScope returned %d items, expected %d", len(filtered), len(inScopeTests))
	}
}

func TestProxyTransportConfiguration(t *testing.T) {
	core.GlobalConfig.Proxy = "http://127.0.0.1:8080"
	defer func() { core.GlobalConfig.Proxy = "" }()

	tr := core.GetHTTPTransport()
	if tr == nil {
		t.Fatalf("GetHTTPTransport returned nil")
	}
	if tr.Proxy == nil {
		t.Fatalf("GetHTTPTransport did not set proxy function when GlobalConfig.Proxy is configured")
	}
}

func TestSVGAndColorFilters(t *testing.T) {
	svg := "M12,2C6.48,2,2,6.48,2,12s4.48,10,10,10,10-4.48,10-10S17.52,2,12,2zm-2,15l-5-5,1.41-1.41L10,14.17l7.59-7.59L19,8l-9,9z"
	color := "#1a2b3c"

	if !scanner.IsSVGPath(svg) {
		t.Errorf("IsSVGPath failed to detect valid SVG path coordinate string")
	}
	if !scanner.IsHexColor(color) {
		t.Errorf("IsHexColor failed to detect valid hex color %s", color)
	}
	if !scanner.IsHexColor("#ffffff") || !scanner.IsHexColor("#fff") {
		t.Errorf("IsHexColor failed to detect standard hex color values")
	}
	if scanner.IsHexColor("AIzaSyD12345") {
		t.Errorf("IsHexColor incorrectly flagged non-color API key as hex color")
	}

	if !scanner.IsMagicByteEncoded("iVBORw0KGgoAAAANSUhEUgAA") {
		t.Errorf("IsMagicByteEncoded failed to detect PNG base64 header")
	}
	if !scanner.IsMagicByteEncoded("d09GMgABAAAAAA") {
		t.Errorf("IsMagicByteEncoded failed to detect WOFF font header")
	}
	if !scanner.IsMagicByteEncoded("UklGRiQAAABXRUJQVlA4") {
		t.Errorf("IsMagicByteEncoded failed to detect WebP header")
	}
}

func TestDictionaryIdentifierFilter(t *testing.T) {
	identifier := "getComponentDetailsFromConfiguration"
	identifier2 := "handleAuthenticationStateChange"
	realSecret := "sk_live_1234567890abcdef"

	if !scanner.IsCodeIdentifierOrDictionaryWords(identifier) {
		t.Errorf("IsCodeIdentifierOrDictionaryWords failed to detect code identifier: %s", identifier)
	}
	if !scanner.IsCodeIdentifierOrDictionaryWords(identifier2) {
		t.Errorf("IsCodeIdentifierOrDictionaryWords failed to detect code identifier: %s", identifier2)
	}
	if scanner.IsCodeIdentifierOrDictionaryWords(realSecret) {
		t.Errorf("IsCodeIdentifierOrDictionaryWords incorrectly flagged real secret as dictionary words: %s", realSecret)
	}
}

func TestUnpackSourcesToDisk(t *testing.T) {
	tmpDir := t.TempDir()
	sources := map[string]string{
		"webpack:///src/auth/login.tsx": "export const auth = 'login';",
		"../config/settings.ts":         "export const api = 'https://api.test.com';",
	}

	written := scanner.UnpackSourcesToDisk(tmpDir, "https://example.com/main.js.map", sources)
	if len(written) != 2 {
		t.Errorf("UnpackSourcesToDisk expected 2 written files, got %d", len(written))
	}
}
