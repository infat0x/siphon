# URL Filter (`downloader/filter.go`)

The `filter.go` module implements a massive regex-based noise reduction system to exclude common, open-source JavaScript libraries from being downloaded and scanned.

## Overview

When scanning a target, up to 90% of the discovered JavaScript URLs might point to common libraries like `jQuery`, `React`, `Bootstrap`, or `Google Analytics`. 

Scanning these files is a waste of time and CPU resources because:
1. They are open-source and do not contain target-specific secrets.
2. They are heavily minified, leading to high-entropy variables (e.g., `var a, b, c;`) that trigger false positives in secret scanners.

> [!NOTE]
> The URL Filter is bypassed if the user runs Siphon with the `-scan-all-js` flag.

## The Exclusion Regex

Siphon maintains a highly curated, case-insensitive regular expression that identifies third-party libraries by their URL naming conventions.

```go
var JsExcludeRe = regexp.MustCompile(`(?i)jquery|react(?:\.js|-dom|-router)?|angular(?:js)?|vue\.js|ember|backbone|bootstrap|lodash|underscore|moment\.js|axios|webpack|babel|polyfill|modernizr|d3\.js|three\.js|chart\.js|socket\.io|amplify|google-analytics|gtag|gtm|fbevents|recaptcha|stripe|twilio|intercom|sentry|datadog|newrelic|hotjar|gsap|swiper|slick|fontawesome|material-ui|tailwind|semantic\.js|foundation|\.min\.js|/vendor/|/bundle|/chunk|/node_modules/|/bower_components/|\.[a-f0-9]{8,}\.js|-[a-f0-9]{8,}\.js|runtime\.|/common\.|manifest\.|/framework\.|/lib/|/libs/`)
```

> [!TIP]
> Notice that the regex aggressively filters out `.min.js`, `/vendor/`, and `/node_modules/`. This ensures that even if a developer bundles libraries locally rather than using a CDN, Siphon will still ignore them.

## Implementation

The logic is a simple loop that checks each discovered URL against the `JsExcludeRe` regex.

```go
func FilterJS(urls []string) []string {
	var filtered []string
	for _, u := range urls {
		if !JsExcludeRe.MatchString(u) {
			filtered = append(filtered, u)
		}
	}
	return filtered
}
```
