package downloader

import "regexp"

// JsExcludeRe matches known third-party libraries, analytics, and vendor packages.
// It explicitly preserves application chunks, hashed bundles, and framework routes.
var JsExcludeRe = regexp.MustCompile(`(?i)(?:^|/|\.)(?:jquery(?:\.min)?\.js|bootstrap(?:\.min)?\.js|lodash(?:\.min)?\.js|underscore(?:\.min)?\.js|moment(?:\.min)?\.js|d3(?:\.min)?\.js|three(?:\.min)?\.js|chart(?:\.min)?\.js|socket\.io(?:\.min)?\.js|google-analytics\.com|googletagmanager\.com|gtag/js|gtm\.js|fbevents\.js|recaptcha|sentry(?:\.min)?\.js|datadoghq|newrelic\.com|hotjar\.com|gsap(?:\.min)?\.js|swiper(?:\.min)?\.js|slick(?:\.min)?\.js|fontawesome|material-ui|semantic(?:\.min)?\.js|foundation(?:\.min)?\.js|polyfill(?:\.min)?\.js|modernizr)|(?:/node_modules/|/bower_components/|/vendor/|/vendors/)`)

func FilterJS(urls []string) []string {
	var filtered []string
	for _, u := range urls {
		if !JsExcludeRe.MatchString(u) {
			filtered = append(filtered, u)
		}
	}
	return filtered
}
