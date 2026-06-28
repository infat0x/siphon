package downloader

import "regexp"

var JsExcludeRe = regexp.MustCompile(`(?i)jquery|react(?:\.js|-dom|-router)?|angular(?:js)?|vue\.js|ember|backbone|bootstrap|lodash|underscore|moment\.js|axios|webpack|babel|polyfill|modernizr|d3\.js|three\.js|chart\.js|socket\.io|amplify|google-analytics|gtag|gtm|fbevents|recaptcha|stripe|twilio|intercom|sentry|datadog|newrelic|hotjar|gsap|swiper|slick|fontawesome|material-ui|tailwind|semantic\.js|foundation|\.min\.js|/vendor/|/bundle|/chunk|/node_modules/|/bower_components/|\.[a-f0-9]{8,}\.js|-[a-f0-9]{8,}\.js|runtime\.|/common\.|manifest\.|/framework\.|/lib/|/libs/`)

func FilterJS(urls []string) []string {
	var filtered []string
	for _, u := range urls {
		if !JsExcludeRe.MatchString(u) {
			filtered = append(filtered, u)
		}
	}
	return filtered
}
