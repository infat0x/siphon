# Interesting Paths (`scanner/interesting_scanner.go`)

The `interesting_scanner.go` module scans JavaScript files for hardcoded paths that point to sensitive administrative, debug, or internal routing endpoints.

## Overview

Often, frontend code will contain references to backend API endpoints that are not meant for public consumption. Developers might comment them out or leave them in the bundle by mistake. 

Siphon uses this scanner to flag these paths as `MEDIUM` severity findings. While they are not direct credential leaks, they often provide attackers with the exact location of sensitive infrastructure.

> [!NOTE]
> This scanner specifically looks for paths like `/swagger.json`, `/graphql`, `/api/v1/internal`, `/actuator/env`, and Cloud Metadata IPs (`169.254.169.254`).

## Implementation

The scanner uses `bufio.Scanner` to read large, minified JavaScript files efficiently without loading the entire string into memory at once. It checks each line against a map of compiled Regular Expressions.

```go
var interestingPatterns = map[string]*regexp.Regexp{
	"Swagger/OpenAPI": regexp.MustCompile(`(?i)(?:/swagger-ui\.html|/v[1-3]/api-docs|/api-docs|/swagger\.json|/swagger\.yaml)`),
	"GraphQL":         regexp.MustCompile(`(?i)(?:/graphql|/graphiql|/altair|/playground)`),
	"Internal API":    regexp.MustCompile(`(?i)(?:/api/v[1-9]/internal|/admin/api|/v[1-9]/dev)`),
	"Actuator/Debug":  regexp.MustCompile(`(?i)(?:/actuator/health|/actuator/env|/server-status|/phpinfo\.php|/_profiler)`),
	"Cloud Metadata":  regexp.MustCompile(`(?i)(?:169\.254\.169\.254|metadata\.google\.internal)`),
}
```

> [!WARNING]
> To prevent hangs on massive, non-string data blocks (like embedded Base64 images), the scanner implements a line length check and skips any line longer than 50,000 characters.
