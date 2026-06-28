# Utilities (`core/utils.go`)

The `utils.go` file acts as the standard library for Siphon, housing pure functions used repeatedly throughout the codebase for data formatting, mathematical calculations, and URL normalization.

## Deduplication Logic

When scraping hundreds of thousands of URLs, duplication is inevitable. The `Dedup` function is a fast, generic string deduplicator using a Go map.

```go
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
```

> [!TIP]
> Siphon also provides `DedupFindings`, which uniquely identifies secrets by concatenating their `Type` and `Match`. This ensures that if 5 different scanners find the exact same API key, it is only reported to the user once!

## Shannon Entropy Calculation

Siphon implements its own mathematical scanner to detect high-entropy strings (which are often cryptographic keys or hashes). The `ShannonEntropy` function calculates the uncertainty (entropy) of a string based on character frequencies.

```go
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
```

> [!NOTE]
> Base64 strings typically have an entropy above `4.5`, while random hex strings sit around `3.5`. Normal English text usually has an entropy below `3.0`.

## JavaScript Validation

When brute-forcing JS paths, web servers often return HTTP `200 OK` for completely invalid files, serving standard HTML custom 404 pages instead. The `IsValidJS` function quickly checks the first 512 bytes of a file to reject HTML.

```go
var htmlErrorRe = regexp.MustCompile(`(?i)<html|<!doctype\s+html|<title>4\d{2}|<title>5\d{2}|Access Denied|403 Forbidden|404 Not Found|<body`)

func IsValidJS(content []byte) bool {
	// ... check head of file against regex
}
```

> [!WARNING]
> This aggressive filter prevents Siphon from trying to regex scan Megabytes of garbage HTML data, drastically saving memory and CPU cycles during the scanning phase.
