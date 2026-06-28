# Deep Parser (`collector/parse.go`)

The `parse.go` module is responsible for deep-parsing initially discovered JavaScript files to uncover dynamically loaded chunks and nested dependencies.

## Overview

Modern web applications built with frameworks like React, Webpack, or Vite often split their JavaScript into multiple "chunks" (e.g., `1.chunk.js`, `vendor.abcdef.js`). These chunks are loaded dynamically and are frequently entirely missing from the initial HTML DOM or passive archives.

The `ExtractDeepJS` function solves this by downloading the initial tier of JS files and statically analyzing their contents to find references to these deeper chunks.

> [!NOTE]
> Deep parsing is an essential step. It frequently yields the most valuable secrets, as developers often assume that dynamically loaded chunks are obscured from casual observation.

## Regex-Based Chunk Discovery

The parser looks for common chunk naming conventions and quoted paths embedded within the JavaScript logic.

```go
var (
	// Matches basic chunk or bundle files like vendor.abcdef.js, main.js, 1.chunk.js
	deepJsLinkRe = regexp.MustCompile(`[a-zA-Z0-9_.\-]+\.js`)
	
	// Sometimes paths are in quotes e.g. "static/js/main.chunk.js"
	quotedPathRe = regexp.MustCompile(`["'](/[a-zA-Z0-9_.\-/\~]+\.js)["']`)
)
```

> [!TIP]
> By running this step concurrently across hundreds of files, Siphon can unpack the entire dependency tree of a modern Single Page Application (SPA) in seconds.

## Source Map Extraction

Beyond chunk parsing, `parse.go` also includes the highly critical `CheckSourceMaps` function.

When developers compile TypeScript or React, a `.js.map` file is often generated. If mistakenly uploaded to the production server, these source maps allow an attacker to reconstruct the original, unminified source code—including comments and potentially hardcoded credentials!

```go
func CheckSourceMaps(jsUrls []string) []string {
    // ...
    mapUrl := target + ".map"
    req, err := http.NewRequest("HEAD", mapUrl, nil)
    // ...
}
```

> [!WARNING]
> Siphon actively probes for `.js.map` variants using HTTP `HEAD` requests. Even if the server responds with a `403 Forbidden`, Siphon records the existence of the source map for further targeted analysis.
