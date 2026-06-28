# Source Map Scanner (`scanner/source_map_scanner.go`)

The `source_map_scanner.go` module automatically extracts, downloads, and unpacks JavaScript source maps, allowing Siphon to scan the *original*, un-minified TypeScript and JavaScript source code for secrets.

## Overview

Modern JavaScript applications are usually minified and bundled using tools like Webpack or Vite. Sometimes, developers accidentally leave `Source Maps` enabled in production. A source map is a JSON file that maps the minified code back to the original source code, effectively leaking the entire frontend repository.

> [!NOTE]
> If a source map is found, Siphon can scan the original React/Vue component code, which is significantly easier to parse and often contains comments, dev-only mock data, and hardcoded secrets that were obfuscated in the minified bundle.

## Discovery Mechanism

Siphon hunts for source maps using two methods simultaneously:

1. **Inline Comments**: It scans the bottom of every downloaded JS file for the `//# sourceMappingURL=...` directive.
2. **Brute Force Guessing**: Even if the developer removed the comment, Siphon automatically attempts to download `filename.js.map` and `filename.map` for every JS file it finds.

## Extraction and Scanning

Once a valid source map JSON file is downloaded, Siphon parses it and extracts the `sourcesContent` array. This array contains the raw string contents of the original source files.

```go
// Extract original sources from source map
sources := extractSourcesFromMap(mapContent)

// Scan each extracted source for secrets
for sourceName, sourceContent := range sources {
    secretFindings := scanContentForSecrets(sourceContent, jsURL, sourceName)
    localFindings = append(localFindings, secretFindings...)
}
```

> [!WARNING]
> Because source map files can be massive (often 10MB+), Siphon limits the download size and uses a streamlined JSON array parser to extract the strings efficiently without loading the entire JSON AST into memory.
