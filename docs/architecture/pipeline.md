# Pipeline Overview

Siphon operates in a linear, multi-stage pipeline.

1. **Input Parsing**: Reads domains or URLs from stdin or files.
2. **Live Check**: Filters out dead hosts using `httpx`.
3. **Reconnaissance**: Harvests JavaScript URLs using `gau`, `waybackurls`, `hakrawler`, etc.
4. **Active Parsing**: Connects to the live sites and extracts `<script>` tags from the HTML.
5. **Deduplication**: Merges all findings and removes duplicate URLs.
6. **Downloading**: Concurrently fetches all JS files.
7. **Scanning**: Runs internal and external scanners against the downloaded files.
8. **Reporting**: Generates JSON and Text reports.
