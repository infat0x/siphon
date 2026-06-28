# Frequently Asked Questions

### Does Siphon run JavaScript?
No. Siphon is a static analyzer. It downloads the JS code and scans it using AST parsing, Regex, and Entropy analysis. It does not spin up a headless browser.

### Is it legal to use Siphon?
Siphon is an offensive security tool. You must have explicit permission to scan the target infrastructure. Do not use Siphon on targets you do not own.

### How much does the AI cost?
Gemini API pricing varies. However, Siphon only sends High-Entropy strings to the API, drastically reducing the token count compared to sending the entire JS file.
