# Best Practices

To get the most out of Siphon, follow these best practices:

1. **Recon First**: Don't run Siphon against a bare domain. Run Subfinder, Amass, and HTTPX first, then feed the massive list of live subdomains into Siphon.
2. **Use the AI**: The `$GEMINI_API_KEY` is your best friend. It saves hours of manual verification.
3. **Check Source Maps**: Always pay attention to Source Map findings. An unpacked source map often leads to critical vulnerabilities.
