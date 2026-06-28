---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Siphon v7"
  text: "Advanced JavaScript Recon"
  tagline: "A hyper-concurrent, Go-based offensive security engine for large-scale JavaScript reconnaissance. Discover hardcoded secrets, hidden API endpoints, and configuration leaks in seconds."
  image:
    src: /logo.png
    alt: Siphon Logo
  actions:
    - theme: brand
      text: Read the Documentation
      link: /guide/getting-started
    - theme: alt
      text: View API Reference
      link: /reference/main
    - theme: alt
      text: GitHub Repository
      link: https://github.com/infat0x/siphon

features:
  - title: ⚡ Ultra Fast Concurrency
    details: Written in Go 1.21+, orchestrating 15 parallel secret scanners to maximize speed. Uses customized Goroutine pools to process gigabytes of JS code without memory leaks.
  - title: 🧠 AI-Driven Analysis
    details: Built-in LLM (Gemini) strict filtering. Siphon dynamically verifies secrets and filters out false positives by analyzing the semantic context of variables.
  - title: 🔍 Deep Extraction
    details: Automatically extracts JS files via Active HTML parsing, Hakrawler, Katana, Gau, and Waybackurls, bypassing complex obfuscation.
  - title: 🧩 Source Map Unpacking
    details: Automatically detects, downloads, and unpacks Webpack/Vite source maps to scan the original un-minified React/Vue code.
  - title: 🛡️ Enterprise Grade Secrets
    details: Uses Shannon Entropy algorithms and a massive custom database covering AWS, GCP, Stripe, PayPal, and regional API endpoints.
  - title: 📊 CI/CD Ready
    details: Outputs structured, deduplicated JSON reports ready for immediate ingestion into SIEMs or automated DevSecOps pipelines.
---

<div style="text-align: center; margin-top: 50px; padding: 20px;">
  <h2 style="color: var(--vp-c-brand-1);">Ready to hunt?</h2>
  <p style="color: var(--vp-c-text-2); max-width: 600px; margin: 0 auto 20px auto;">Dive into the comprehensive documentation to learn how to configure, optimize, and integrate Siphon into your security workflow.</p>
  <a href="./guide/getting-started" style="display: inline-block; padding: 10px 20px; background-color: var(--vp-c-brand-1); color: #fff; text-decoration: none; border-radius: 4px; font-weight: bold;">Get Started →</a>
</div>
