---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Siphon v7"
  text: "JavaScript Secret Recon"
  tagline: A hyper-concurrent, Go-based offensive security engine for large-scale JavaScript reconnaissance.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/infat0x/siphon

features:
  - title: Ultra Fast
    details: Written in Go 1.21+, orchestrating 15 parallel secret scanners to maximize speed and efficiency.
  - title: Deep Extraction
    details: Automatically extracts JS files via Active HTML parsing, Hakrawler, Katana, Gau, and Waybackurls.
  - title: AI-Driven Analysis
    details: Filters out false positives with deep algorithmic checks and an integrated AI (LLM) strict filter for perfect true positives.
---
