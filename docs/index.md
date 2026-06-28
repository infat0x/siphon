---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Siphon"
  text: "Advanced JavaScript Reconnaissance"
  tagline: "A hyper-concurrent, Go-based offensive security engine for large-scale JavaScript analysis. Discover hardcoded secrets, hidden API endpoints, and configuration leaks."
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
  - title: Ultra Fast Concurrency
    details: Written in Go 1.21+, orchestrating parallel secret scanners to maximize speed. Utilizes customized Goroutine pools to process large JavaScript payloads efficiently.
  - title: AI-Driven Analysis
    details: Integrated LLM strict filtering. Siphon dynamically verifies secrets and eliminates false positives by analyzing the semantic context of variables.
  - title: Deep Extraction
    details: Automatically extracts JS files via Active HTML parsing, Hakrawler, Katana, Gau, and Waybackurls, bypassing obfuscation mechanisms.
  - title: Source Map Unpacking
    details: Automatically detects, downloads, and unpacks Webpack/Vite source maps to scan the original un-minified React/Vue code.
  - title: Enterprise Grade Secrets
    details: Implements Shannon Entropy algorithms and a custom database covering extensive API endpoints and cloud service credentials.
  - title: CI/CD Ready
    details: Outputs structured, deduplicated JSON reports engineered for immediate ingestion into SIEMs or automated DevSecOps pipelines.
---
