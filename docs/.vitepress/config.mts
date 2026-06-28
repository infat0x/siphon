import { defineConfig } from 'vitepress'

export default defineConfig({
  title: "Siphon",
  description: "A hyper-concurrent, Go-based offensive security engine for large-scale JavaScript reconnaissance.",
  base: "/siphon/", // Required for GitHub Pages deployment
  cleanUrls: true,
  appearance: 'force-dark',
  themeConfig: {
    logo: '/logo.png',
    
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Documentation', link: '/' },
      { text: 'API Reference', link: '/reference/main' }
    ],

    sidebar: [
      {
        text: 'System Documentation',
        collapsed: false,
        items: [
          {
            text: 'Introduction',
            collapsed: true,
            items: [
              { text: 'Getting Started', link: '/' },
              { text: 'Installation', link: '/guide/installation' },
              { text: 'Configuration', link: '/guide/configuration' },
              { text: 'CLI Usage', link: '/guide/cli-usage' },
              { text: 'AI Integration', link: '/guide/ai-integration' },
            ]
          },
          {
            text: 'Architecture & Engine',
            collapsed: true,
            items: [
              { text: 'Pipeline Overview', link: '/architecture/pipeline' },
              { text: 'Concurrency Model', link: '/architecture/concurrency-model' },
              { text: 'Secret Patterns', link: '/architecture/secret-patterns' },
              { text: 'Data Flow', link: '/architecture/data-flow' },
            ]
          },
          {
            text: 'Use Cases & Scenarios',
            collapsed: true,
            items: [
              { text: 'Bug Bounty Hunting', link: '/scenarios/bug-bounty' },
              { text: 'Red Teaming', link: '/scenarios/red-teaming' },
              { text: 'CI/CD Integration', link: '/scenarios/cicd-integration' },
              { text: 'Custom Rules', link: '/scenarios/custom-rules' },
            ]
          },
          {
            text: 'Advanced Configurations',
            collapsed: true,
            items: [
              { text: 'Distributed Scanning', link: '/advanced/distributed-scanning' },
              { text: 'Rate Limiting & Evasion', link: '/advanced/rate-limiting' },
              { text: 'Fine Tuning the AI', link: '/advanced/fine-tuning' },
            ]
          },
          {
            text: 'API & Reports',
            collapsed: true,
            items: [
              { text: 'JSON Report Schema', link: '/api/json-reports' },
              { text: 'Stdout Parsing', link: '/api/stdout-parsing' },
            ]
          },
          {
            text: 'Maintenance',
            collapsed: true,
            items: [
              { text: 'Troubleshooting', link: '/guide/troubleshooting' },
              { text: 'FAQ', link: '/guide/faq' },
              { text: 'Best Practices', link: '/guide/best-practices' },
              { text: 'Development Guide', link: '/contributing/development-guide' },
            ]
          }
        ]
      },
      {
        text: 'Codebase Reference',
        collapsed: true,
        items: [
          { text: 'Core System (main.go)', link: '/reference/main' },
          {
            text: 'Collector Module',
            collapsed: true,
            items: [
              { text: 'Active Scraper', link: '/reference/collector/active' },
              { text: 'Brute Forcer', link: '/reference/collector/brute' },
              { text: 'Deep Parser', link: '/reference/collector/parse' },
              { text: 'Passive Discovery', link: '/reference/collector/passive' },
            ]
          },
          {
            text: 'Core Module',
            collapsed: true,
            items: [
              { text: 'AI Engine', link: '/reference/core/ai' },
              { text: 'Logging', link: '/reference/core/log' },
              { text: 'Types & Structs', link: '/reference/core/types' },
              { text: 'Terminal UI', link: '/reference/core/ui' },
              { text: 'Utilities', link: '/reference/core/utils' },
            ]
          },
          {
            text: 'Downloader Module',
            collapsed: true,
            items: [
              { text: 'Async Downloader', link: '/reference/downloader/download' },
              { text: 'URL Filter', link: '/reference/downloader/filter' },
            ]
          },
          {
            text: 'Scanner Module',
            collapsed: true,
            items: [
              { text: 'Base64 Scanner', link: '/reference/scanner/base64_scanner' },
              { text: 'Config Leak Scanner', link: '/reference/scanner/config_leak_scanner' },
              { text: 'Entropy Scanner', link: '/reference/scanner/entropy' },
              { text: 'HTTPX Probe', link: '/reference/scanner/httpx' },
              { text: 'Inline Assignments', link: '/reference/scanner/inline_scanner' },
              { text: 'Interesting Paths', link: '/reference/scanner/interesting_scanner' },
              { text: 'Regex Patterns', link: '/reference/scanner/patterns' },
              { text: 'Regex Scanner', link: '/reference/scanner/regex' },
              { text: 'Report Generator', link: '/reference/scanner/report' },
              { text: 'Source Map Scanner', link: '/reference/scanner/source_map_scanner' },
              { text: 'External Tools', link: '/reference/scanner/tools' },
            ]
          }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/infat0x/siphon' }
    ],
    
    search: {
      provider: 'local',
      options: {
        detailedView: true,
        miniSearch: {
          options: {
            /* Options for miniSearch */
          }
        }
      }
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024-present infat0x'
    }
  }
})
