import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Siphon",
  description: "A hyper-concurrent, Go-based offensive security engine for large-scale JavaScript reconnaissance.",
  base: "/siphon/", // Required for GitHub Pages deployment
  cleanUrls: true,
  themeConfig: {
    logo: '/logo.png',
    
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Architecture', link: '/architecture/pipeline' },
      { text: 'Codebase Reference', link: '/reference/main' }
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
        ]
      },
      {
        text: 'Architecture & Engine',
        items: [
          { text: 'Pipeline', link: '/architecture/pipeline' },
        ]
      },
      {
        text: 'Codebase Reference',
        items: [
          { text: 'Core System (main.go)', link: '/reference/main' },
          {
            text: 'Collector Module',
            collapsed: false,
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
      provider: 'local'
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024-present infat0x'
    }
  }
})
