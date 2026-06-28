import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Siphon",
  description: "A hyper-concurrent, Go-based offensive security engine for large-scale JavaScript reconnaissance.",
  base: "/siphon/", // Required for GitHub Pages deployment
  cleanUrls: true,
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Architecture', link: '/architecture/pipeline' }
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
