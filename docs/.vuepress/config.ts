import process from 'node:process'
import { viteBundler } from '@vuepress/bundler-vite'
import { webpackBundler } from '@vuepress/bundler-webpack'
import { defineUserConfig } from '@vuepress/cli'
import { defaultTheme } from '@vuepress/theme-default'
import { getDirname, path } from '@vuepress/utils'
import { searchPlugin } from '@vuepress/plugin-search'
import googleAnalyticsPlugin from '@vuepress/plugin-google-analytics'
import { docsearchPlugin } from '@vuepress/plugin-docsearch'

import {
  head,
  navbarEn,
  sidebarEn,
} from './configs/index.js'

const __dirname = getDirname(import.meta.url)
const isProd = process.env.NODE_ENV === 'production'

export default defineUserConfig({
  // set site base to default value
  base: '/',

  // extra tags in `<head>`
  head,

  // site-level locales config
  locales: {
    '/': {
      lang: 'en-US',
      title: 'CyberOwl',
      description: 'Stay informed on the latest cyber threats - a one-stop destination for all the latest alerts and updates from multiple sources.',
    },
    // '/fr/': {
    //   lang: 'fr-FR',
    //   title: 'cyberowl',
    //   description: 'Résumé quotidien des incidents de sécurité les plus fréquemment signalés provenant de diverses sources',
    // },
  },

  // specify bundler via environment variable
  bundler:
    process.env.DOCS_BUNDLER === 'webpack' ? webpackBundler() : viteBundler(),

  // configure default theme
  theme: defaultTheme({
    logo: '/images/logo1.webp',
    logoDark: '/images/logoDark.webp',
    repo: 'karimhabush/cyberowl',
    docsDir: 'docs',
    contributors: false,

    // theme-level locales config
    locales: {
      /**
       * English locale config
       *
       * As the default locale of @vuepress/theme-default is English,
       * we don't need to set all of the locale fields
       */
      '/': {
        // navbar
        navbar: navbarEn,
        // sidebar
        sidebar: sidebarEn,
        // page meta
        editLinkText: 'Edit this page on GitHub',
      },

    },

    themePlugins: {
      // only enable git plugin in production mode
      git: isProd,
      // use shiki plugin in production mode instead
      prismjs: !isProd,
    },
  }),

  // configure markdown
  markdown: {
    importCode: {
      handleImportPath: (str) =>
        str.replace(/^@vuepress/, path.resolve(__dirname, '../../ecosystem')),
    },
  },

  // use plugins
  plugins: [
    searchPlugin({}),
    googleAnalyticsPlugin({
      id: process.env.GA_ID ?? '',
    }),
    // docsearchPlugin({
    //   appId: 'JF3XXSIIVE',
    //   apiKey: '4bf131e5a248c25baf276a394b7d18cd',
    //   indexName: 'cyberowl',
    // }),
  ],
})
