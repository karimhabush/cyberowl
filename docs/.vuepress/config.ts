import process from 'node:process'
import { webpackBundler } from '@vuepress/bundler-webpack'
import { defineUserConfig } from 'vuepress'
import { defaultTheme } from '@vuepress/theme-default'
import { getDirname, path } from 'vuepress/utils'
import { searchPlugin } from '@vuepress/plugin-search'
import { googleAnalyticsPlugin } from '@vuepress/plugin-google-analytics'
import { registerComponentsPlugin } from '@vuepress/plugin-register-components'

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
      title: 'CyberOwl AI',
      description: 'Stay informed on the latest cyber threats - a one-stop destination for all the latest alerts and updates from multiple sources.',
    },
  },

  bundler: webpackBundler({
    evergreen: true,
    configureWebpack: (config) => {
      config.module?.rules?.forEach((rule: any) => {
        if (rule?.use) {
          const uses = Array.isArray(rule.use) ? rule.use : [rule.use]
          uses.forEach((use: any) => {
            if (use?.loader?.includes('esbuild-loader') && use.options) {
              use.options.target = 'es2022'
            }
          })
        }
      })
      return {}
    },
  }),

  // configure default theme
  theme: defaultTheme({
    logo: '/images/logo1.webp',
    logoDark: '/images/logoDark.webp',
    repo: 'karimhabush/cyberowl',
    docsDir: 'docs',
    contributors: false,

    // theme-level locales config
    locales: {
      '/': {
        // navbar
        navbar: navbarEn,
        // sidebar
        sidebar: sidebarEn,
        // page meta
        editLink: false,
      },
    },

    themePlugins: {
      git: !isProd,
      prismjs: !isProd,
      backToTop: false,
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
    registerComponentsPlugin({
      componentsDir: path.resolve(__dirname, './components'),
    }),
  ]
})
