import type { HeadConfig } from '@vuepress/core'

export const head: HeadConfig[] = [
  [
    'link',
    {
      rel: 'icon',
      type: 'image/webp',
      sizes: '16x16',
      href: `/images/logo1.webp`,
    },
  ],
  [
    'link',
    {
      rel: 'icon',
      type: 'image/webp',
      sizes: '32x32',
      href: `/images/logo1.webp`,
    },
  ],
  ['link', { rel: 'manifest', href: '/manifest.webmanifest' }],
  ['meta', { name: 'application-name', content: 'Cyberowl' }],
  ['meta', { name: 'apple-mobile-web-app-title', content: 'Cyberowl' }],
  ['meta', { name: 'apple-mobile-web-app-status-bar-style', content: 'black' }],
  [
    'link',
    { rel: 'apple-touch-icon', href: `/images/logo1.webp` },
  ],
  [
    'link',
    {
      rel: 'mask-icon',
      href: '/images/logo1.webp',
      color: '#3eaf7c',
    },
  ],
  ['meta', { name: 'msapplication-TileColor', content: '#3eaf7c' }],
  ['meta', { name: 'theme-color', content: '#3eaf7c' }],
  // ['link', { rel: 'stylesheet', href: 'https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css' }],
]
