import type { SidebarConfig } from '@vuepress/theme-default'

export const sidebarEn: SidebarConfig = {
  '/activity/': [
    {
      text: 'Activity',
      children: [
        '/activity/us-cert.md',
        '/activity/cert-fr.md',
        '/activity/ma-cert.md',
        '/activity/ibm-x-force-exchange.md',
        '/activity/zerodayinitiative.md',
        '/activity/obs-vigilance.md',
        '/activity/vuldb.md',
        '/activity/hk-cert.md',

      ],
    },
  ],
  '/docs/': [
    {
      text: 'Docs',
      children: [
        '/docs/',
        '/docs/contributing.md',
        '/docs/code_of_conduct.md',
      ],
    },
  ],
}
