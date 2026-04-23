import type { SidebarConfig } from '@vuepress/theme-default'

export const sidebarEn: SidebarConfig = {
  '/activity/': [
    {
      text: 'Activity',
      children: [
        '/activity/US-CERT.md',
        '/activity/CERT-FR.md',
        '/activity/MA-CERT.md',
        '/activity/IBM-X-FORCE-EXCHANGE.md',
        '/activity/ZERODAYINITIATIVE.md',
        '/activity/OBS-Vigilance.md',
        '/activity/VulDB.md',
        '/activity/HK-CERT.md',
        '/activity/CA-CCS.md',
        '/activity/EU-CERT.md',
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
