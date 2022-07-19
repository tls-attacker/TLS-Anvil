// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'TLS-Anvil',
  tagline: 'An automated test suite for TLS',
  url: 'https://tls-anvil.com/',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/logo.png',
  staticDirectories: ['static'],

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'tls-attacker', // Usually your GitHub org/user name.
  projectName: 'TLS-Anvil', // Usually your repo name.

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/tls-attacker/TLS-Anvil/tree/main/Docs/',
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/tls-attacker/TLS-Anvil/tree/main/Docs/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'TLS-Anvil',
         logo: {
           alt: 'TLS-Anvil Logo',
           src: 'img/logo.png',
         },
        items: [
          {
            type: 'doc',
            docId: 'Quick-Start/index',
            position: 'left',
            label: 'Docs',
          },
          {
            position: 'left',
            label: 'Publications',
            to: '/publications'
          },
          { 
            to: '/blog', 
            label: 'What\'s New', 
            position: 'left' 
          },
          {
            href: 'https://github.com/tls-attacker/TLS-Anvil',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'light',
        links: [
          {
            label: "GitHub",
            href: "https://github.com/tls-attacker/TLS-Anvil"
          }
        ],
        copyright: `Copyright © ${new Date().getFullYear()} TLS-Anvil. Built with ❤️ and Docusaurus.`,
      },
      prism: {
        theme: lightCodeTheme,
        additionalLanguages: ["java"],
        darkTheme: darkCodeTheme,
      },
    }),
};

module.exports = config;
