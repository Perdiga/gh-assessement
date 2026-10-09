const config = {
  title: "GitHub Enterprise Assessment Framework",
  tagline: "Evidence-driven assessment guidance and versioned control reference",
  url: "https://perdiga.github.io",
  baseUrl: process.env.DOCUSAURUS_BASE_URL || "/",
  organizationName: "Perdiga",
  projectName: "gh-assessement",
  onBrokenLinks: "throw",
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: "warn",
    },
  },
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },
  presets: [
    [
      "classic",
      {
        docs: {
          routeBasePath: "/",
          sidebarPath: "./sidebars.js",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      },
    ],
  ],
  themeConfig: {
    navbar: {
      title: "GitHub Enterprise Assessment Framework",
      hideOnScroll: true,
      items: [
        { to: "/", label: "Overview", position: "left" },
        { to: "/installation", label: "Install", position: "left" },
        { to: "/usage", label: "Use", position: "left" },
        { to: "/controls", label: "Controls", position: "left" },
        {
          href: "https://github.com/github/github-well-architected",
          label: "GitHub Well-Architected",
          position: "right",
        },
      ],
    },
    footer: {
      style: "light",
      links: [
        {
          title: "Project",
          items: [
            { label: "Overview", to: "/" },
            { label: "Install", to: "/installation" },
            { label: "Use", to: "/usage" },
          ],
        },
        {
          title: "Reference",
          items: [
            { label: "Control catalog", to: "/controls" },
            {
              label: "GitHub Well-Architected",
              href: "https://github.com/github/github-well-architected",
            },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} GitHub Enterprise Assessment Framework contributors`,
    },
    prism: {
      additionalLanguages: ["bash", "json", "yaml"],
    },
  },
};

module.exports = config;
