import type { Metadata } from "next";
/* Self-hosted fonts via @fontsource — no external requests, works offline */
import "@fontsource-variable/sora";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "@fontsource/jetbrains-mono/700.css";
import "./globals.css";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://mcp-sentinel.com";
const API_URL = process.env.NEXT_PUBLIC_API_URL || "https://api.mcp-sentinel.com";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "MCP Sentinel — MCP Server Security Intelligence",
    template: "%s — MCP Sentinel",
  },
  description:
    "The world's most comprehensive security intelligence registry for MCP servers. 22,000+ servers scanned across 150+ detection rules covering prompt injection, supply chain attacks, dependency vulnerabilities, and more.",
  keywords: [
    "MCP",
    "Model Context Protocol",
    "MCP security",
    "MCP server scanner",
    "AI security",
    "prompt injection",
    "OWASP",
    "vulnerability scanner",
    "Claude",
    "Anthropic",
  ],
  authors: [{ name: "MCP Sentinel" }],
  creator: "MCP Sentinel",
  openGraph: {
    type: "website",
    siteName: "MCP Sentinel",
    locale: "en_US",
    url: SITE_URL,
    title: "MCP Sentinel — MCP Server Security Intelligence",
    description:
      "22,000+ MCP servers scanned. 150+ detection rules. Know which servers are safe before they touch your agent.",
    images: [
      {
        url: `${SITE_URL}/og.png`,
        width: 1200,
        height: 630,
        alt: "MCP Sentinel — Security Intelligence Registry",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "MCP Sentinel — MCP Server Security Intelligence",
    description:
      "22,000+ MCP servers scanned. 150+ detection rules. Know which servers are safe before they touch your agent.",
    images: [`${SITE_URL}/og.png`],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
};

const websiteJsonLd = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: "MCP Sentinel",
  description: "Security intelligence registry for Model Context Protocol servers",
  url: SITE_URL,
  potentialAction: {
    "@type": "SearchAction",
    target: {
      "@type": "EntryPoint",
      urlTemplate: `${SITE_URL}/?q={search_term_string}`,
    },
    "query-input": "required name=search_term_string",
  },
};

const organizationJsonLd = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "MCP Sentinel",
  url: SITE_URL,
  logo: `${SITE_URL}/logo.png`,
  description:
    "The world's most comprehensive MCP server security intelligence registry. 22,000+ servers scanned, 150+ detection rules, zero guesswork.",
  sameAs: ["https://github.com/mcp-sentinel"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon.svg" sizes="any" />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(websiteJsonLd) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationJsonLd) }}
        />
      </head>
      <body>
        {/* ── Header ────────────────────────────────── */}
        <header className="site-header">
          <div className="header-inner">
            <a href="/" className="site-logo">
              <span className="logo-mark" aria-hidden="true">
                <svg
                  width="34"
                  height="34"
                  viewBox="0 0 34 34"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <rect width="34" height="34" rx="8" fill="#111" />
                  <path
                    d="M17 7L24.5 10.5V16C24.5 21 21.2 25.2 17 26.5C12.8 25.2 9.5 21 9.5 16V10.5L17 7Z"
                    fill="none"
                    stroke="#34D399"
                    strokeWidth="1.6"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M13.5 17L15.8 19.3L20.5 14.5"
                    stroke="#34D399"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </span>
              <span className="logo-text">
                <span className="logo-sentinel">Sentinel</span>
              </span>
            </a>

            <button
              className="nav-toggle"
              aria-label="Toggle navigation"
              aria-expanded="false"
              onClick={undefined}
            >
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
                <path d="M3 5h14M3 10h14M3 15h14" />
              </svg>
            </button>
            <nav className="site-nav" id="site-nav" aria-label="Main navigation">
              <a href="/" className="nav-link">Registry</a>
              <a href="/servers" className="nav-link">Servers</a>
              <a href="/categories" className="nav-link">Categories</a>
              <a href="/compliance" className="nav-link">Compliance</a>
              <a href="/scanner" className="nav-link nav-link-scanner">MCP Scanner</a>
            </nav>
          </div>
        </header>

        {/* ── Main ──────────────────────────────────── */}
        <main className="site-main">{children}</main>

        {/* ── Footer ────────────────────────────────── */}
        <footer className="site-footer">
          <div className="footer-inner">
            <div className="footer-brand">
              <a href="/" className="footer-brand-link">
                <svg width="22" height="22" viewBox="0 0 34 34" fill="none">
                  <rect width="34" height="34" rx="8" fill="#111" />
                  <path d="M17 7L24.5 10.5V16C24.5 21 21.2 25.2 17 26.5C12.8 25.2 9.5 21 9.5 16V10.5L17 7Z" fill="none" stroke="#34D399" strokeWidth="1.6" strokeLinejoin="round" />
                  <path d="M13.5 17L15.8 19.3L20.5 14.5" stroke="#34D399" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <span className="footer-brand-text">Sentinel</span>
              </a>
              <p className="footer-tagline">
                Security intelligence for the MCP ecosystem.
                <br />
                150+ detection rules. Zero guesswork. No LLMs.
              </p>
            </div>
            <div className="footer-columns">
              <div className="footer-col">
                <h4 className="footer-col-title">Product</h4>
                <nav className="footer-col-links" aria-label="Product links">
                  <a href="/" className="footer-link">Registry</a>
                  <a href="/categories" className="footer-link">Categories</a>
                  <a href="/compliance" className="footer-link">Compliance</a>
                  <a href="/scanner" className="footer-link">MCP Scanner</a>
                  <a href="/responsible-disclosure" className="footer-link">Responsible Disclosure</a>
                </nav>
              </div>
              <div className="footer-col">
                <h4 className="footer-col-title">Developers</h4>
                <nav className="footer-col-links" aria-label="Developer links">
                  <a href={API_URL} className="footer-link" target="_blank" rel="noopener noreferrer">REST API</a>
                  <a href="https://github.com/mcp-sentinel" className="footer-link" target="_blank" rel="noopener noreferrer">GitHub</a>
                  <a href="https://www.npmjs.com/package/mcp-sentinel" className="footer-link" target="_blank" rel="noopener noreferrer">npm CLI</a>
                </nav>
              </div>
              <div className="footer-col">
                <h4 className="footer-col-title">Resources</h4>
                <nav className="footer-col-links" aria-label="Resource links">
                  <a href="https://modelcontextprotocol.io" className="footer-link" target="_blank" rel="noopener noreferrer">MCP Spec</a>
                  <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" className="footer-link" target="_blank" rel="noopener noreferrer">OWASP MCP Top 10</a>
                </nav>
              </div>
            </div>
          </div>
          <div className="footer-bottom">
            <div className="footer-bottom-inner">
              <span className="footer-copy">
                &copy; {new Date().getFullYear()} MCP Sentinel
              </span>
            </div>
          </div>
        </footer>
        <script
          dangerouslySetInnerHTML={{
            __html: `document.querySelector('.nav-toggle')?.addEventListener('click',function(){var n=document.getElementById('site-nav');if(n){n.classList.toggle('nav-open');this.setAttribute('aria-expanded',n.classList.contains('nav-open'))}})`,
          }}
        />
      </body>
    </html>
  );
}
