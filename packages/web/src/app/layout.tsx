import type { Metadata } from "next";
import "./globals.css";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://mcp-sentinel.com";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "MCP Sentinel — MCP Server Security Intelligence",
    template: "%s — MCP Sentinel",
  },
  description:
    "The world's most comprehensive security intelligence registry for MCP servers. 22,000+ servers scanned across 60 detection rules covering prompt injection, supply chain attacks, dependency vulnerabilities, and more.",
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
      "22,000+ MCP servers scanned. 60 detection rules. Know which servers are safe before they touch your agent.",
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
      "22,000+ MCP servers scanned. 60 detection rules. Know which servers are safe before they touch your agent.",
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

/* JSON-LD: WebSite schema with SearchAction — enables Google Sitelinks Search Box */
const websiteJsonLd = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: "MCP Sentinel",
  description:
    "Security intelligence registry for Model Context Protocol servers",
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

/* JSON-LD: Organization schema */
const organizationJsonLd = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "MCP Sentinel",
  url: SITE_URL,
  logo: `${SITE_URL}/logo.png`,
  description:
    "The world's most comprehensive MCP server security intelligence registry. 22,000+ servers scanned, 60 detection rules, zero guesswork.",
  sameAs: ["https://github.com/mcp-sentinel"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        {/* Preconnect for Google Fonts */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        {/* JSON-LD structured data */}
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
        {/* ── Header ─────────────────────────────────────── */}
        <header className="site-header">
          <div className="header-inner">
            {/* Wordmark */}
            <a href="/" className="site-logo">
              <span className="logo-icon" aria-hidden="true">
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 16 16"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M8 1L14 4V8C14 11.5 11.5 14.5 8 15.5C4.5 14.5 2 11.5 2 8V4L8 1Z"
                    stroke="white"
                    strokeWidth="1.5"
                    strokeLinejoin="round"
                    fill="none"
                  />
                  <path
                    d="M5.5 8L7 9.5L10.5 6"
                    stroke="white"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </span>
              MCP Sentinel
            </a>

            {/* Nav */}
            <nav className="site-nav" aria-label="Main navigation">
              <a href="/" className="nav-link">Registry</a>
              <a href="/dashboard" className="nav-link">Dashboard</a>
              <a href="/about" className="nav-link">About</a>
              <a
                href="/api/v1"
                className="nav-api"
                target="_blank"
                rel="noopener noreferrer"
              >
                API
              </a>
            </nav>
          </div>
        </header>

        {/* ── Main ───────────────────────────────────────── */}
        <main className="site-main">{children}</main>

        {/* ── Footer ─────────────────────────────────────── */}
        <footer className="site-footer">
          <div className="footer-inner">
            <span className="footer-copy">
              © {new Date().getFullYear()} MCP Sentinel — All detection is
              deterministic. No LLMs.
            </span>
            <nav className="footer-links" aria-label="Footer links">
              <a
                href="https://github.com/mcp-sentinel"
                className="footer-link"
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub
              </a>
              <a href="/about" className="footer-link">About</a>
              <a
                href="/api/v1"
                className="footer-link"
                target="_blank"
                rel="noopener noreferrer"
              >
                API Docs
              </a>
              <a
                href="https://modelcontextprotocol.io"
                className="footer-link"
                target="_blank"
                rel="noopener noreferrer"
              >
                MCP Spec
              </a>
            </nav>
          </div>
        </footer>
      </body>
    </html>
  );
}
