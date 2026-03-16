import type { Metadata } from "next";
/* Self-hosted fonts via @fontsource — no external requests, works offline */
import "@fontsource-variable/inter";
import "@fontsource-variable/outfit";
import "@fontsource/instrument-serif/400.css";
import "@fontsource/instrument-serif/400-italic.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "./globals.css";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://mcp-sentinel.com";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "MCP Sentinel — MCP Server Security Intelligence",
    template: "%s — MCP Sentinel",
  },
  description:
    "The world's most comprehensive security intelligence registry for MCP servers. 22,000+ servers scanned across 103 detection rules covering prompt injection, supply chain attacks, dependency vulnerabilities, and more.",
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
      "22,000+ MCP servers scanned. 103 detection rules. Know which servers are safe before they touch your agent.",
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
      "22,000+ MCP servers scanned. 103 detection rules. Know which servers are safe before they touch your agent.",
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
    "The world's most comprehensive MCP server security intelligence registry. 22,000+ servers scanned, 103 detection rules, zero guesswork.",
  sameAs: ["https://github.com/mcp-sentinel"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
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
                {/* AI Shield: neural network nodes + radar rings inside a security shield */}
                <svg
                  width="30"
                  height="30"
                  viewBox="0 0 30 30"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  {/* Shield body */}
                  <path
                    d="M15 2.5L25.5 6.5V13.5C25.5 20 21 25.5 15 27.5C9 25.5 4.5 20 4.5 13.5V6.5L15 2.5Z"
                    fill="var(--accent-sub)"
                    stroke="var(--accent)"
                    strokeWidth="1.4"
                    strokeLinejoin="round"
                  />
                  {/* Outer radar ring */}
                  <circle cx="15" cy="14" r="6.5" stroke="var(--accent)" strokeWidth="0.6" opacity="0.28" strokeDasharray="2 2" />
                  {/* Inner radar ring */}
                  <circle cx="15" cy="14" r="3.8" stroke="var(--accent)" strokeWidth="0.5" opacity="0.18" strokeDasharray="1.5 1.8" />
                  {/* Neural network nodes — upper pair */}
                  <circle cx="10.5" cy="10.5" r="1.35" fill="var(--accent)" opacity="0.65" />
                  <circle cx="19.5" cy="10.5" r="1.35" fill="var(--accent)" opacity="0.65" />
                  {/* Neural network nodes — lower pair */}
                  <circle cx="10" cy="18.5" r="1.1" fill="var(--accent)" opacity="0.42" />
                  <circle cx="20" cy="18.5" r="1.1" fill="var(--accent)" opacity="0.42" />
                  {/* Connection lines from nodes to center */}
                  <line x1="10.5" y1="10.5" x2="15" y2="14" stroke="var(--accent)" strokeWidth="0.75" opacity="0.40" />
                  <line x1="19.5" y1="10.5" x2="15" y2="14" stroke="var(--accent)" strokeWidth="0.75" opacity="0.40" />
                  <line x1="10"   y1="18.5" x2="15" y2="14" stroke="var(--accent)" strokeWidth="0.65" opacity="0.28" />
                  <line x1="20"   y1="18.5" x2="15" y2="14" stroke="var(--accent)" strokeWidth="0.65" opacity="0.28" />
                  {/* Center pulse — glow ring + solid core */}
                  <circle cx="15" cy="14" r="2.6" fill="var(--accent)" opacity="0.18" />
                  <circle cx="15" cy="14" r="1.7" fill="var(--accent)" />
                </svg>
              </span>
              <span className="logo-text">
                <span className="logo-mcp">MCP</span>
                <span className="logo-sentinel"> Sentinel</span>
              </span>
            </a>

            <nav className="site-nav" aria-label="Main navigation">
              <a href="/" className="nav-link">Registry</a>
              <a href="/categories" className="nav-link">Categories</a>
              <a href="/dashboard" className="nav-link">Dashboard</a>
              <a href="/about" className="nav-link">About</a>
              <a href="/api/v1" className="nav-link nav-link-api" target="_blank" rel="noopener noreferrer">
                API
              </a>
            </nav>
          </div>
        </header>

        {/* ── Main ──────────────────────────────────── */}
        <main className="site-main">{children}</main>

        {/* ── Footer ────────────────────────────────── */}
        <footer className="site-footer">
          <div className="footer-inner">
            <span className="footer-copy">
              © {new Date().getFullYear()} MCP Sentinel — All detection is deterministic. No LLMs.
            </span>
            <nav className="footer-links" aria-label="Footer links">
              <a href="https://github.com/mcp-sentinel" className="footer-link" target="_blank" rel="noopener noreferrer">
                GitHub
              </a>
              <a href="/about" className="footer-link">About</a>
              <a href="/api/v1" className="footer-link" target="_blank" rel="noopener noreferrer">
                API Docs
              </a>
              <a href="https://modelcontextprotocol.io" className="footer-link" target="_blank" rel="noopener noreferrer">
                MCP Spec
              </a>
            </nav>
          </div>
        </footer>
      </body>
    </html>
  );
}
