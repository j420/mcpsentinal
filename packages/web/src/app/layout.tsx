import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "MCP Sentinel — MCP Server Security Intelligence",
    template: "%s — MCP Sentinel",
  },
  description:
    "The world's most comprehensive security intelligence registry for MCP servers. Scan, score, and evaluate Model Context Protocol servers across 60 detection rules.",
  keywords: [
    "MCP",
    "Model Context Protocol",
    "security",
    "registry",
    "vulnerability scanner",
    "OWASP",
    "AI security",
  ],
  openGraph: {
    siteName: "MCP Sentinel",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
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
              <a href="/" className="nav-link">
                Registry
              </a>
              <a href="/dashboard" className="nav-link">
                Dashboard
              </a>
              <a href="/about" className="nav-link">
                About
              </a>
              <a href="/api/v1" className="nav-api" target="_blank" rel="noopener noreferrer">
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
              © {new Date().getFullYear()} MCP Sentinel. All detection is
              deterministic — no LLMs.
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
              <a href="/about" className="footer-link">
                About
              </a>
              <a href="/api/v1" className="footer-link" target="_blank" rel="noopener noreferrer">
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
