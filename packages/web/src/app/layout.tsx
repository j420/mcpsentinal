import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "MCP Sentinel — MCP Server Security Intelligence Registry",
  description:
    "The world's most comprehensive security intelligence registry for MCP servers. Search, compare, and evaluate the security posture of Model Context Protocol servers.",
  keywords: [
    "MCP",
    "Model Context Protocol",
    "security",
    "registry",
    "vulnerability",
    "scanner",
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
          backgroundColor: "#0a0a0a",
          color: "#ededed",
        }}
      >
        <header
          style={{
            borderBottom: "1px solid #222",
            padding: "16px 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <a
            href="/"
            style={{
              color: "#ededed",
              textDecoration: "none",
              fontSize: "20px",
              fontWeight: 700,
            }}
          >
            MCP Sentinel
          </a>
          <nav style={{ display: "flex", gap: "24px" }}>
            <a href="/" style={{ color: "#888", textDecoration: "none" }}>
              Registry
            </a>
            <a
              href="/dashboard"
              style={{ color: "#888", textDecoration: "none" }}
            >
              Dashboard
            </a>
            <a href="/about" style={{ color: "#888", textDecoration: "none" }}>
              About
            </a>
          </nav>
        </header>
        <main style={{ maxWidth: "1200px", margin: "0 auto", padding: "24px" }}>
          {children}
        </main>
      </body>
    </html>
  );
}
