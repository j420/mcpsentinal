/**
 * PreviewFooter — slim, honest footer for the preview area.
 *
 * Surfaces the experimental status, links back to the live site, and points
 * reviewers to the README that explains how to remove this whole tree.
 */

export default function PreviewFooter() {
  return (
    <footer
      style={{
        marginTop: "var(--s12)",
        borderTop: "1px solid var(--border)",
        padding: "var(--s8) 24px",
        background: "var(--surface-2)",
      }}
    >
      <div
        style={{
          maxWidth: "1200px",
          margin: "0 auto",
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "var(--s6)",
          flexWrap: "wrap",
        }}
      >
        <div style={{ maxWidth: "420px" }}>
          <p
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              letterSpacing: "0.04em",
              textTransform: "uppercase",
              color: "var(--text-3)",
              marginBottom: "8px",
            }}
          >
            Preview area
          </p>
          <p
            style={{
              fontSize: "13px",
              color: "var(--text-2)",
              lineHeight: 1.6,
            }}
          >
            This is an experimental information architecture for the MCP
            Sentinel public registry. Live behaviour is unchanged. The proposal
            and removal instructions live in{" "}
            <code
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                background: "var(--surface-3)",
                padding: "2px 6px",
                borderRadius: "4px",
              }}
            >
              packages/web/src/app/preview/README.md
            </code>
            .
          </p>
        </div>

        <nav
          aria-label="Footer navigation"
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "8px",
            fontSize: "13px",
          }}
        >
          <a
            href="/"
            style={{ color: "var(--text-2)", textDecoration: "none" }}
          >
            Live site →
          </a>
          <a
            href="/responsible-disclosure"
            style={{ color: "var(--text-2)", textDecoration: "none" }}
          >
            Responsible disclosure
          </a>
          <a
            href="https://github.com/j420/mcpsentinal"
            style={{ color: "var(--text-2)", textDecoration: "none" }}
            target="_blank"
            rel="noopener noreferrer"
          >
            Source on GitHub
          </a>
        </nav>
      </div>
    </footer>
  );
}
