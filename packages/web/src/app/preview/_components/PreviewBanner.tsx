/**
 * PreviewBanner — visible on every /preview/* route.
 *
 * Makes it impossible for a visitor to accidentally believe they are looking at
 * the live site. Links to the README so internal reviewers can understand what
 * they are looking at.
 */

export default function PreviewBanner() {
  return (
    <div
      role="status"
      style={{
        position: "sticky",
        top: 0,
        zIndex: 100,
        background: "var(--accent-sub)",
        color: "var(--accent-2)",
        borderBottom: "1px solid var(--accent-ring)",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        letterSpacing: "0.02em",
        padding: "8px 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "12px",
        textAlign: "center",
      }}
    >
      <span aria-hidden="true">◐</span>
      <span>
        <strong style={{ fontWeight: 600 }}>Preview</strong>
        {" — experimental information architecture. The live site at "}
        <a
          href="/"
          style={{ color: "var(--accent-2)", textDecoration: "underline" }}
        >
          mcp-sentinel.com
        </a>
        {" is unchanged."}
      </span>
    </div>
  );
}
