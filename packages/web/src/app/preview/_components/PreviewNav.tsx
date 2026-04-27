/**
 * PreviewNav — top navigation for the proposed IA.
 *
 * Five top-level slots, each answering a distinct question. Compare to the
 * live nav (Registry / Servers / Categories / MCP Scanner) which has two
 * server-list entries and no entry for Ecosystem or Intelligence.
 */

const NAV_ITEMS: { href: string; label: string; emphasised?: boolean }[] = [
  { href: "/preview/servers", label: "Servers" },
  { href: "/preview/ecosystem", label: "Ecosystem" },
  { href: "/preview/intelligence", label: "Intelligence" },
  { href: "/preview/methodology", label: "Methodology" },
  { href: "/preview/scanner", label: "Scanner", emphasised: true },
];

export default function PreviewNav() {
  return (
    <header
      style={{
        position: "sticky",
        top: 33,
        zIndex: 99,
        background: "rgba(255, 255, 255, 0.85)",
        backdropFilter: "saturate(180%) blur(12px)",
        WebkitBackdropFilter: "saturate(180%) blur(12px)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div
        style={{
          maxWidth: "1200px",
          margin: "0 auto",
          padding: "14px 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "24px",
        }}
      >
        <a
          href="/preview"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            color: "var(--text)",
            textDecoration: "none",
            fontFamily: "var(--font-body)",
            fontWeight: 700,
            letterSpacing: "-0.01em",
          }}
          aria-label="Sentinel preview home"
        >
          <svg
            width="28"
            height="28"
            viewBox="0 0 34 34"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            aria-hidden="true"
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
          <span>Sentinel</span>
        </a>

        <nav
          aria-label="Preview navigation"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "4px",
            flexWrap: "wrap",
          }}
        >
          {NAV_ITEMS.map((item) => (
            <a
              key={item.href}
              href={item.href}
              style={{
                padding: "8px 14px",
                fontSize: "14px",
                fontWeight: 500,
                color: item.emphasised ? "var(--accent)" : "var(--text-2)",
                textDecoration: "none",
                borderRadius: "6px",
                transition: "background 120ms ease, color 120ms ease",
              }}
            >
              {item.label}
            </a>
          ))}
        </nav>
      </div>
    </header>
  );
}
