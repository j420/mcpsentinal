import CategoryDeepDivePanel from "@/components/CategoryDeepDivePanel";
import { THREAT_CATS } from "@/components/cdd-data";

export const metadata = { title: "Security Rule Taxonomy — MCP Sentinel" };

const totalRules = THREAT_CATS.reduce(
  (sum, cat) => sum + cat.subCats.reduce((s, sc) => s + sc.rules.length, 0),
  0
);
const totalSubCats = THREAT_CATS.reduce((sum, cat) => sum + cat.subCats.length, 0);

export default function TaxonomyPage() {
  return (
    <main style={{ maxWidth: 1200, margin: "0 auto", padding: "var(--s5) var(--s4)" }}>
      {/* Page header */}
      <div style={{ marginBottom: "var(--s5)" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, marginBottom: "var(--s2)" }}>
          Security Rule Taxonomy
        </h1>
        <p style={{ color: "var(--text-3)", fontSize: "14px", marginBottom: "var(--s4)" }}>
          {totalRules} detection rules · {THREAT_CATS.length} threat categories · {totalSubCats} sub-categories · 9 security frameworks
        </p>

        {/* Summary grid */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
          gap: "var(--s2)",
          marginBottom: "var(--s5)",
        }}>
          {THREAT_CATS.map((cat) => {
            const ruleCount = cat.subCats.reduce((s, sc) => s + sc.rules.length, 0);
            return (
              <a
                key={cat.id}
                href={`#cdd-${cat.id}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "10px 14px",
                  background: "var(--surface-1)",
                  border: `1px solid ${cat.color}33`,
                  borderRadius: "8px",
                  textDecoration: "none",
                  color: "inherit",
                }}
              >
                <span style={{ fontSize: "20px" }}>{cat.icon}</span>
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px", color: cat.color }}>{cat.id}</div>
                  <div style={{ fontSize: "11px", color: "var(--text-3)" }}>{ruleCount} rules</div>
                </div>
              </a>
            );
          })}
        </div>
      </div>

      {/* The full panel — no findings means everything shows as clean */}
      <CategoryDeepDivePanel findings={[]} />
    </main>
  );
}
