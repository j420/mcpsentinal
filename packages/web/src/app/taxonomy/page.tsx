import CategoryDeepDivePanel from "@/components/CategoryDeepDivePanel";
import { THREAT_CATS } from "@/components/cdd-data";

import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Security Rule Taxonomy — 177 Detection Rules",
  description:
    "Browse all 177 MCP security detection rules across 17 categories. Covers prompt injection, tool poisoning, supply chain attacks, OAuth vulnerabilities, protocol edge cases, and more. Each rule maps to OWASP MCP Top 10 and MITRE ATLAS.",
  openGraph: {
    title: "177 MCP Security Detection Rules — MCP Sentinel",
    description: "Browse all detection rules: prompt injection, tool poisoning, supply chain, OAuth, protocol attacks.",
  },
};

const totalRules = THREAT_CATS.reduce(
  (sum, cat) => sum + cat.subCats.reduce((s, sc) => s + sc.rules.length, 0),
  0
);
const totalSubCats = THREAT_CATS.reduce((sum, cat) => sum + cat.subCats.length, 0);

const SEV_COUNTS = { critical: 0, high: 0, medium: 0, low: 0 };
// Count severities across all rules (simplified view)
const allRuleIds = THREAT_CATS.flatMap((c) => c.subCats.flatMap((sc) => sc.rules));

export default function TaxonomyPage() {
  return (
    <div className="tax-page">
      {/* Hero header */}
      <div className="tax-hero">
        <div className="tax-hero-eyebrow">Detection Engine</div>
        <h1 className="tax-hero-title">Security Rule Taxonomy</h1>
        <p className="tax-hero-sub">
          {totalRules} detection rules across {THREAT_CATS.length} threat categories and {totalSubCats} sub-categories.
          Every rule is backed by OWASP, MITRE ATLAS, or real-world CVEs. No LLMs. Deterministic.
        </p>
      </div>

      {/* Category quick-nav grid */}
      <div className="tax-nav-grid">
        {THREAT_CATS.map((cat) => {
          const ruleCount = cat.subCats.reduce((s, sc) => s + sc.rules.length, 0);
          return (
            <a
              key={cat.id}
              href={`#cdd-${cat.id}`}
              className="tax-nav-card"
              style={{ "--tax-cc": cat.color } as React.CSSProperties}
            >
              <div className="tax-nav-icon">{cat.icon}</div>
              <div className="tax-nav-info">
                <span className="tax-nav-code">{cat.id}</span>
                <span className="tax-nav-name">{cat.name}</span>
              </div>
              <span className="tax-nav-count">{ruleCount}</span>
            </a>
          );
        })}
      </div>

      {/* Stats strip */}
      <div className="tax-stats">
        <div className="tax-stat">
          <span className="tax-stat-val">{totalRules}</span>
          <span className="tax-stat-label">Rules</span>
        </div>
        <div className="tax-stat">
          <span className="tax-stat-val">{THREAT_CATS.length}</span>
          <span className="tax-stat-label">Categories</span>
        </div>
        <div className="tax-stat">
          <span className="tax-stat-val">{totalSubCats}</span>
          <span className="tax-stat-label">Sub-categories</span>
        </div>
        <div className="tax-stat">
          <span className="tax-stat-val">9</span>
          <span className="tax-stat-label">Frameworks</span>
        </div>
        <div className="tax-stat">
          <span className="tax-stat-val">4</span>
          <span className="tax-stat-label">Handler Types</span>
        </div>
      </div>

      {/* The full deep-dive panel */}
      <CategoryDeepDivePanel findings={[]} />
    </div>
  );
}
