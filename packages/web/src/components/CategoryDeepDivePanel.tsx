"use client";
import React, { useState, useCallback } from "react";
import {
  CddFinding,
  RULE_NAMES,
  RULE_SEVERITIES,
  THREAT_CATS,
  CAT_VECTORS,
  CAT_MITIGATIONS,
  RULE_TESTS,
  getRuleFrameworks,
  getFrameworkCoverage,
} from "./cdd-data";

export type { CddFinding };
export { THREAT_CATS };

export default function CategoryDeepDivePanel({ findings }: { findings: CddFinding[] }) {
  const triggered = new Set(findings.map((f) => f.rule_id));
  const [expandedRule, setExpandedRule] = useState<string | null>(null);

  const toggleRule = useCallback((ruleId: string) => {
    setExpandedRule((prev) => (prev === ruleId ? null : ruleId));
  }, []);

  const defaultCat = "PI";

  return (
    <section className="cdd-section">
      <div className="cdd-section-header">
        <h2 className="cdd-section-title">Security Category Deep Dive</h2>
        <p className="cdd-section-sub">
          Sub-Category Tree · Framework Coverage · Kill Chain · Compliance Overlay
        </p>
      </div>

      <div className="cdd-wrap">
        {/* Tab bar — full names in two rows */}
        <div className="cdd-tabs">
          {THREAT_CATS.map((cat) => {
            const catRules = cat.subCats.flatMap((sc) => sc.rules);
            const catFindings = catRules.filter((r) => triggered.has(r)).length;
            return (
              <label
                key={cat.id}
                htmlFor={`cdd-${cat.id}`}
                className="cdd-tab"
                style={{ "--cc": cat.color } as React.CSSProperties}
              >
                <span className="cdd-tab-icon">{cat.icon}</span>
                <span className="cdd-tab-name">{cat.name}</span>
                {catFindings > 0 && <span className="cdd-tab-dot" />}
              </label>
            );
          })}
        </div>

        {/* Radio+panel pairs — input MUST directly precede its panel for CSS + combinator */}
        {THREAT_CATS.map((cat) => {
          const allRules = cat.subCats.flatMap((sc) => sc.rules);
          const catHits = allRules.filter((r) => triggered.has(r));

          return (
            <React.Fragment key={cat.id}>
              <input
                type="radio"
                name="cdd-cat"
                id={`cdd-${cat.id}`}
                className="cdd-radio"
                defaultChecked={cat.id === defaultCat}
              />
              <div className="cdd-panel">
                {/* Category header */}
                <div className="cdd-cat-hdr" style={{ "--cc": cat.color } as React.CSSProperties}>
                  <div className="cdd-cat-hdr-left">
                    <span className="cdd-cat-icon">{cat.icon}</span>
                    <div>
                      <div className="cdd-cat-name">{cat.name}</div>
                      <div className="cdd-cat-tagline">{cat.tagline}</div>
                    </div>
                  </div>
                </div>

                {/* Stats row */}
                <div className="cdd-stats">
                  {[
                    { num: allRules.length, label: "RULES", color: undefined },
                    { num: catHits.length, label: "FINDINGS", color: catHits.length > 0 ? "var(--critical)" : "var(--good)" },
                    { num: cat.frameworks.length, label: "FRAMEWORKS", color: undefined },
                  ].map((s) => (
                    <div key={s.label} className="cdd-stat">
                      <div className="cdd-stat-num" style={s.color ? { color: s.color } : {}}>
                        {s.num}
                      </div>
                      <div className="cdd-stat-label">{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Body: left tree + right sidebar */}
                <div className="cdd-body">
                  {/* Left — sub-category tree */}
                  <div className="cdd-left">
                    {cat.subCats.map((sc) => {
                      const scHits = sc.rules.filter((r) => triggered.has(r));
                      const scPct =
                        sc.rules.length > 0
                          ? Math.round(((sc.rules.length - scHits.length) / sc.rules.length) * 100)
                          : 100;
                      const barColor = scPct === 100 ? "var(--good)" : scPct >= 50 ? "var(--moderate)" : "var(--critical)";

                      return (
                        <div key={sc.id} className={`cdd-subcat${scHits.length > 0 ? " cdd-subcat-hit" : ""}`}>
                          <div className="cdd-subcat-hdr">
                            <div className="cdd-subcat-meta">
                              <span className="cdd-subcat-id" style={{ color: cat.color }}>{sc.id}</span>
                              <span className="cdd-subcat-name">{sc.name}</span>
                            </div>
                            <div className="cdd-subcat-right">
                              <div className="cdd-bar-wrap">
                                <div className="cdd-bar" style={{ width: `${scPct}%`, background: barColor }} />
                              </div>
                              <span className="cdd-pct" style={{ color: barColor }}>{scPct}%</span>
                              <span className="cdd-badge cdd-badge-rules">{sc.rules.length} rules</span>
                              {scHits.length > 0 && (
                                <span className="cdd-badge cdd-badge-hit">{scHits.length} found</span>
                              )}
                            </div>
                          </div>
                          <div className="cdd-subcat-desc">{sc.desc}</div>

                          {/* Rule rows */}
                          <div className="cdd-rule-list">
                            {sc.rules.map((ruleId) => {
                              const isHit = triggered.has(ruleId);
                              const isOpen = expandedRule === ruleId;
                              const sev = RULE_SEVERITIES[ruleId] ?? "medium";
                              const catPrefix = ruleId.replace(/\d+$/, "");
                              const vectors = CAT_VECTORS[catPrefix] ?? ["Tool metadata", "Server analysis"];
                              const mitigations = CAT_MITIGATIONS[catPrefix] ?? ["Apply security best practices"];
                              const tests = RULE_TESTS[ruleId] ?? [
                                "True positive: malicious payload detected",
                                "True positive: variant pattern detected",
                                "True negative: safe pattern passes",
                                "True negative: sanitized input passes",
                              ];
                              const fwBadges = getRuleFrameworks(ruleId);
                              return (
                                <div
                                  key={ruleId}
                                  className={`cdd-rule${isHit ? " cdd-rule-hit" : " cdd-rule-clean"}${isOpen ? " cdd-rule-open" : ""}`}
                                >
                                  <button
                                    type="button"
                                    className="cdd-rule-summary"
                                    onClick={() => toggleRule(ruleId)}
                                    aria-expanded={isOpen}
                                  >
                                    <span className="cdd-rule-id" style={{ color: cat.color }}>{ruleId}</span>
                                    <span className={`cdd-sev-dot cdd-sev-${sev}`} />
                                    <span className="cdd-rule-name">{RULE_NAMES[ruleId] ?? ruleId}</span>
                                    <div className="cdd-rule-right">
                                      {isHit ? (
                                        <span className="cdd-badge cdd-badge-triggered">triggered</span>
                                      ) : (
                                        <span className="cdd-badge cdd-badge-clean">clean</span>
                                      )}
                                      <span className="cdd-tests">{tests.length}✓</span>
                                      <span className={`cdd-expand-arrow${isOpen ? " cdd-expand-arrow-up" : ""}`}>▼</span>
                                    </div>
                                  </button>
                                  {isOpen && (
                                    <div className="cdd-rule-detail">
                                      <div className="cdd-rule-detail-sections">
                                        <div className="cdd-detail-section cdd-detail-tests">
                                          <div className="cdd-detail-heading">Tests</div>
                                          <div className="cdd-detail-grid">
                                            {tests.map((t, ti) => (
                                              <div key={ti} className="cdd-detail-item cdd-detail-test">
                                                <span className="cdd-detail-check">✓</span>
                                                <span>{t}</span>
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                        <div className="cdd-detail-right-col">
                                          <div className="cdd-detail-section">
                                            <div className="cdd-detail-heading">Attack Vectors</div>
                                            <div className="cdd-detail-grid">
                                              {vectors.map((v, vi) => (
                                                <div key={vi} className="cdd-detail-item cdd-detail-vector">
                                                  <span className="cdd-detail-bar" style={{ background: cat.color }} />
                                                  <span>{v}</span>
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                          <div className="cdd-detail-section">
                                            <div className="cdd-detail-heading">Mitigations</div>
                                            <div className="cdd-detail-grid">
                                              {mitigations.map((m, mi) => (
                                                <div key={mi} className="cdd-detail-item cdd-detail-mitigation">
                                                  <span className="cdd-detail-arrow">→</span>
                                                  <span>{m}</span>
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        </div>
                                      </div>
                                      {fwBadges.length > 0 && (
                                        <div className="cdd-fw-badges">
                                          {fwBadges.map((fw) => (
                                            <span
                                              key={fw.abbr}
                                              className="cdd-fw-pill"
                                              style={{ background: fw.color + "22", color: fw.color, borderColor: fw.color + "44" }}
                                            >
                                              {fw.abbr}
                                            </span>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Right sidebar */}
                  <div className="cdd-right">
                    <div className="cdd-sidebar-card">
                      <div className="cdd-sidebar-title">Framework Coverage</div>
                      {getFrameworkCoverage(allRules, cat.frameworks).map((fw) => {
                        const fwPct = fw.total > 0 ? Math.round((fw.covered / fw.total) * 100) : 0;
                        return (
                          <div key={fw.name} className="cdd-fw-row">
                            <span className="cdd-fw-name">{fw.name}</span>
                            <span className="cdd-fw-count" style={{ color: cat.color }}>
                              {fw.covered}/{fw.total}
                            </span>
                            <div className="cdd-fw-bar-wrap">
                              <div className="cdd-fw-bar" style={{ width: `${fwPct}%`, background: cat.color }} />
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="cdd-sidebar-card">
                      <div className="cdd-sidebar-title">Kill Chain Phases</div>
                      {cat.killChain.map((phase, idx) => {
                        const phaseCount =
                          catHits.length > 0
                            ? Math.max(1, Math.ceil((catHits.length * (cat.killChain.length - idx)) / (cat.killChain.length * (cat.killChain.length + 1) / 2)))
                            : 0;
                        return (
                          <div key={phase} className="cdd-kc-row">
                            <span
                              className="cdd-kc-badge"
                              style={{
                                background: phaseCount > 0 ? cat.color : "var(--surface-3)",
                                color: phaseCount > 0 ? "#fff" : "var(--text-3)",
                              }}
                            >
                              {phaseCount}
                            </span>
                            <span className="cdd-kc-phase">{phase}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>
    </section>
  );
}
