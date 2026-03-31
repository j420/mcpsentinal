"use client";
import React, { useState, useMemo } from "react";
import EvidenceChainViz from "@/components/EvidenceChainViz";
import type { EvidenceChainData } from "@/components/EvidenceChainViz";
import {
  CddFinding,
  FullFinding,
  RULE_NAMES,
  THREAT_CATS,
  getFrameworkCoverage,
  getFindingsForCategory,
  RULES,
  GAPS,
  ATTACK_STORIES,
  COMPLIANCE_MAP,
  ATLAS_TECHNIQUES,
  computeMaturity,
  computeRemediation,
  type EnrichedRule,
  type RuleEvidenceChain,
  type Gap,
} from "./cdd-data";

export type { CddFinding };
export { THREAT_CATS };

// ── View tab type ───────────────────────────────────────────────────────────
type ViewTab = "tree" | "remediation" | "stories" | "compliance" | "atlas" | "maturity";

const VIEW_TABS: { id: ViewTab; label: string }[] = [
  { id: "tree",        label: "Sub-Category Tree" },
  { id: "remediation", label: "Remediation Roadmap" },
  { id: "stories",     label: "Attack Stories" },
  { id: "compliance",  label: "Compliance Overlay" },
  { id: "atlas",       label: "ATLAS Technique Tree" },
  { id: "maturity",    label: "Maturity Model" },
];

// ── Status helpers ──────────────────────────────────────────────────────────
function statusIcon(status: string): string {
  if (status === "implemented") return "✓";
  if (status === "partial") return "◐";
  return "✗";
}
function statusClass(status: string): string {
  if (status === "implemented") return "cdd-status-impl";
  if (status === "partial") return "cdd-status-partial";
  return "cdd-status-planned";
}

const SEV_ORDER = ["critical", "high", "medium", "low", "informational"] as const;

export default function CategoryDeepDivePanel({ findings, fullFindings }: { findings: CddFinding[]; fullFindings?: FullFinding[] }) {
  const triggered = new Set(findings.map((f) => f.rule_id));
  const [activeView, setActiveView] = useState<ViewTab>("tree");
  const [selectedCat, setSelectedCat] = useState<string | null>(null);
  const [expandedStory, setExpandedStory] = useState<string | null>(null);
  const [expandedAtlas, setExpandedAtlas] = useState<string | null>(null);
  const [expandedRule, setExpandedRule] = useState<string | null>(null);

  // Shared derived data — computed only when a category is selected
  const cat = selectedCat ? THREAT_CATS.find(c => c.id === selectedCat) ?? null : null;
  const catRules = useMemo(() => selectedCat ? RULES.filter(r => r.cat === selectedCat) : [], [selectedCat]);
  const catGaps = useMemo(() => selectedCat ? GAPS.filter(g => g.cat === selectedCat) : [], [selectedCat]);
  const maturity = useMemo(() => computeMaturity(catRules), [catRules]);
  const remediation = useMemo(() => computeRemediation(catRules), [catRules]);

  const allRuleIds = cat ? cat.subCats.flatMap((sc) => sc.rules) : [];
  const catHits = allRuleIds.filter((r) => triggered.has(r));
  const implPct = catRules.length > 0
    ? Math.round((catRules.filter(r => r.status === "implemented").length / catRules.length) * 100)
    : 0;
  const totalTests = catRules.reduce((s, r) => s + r.tests.length, 0);
  const catStories = selectedCat ? ATTACK_STORIES.filter(s => s.cat === selectedCat) : [];

  // Findings for the selected category (with full evidence/remediation)
  const catFullFindings = useMemo(
    () => (fullFindings && selectedCat) ? getFindingsForCategory(selectedCat, fullFindings) : [],
    [selectedCat, fullFindings]
  );
  const catSevCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of catFullFindings) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    return SEV_ORDER.map(s => ({ sev: s, count: counts[s] ?? 0 })).filter(s => s.count > 0);
  }, [catFullFindings]);

  return (
    <section className="cdd-section">
      <div className="cdd-section-header">
        <h2 className="cdd-section-title">Security Category Deep Dive</h2>
      </div>

      <div className="cdd-wrap">
        {/* ── Sidebar ────────────────────────────────────────── */}
        <nav className="cdd-sidebar">
          {THREAT_CATS.map((c) => {
            const cRules = c.subCats.flatMap((sc) => sc.rules);
            const cFindingCount = cRules.filter((r) => triggered.has(r)).length;
            const isActive = c.id === selectedCat;
            return (
              <div key={c.id}>
                <button
                  type="button"
                  className={`cdd-sidebar-item${isActive ? " cdd-sidebar-item-active" : ""}`}
                  style={{ "--cc": c.color } as React.CSSProperties}
                  onClick={() => setSelectedCat(isActive ? null : c.id)}
                >
                  <span className="cdd-sidebar-name">{c.name}</span>
                  {cFindingCount > 0 && (
                    <span className="cdd-sidebar-count">{cFindingCount}</span>
                  )}
                </button>
                {isActive && (
                  <div className="cdd-sidebar-subs">
                    {c.subCats.map((sc) => {
                      const scHits = sc.rules.filter((r) => triggered.has(r)).length;
                      return (
                        <div
                          key={sc.id}
                          className={`cdd-sidebar-subitem${scHits > 0 ? " cdd-sidebar-subitem-hit" : ""}`}
                        >
                          <span className="cdd-sidebar-sub-name">{sc.name}</span>
                          {scHits > 0 && (
                            <span className="cdd-sidebar-sub-count">{scHits}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        {/* ── Detail panel ───────────────────────────────────── */}
        <div className="cdd-detail">
          {!cat ? (
            /* ── No category selected — show category grid ──── */
            <div className="cdd-overview">
              <p className="cdd-overview-intro">Select a category to explore sub-categories, findings, and compliance coverage.</p>
              <div className="cdd-overview-grid">
                {THREAT_CATS.map((c) => {
                  const cRules = c.subCats.flatMap((sc) => sc.rules);
                  const cFindingCount = cRules.filter((r) => triggered.has(r)).length;
                  return (
                    <button
                      key={c.id}
                      type="button"
                      className={`cdd-overview-card${cFindingCount > 0 ? " cdd-overview-card-hit" : ""}`}
                      style={{ "--cc": c.color } as React.CSSProperties}
                      onClick={() => setSelectedCat(c.id)}
                    >
                      <div className="cdd-overview-card-name">{c.name}</div>
                      <div className="cdd-overview-card-meta">
                        <span>{cRules.length} rules</span>
                        {cFindingCount > 0 && (
                          <span className="cdd-overview-card-findings">{cFindingCount} findings</span>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            /* ── Category selected — show detail ──────────── */
            <>
              {/* Category header */}
              <div className="cdd-cat-hdr" style={{ "--cc": cat.color } as React.CSSProperties}>
                <div className="cdd-cat-hdr-left">
                  <div>
                    <div className="cdd-cat-name">{cat.name}</div>
                    <div className="cdd-cat-tagline">{cat.tagline}</div>
                  </div>
                </div>
              </div>

              {/* Stats row */}
              <div className="cdd-stats">
                {[
                  { num: allRuleIds.length, label: "Rules", color: undefined },
                  { num: cat.subCats.length, label: "Sub-Categories", color: undefined },
                  { num: catGaps.length, label: "Gaps", color: catGaps.length > 0 ? "var(--moderate)" : undefined },
                  { num: `${implPct}%`, label: "Implemented", color: implPct >= 80 ? "var(--good)" : implPct >= 50 ? "var(--moderate)" : "var(--critical)" },
                  { num: totalTests, label: "Tests", color: undefined },
                  { num: catStories.length, label: "Stories", color: undefined },
                ].map((s) => (
                  <div key={s.label} className="cdd-stat">
                    <div className="cdd-stat-num" style={s.color ? { color: s.color } : {}}>
                      {s.num}
                    </div>
                    <div className="cdd-stat-label">{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Triggered findings for this category */}
              {catFullFindings.length > 0 && (
                <div className="cdd-findings-section">
                  <div className="cdd-findings-header">
                    <span className="cdd-findings-title">Findings</span>
                    <span className="cdd-findings-count">{catFullFindings.length}</span>
                  </div>
                  <div className="cdd-findings-sevs">
                    {catSevCounts.map(({ sev, count }) => (
                      <span key={sev} className={`cdd-findings-sev cdd-findings-sev-${sev}`}>
                        {count} {sev}
                      </span>
                    ))}
                  </div>
                  <div className="cdd-findings-list">
                    {catFullFindings.map((f) => (
                      <div key={f.id} className={`cdd-finding-card cdd-finding-${f.severity}`}>
                        <div className="cdd-finding-hdr">
                          <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
                          <span className="cdd-finding-rule-id">{f.rule_id}</span>
                          <span className="cdd-finding-rule-name">{RULE_NAMES[f.rule_id] ?? f.rule_id}</span>
                          {f.owasp_category && <span className="cdd-finding-owasp">{f.owasp_category}</span>}
                          {f.mitre_technique && <span className="cdd-finding-mitre">{f.mitre_technique}</span>}
                        </div>
                        <div className="cdd-finding-evidence">{f.evidence}</div>
                        <EvidenceChainViz
                          chain={f.evidence_chain as EvidenceChainData | null | undefined}
                          confidence={f.confidence}
                        />
                        {f.remediation && (
                          <div className="cdd-finding-remediation">{f.remediation}</div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* View tabs */}
              <div className="cdd-view-tabs">
                {VIEW_TABS.map((vt) => (
                  <button
                    key={vt.id}
                    type="button"
                    className={`cdd-view-tab${activeView === vt.id ? " cdd-view-tab-active" : ""}`}
                    onClick={() => setActiveView(vt.id)}
                  >
                    {vt.label}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              {activeView === "tree" && (
                <TreeTab
                  cat={cat}
                  catGaps={catGaps}
                  catRules={catRules}
                  triggered={triggered}
                  allRuleIds={allRuleIds}
                  catHits={catHits}
                  expandedRule={expandedRule}
                  setExpandedRule={setExpandedRule}
                />
              )}
              {activeView === "remediation" && (
                <RemediationTab catColor={cat.color} remediation={remediation} />
              )}
              {activeView === "stories" && (
                <StoriesTab
                  stories={catStories}
                  catColor={cat.color}
                  expandedStory={expandedStory}
                  setExpandedStory={setExpandedStory}
                />
              )}
              {activeView === "compliance" && (
                <ComplianceTab cat={cat} catRules={catRules} />
              )}
              {activeView === "atlas" && (
                <AtlasTab
                  cat={cat}
                  expandedAtlas={expandedAtlas}
                  setExpandedAtlas={setExpandedAtlas}
                />
              )}
              {activeView === "maturity" && (
                <MaturityTab catColor={cat.color} maturity={maturity} />
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// Tab 1: Sub-Category Tree (preserves original layout)
// ══════════════════════════════════════════════════════════════════════════════

interface TreeTabProps {
  cat: (typeof THREAT_CATS)[number];
  catGaps: Gap[];
  catRules: EnrichedRule[];
  triggered: Set<string>;
  allRuleIds: string[];
  catHits: string[];
  expandedRule: string | null;
  setExpandedRule: (id: string | null) => void;
}

function TreeTab({ cat, catGaps, catRules, triggered, allRuleIds, catHits, expandedRule, setExpandedRule }: TreeTabProps) {
  return (
    <div className="cdd-body">
      <div className="cdd-left">
        {cat.subCats.map((sc) => {
          const scHits = sc.rules.filter((r) => triggered.has(r));
          const scPct =
            sc.rules.length > 0
              ? Math.round(((sc.rules.length - scHits.length) / sc.rules.length) * 100)
              : 100;
          const barColor = scPct === 100 ? "var(--good)" : scPct >= 50 ? "var(--moderate)" : "var(--critical)";
          const scGaps = catGaps.filter(g => g.proposedSub === sc.id);
          const scRules = catRules.filter(r => sc.rules.includes(r.id));

          return (
            <div key={sc.id} className={`cdd-subcat${scHits.length > 0 ? " cdd-subcat-hit" : ""}`}>
              <div className="cdd-subcat-hdr">
                <div className="cdd-subcat-meta">
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

              {/* Individual rules with evidence chains */}
              <div className="cdd-rules-list">
                {scRules.map((rule) => {
                  const isExpanded = expandedRule === rule.id;
                  const isTriggered = triggered.has(rule.id);
                  return (
                    <div key={rule.id} className={`cdd-rule-card${isTriggered ? " cdd-rule-triggered" : ""}`}>
                      <button
                        type="button"
                        className="cdd-rule-toggle"
                        onClick={() => setExpandedRule(isExpanded ? null : rule.id)}
                        aria-expanded={isExpanded}
                      >
                        <span className={`sev-badge sev-${rule.severity}`}>{rule.severity}</span>
                        <span className="cdd-rule-id">{rule.id}</span>
                        <span className="cdd-rule-name">{rule.name}</span>
                        <span className={`cdd-rule-status ${statusClass(rule.status)}`}>{statusIcon(rule.status)}</span>
                        <span className="cdd-rule-chevron">{isExpanded ? "\u25B2" : "\u25BC"}</span>
                      </button>
                      {isExpanded && (
                        <div className="cdd-rule-evidence">
                          <div className="cdd-ec-grid">
                            <div className="cdd-ec-item">
                              <div className="cdd-ec-label">WHAT is examined?</div>
                              <div className="cdd-ec-value">{rule.evidenceChain.source}</div>
                            </div>
                            <div className="cdd-ec-item">
                              <div className="cdd-ec-label">WHERE / HOW detected?</div>
                              <div className="cdd-ec-value">{rule.evidenceChain.detection}</div>
                            </div>
                            <div className="cdd-ec-item">
                              <div className="cdd-ec-label">WHY is this dangerous?</div>
                              <div className="cdd-ec-value">{rule.evidenceChain.impact}</div>
                            </div>
                            <div className="cdd-ec-item">
                              <div className="cdd-ec-label">HOW CONFIDENT?</div>
                              <div className="cdd-ec-value">{rule.evidenceChain.confidence_basis}</div>
                            </div>
                            <div className="cdd-ec-item">
                              <div className="cdd-ec-label">HOW TO VERIFY?</div>
                              <div className="cdd-ec-value">{rule.evidenceChain.verification}</div>
                            </div>
                          </div>
                          {rule.tests.length > 0 && (
                            <div className="cdd-rule-tests">
                              <div className="cdd-ec-label">Test Cases</div>
                              {rule.tests.map((t, i) => (
                                <div key={i} className={`cdd-rule-test cdd-rule-test-${t.status}`}>
                                  <span className="cdd-test-icon">{t.status === "pass" ? "\u2713" : "\u2717"}</span>
                                  <span className="cdd-test-label">{t.label}</span>
                                </div>
                              ))}
                            </div>
                          )}
                          {rule.frameworks.length > 0 && (
                            <div className="cdd-rule-fws">
                              {rule.frameworks.map(fw => (
                                <span key={fw} className="cdd-rule-fw-badge">{fw}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Gap cards */}
              {scGaps.map(gap => (
                <div key={gap.id} className="cdd-gap-card">
                  <span className="cdd-gap-id">{gap.id}</span>
                  <span className="cdd-gap-name">{gap.name}</span>
                  <span className="cdd-gap-desc">{gap.desc}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* Right sidebar */}
      <div className="cdd-right">
        <div className="cdd-sidebar-card">
          <div className="cdd-sidebar-title">Framework Coverage</div>
          {getFrameworkCoverage(allRuleIds, cat.frameworks).map((fw) => {
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
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// Tab 2: Remediation Roadmap
// ══════════════════════════════════════════════════════════════════════════════

function RemediationTab({ catColor, remediation }: { catColor: string; remediation: ReturnType<typeof computeRemediation> }) {
  if (remediation.length === 0) {
    return (
      <div className="cdd-empty-tab">
        <span className="cdd-empty-icon">✓</span>
        <p>All rules in this category are fully implemented.</p>
      </div>
    );
  }

  return (
    <div className="cdd-rem-list">
      <div className="cdd-rem-header">
        <span className="cdd-rem-header-label">Rule</span>
        <span className="cdd-rem-header-label">Priority</span>
        <span className="cdd-rem-header-label">Status</span>
        <span className="cdd-rem-header-label">Risk</span>
        <span className="cdd-rem-header-label">Effort</span>
        <span className="cdd-rem-header-label">Failing Tests</span>
        <span className="cdd-rem-header-label">Kill Chain</span>
      </div>
      {remediation.map((item) => {
        const r = item.rule;
        const prioColor = item.priority >= 70 ? "var(--critical)" : item.priority >= 40 ? "var(--moderate)" : "var(--good)";
        return (
          <div key={r.id} className="cdd-rem-row">
            <div className="cdd-rem-rule">
              <span className="cdd-rule-id" style={{ color: catColor }}>{r.id}</span>
              <span className="cdd-rem-name">{r.name}</span>
            </div>
            <div className="cdd-rem-prio">
              <div className="cdd-rem-prio-bar-wrap">
                <div className="cdd-rem-prio-bar" style={{ width: `${item.priority}%`, background: prioColor }} />
              </div>
              <span className="cdd-rem-prio-val" style={{ color: prioColor }}>{item.priority}</span>
            </div>
            <span className={`cdd-badge ${statusClass(r.status)}`}>
              {statusIcon(r.status)} {r.status}
            </span>
            <span className={`cdd-badge cdd-risk-${r.risk}`}>{r.risk}</span>
            <span className={`cdd-badge cdd-effort-${r.effort}`}>{r.effort}</span>
            <span className="cdd-rem-tests-fail">
              {item.failingTests > 0 ? (
                <><span className="cdd-rem-fail-num">{item.failingTests}</span> failing</>
              ) : (
                <span className="cdd-rem-pass">all passing</span>
              )}
            </span>
            <span className="cdd-rem-phase">{r.killChainPhase}</span>
          </div>
        );
      })}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// Tab 3: Attack Stories
// ══════════════════════════════════════════════════════════════════════════════

interface StoriesTabProps {
  stories: typeof ATTACK_STORIES;
  catColor: string;
  expandedStory: string | null;
  setExpandedStory: (id: string | null) => void;
}

function StoriesTab({ stories, catColor, expandedStory, setExpandedStory }: StoriesTabProps) {
  if (stories.length === 0) {
    return (
      <div className="cdd-empty-tab">
        <span className="cdd-empty-icon">📖</span>
        <p>No attack stories mapped to this category yet.</p>
      </div>
    );
  }

  return (
    <div className="cdd-stories-list">
      {stories.map((story) => {
        const isOpen = expandedStory === story.id;
        // Derive defense grade from how many involved rules are implemented
        const allInvolved = story.narrative.flatMap(n => n.rulesInvolved);
        const uniqueRules = [...new Set(allInvolved)];
        const implRules = uniqueRules.filter(rId => {
          const rule = RULES.find(r => r.id === rId);
          return rule?.status === "implemented";
        });
        const defenseRatio = uniqueRules.length > 0 ? implRules.length / uniqueRules.length : 0;
        const defenseGrade = defenseRatio >= 0.8 ? "A" : defenseRatio >= 0.6 ? "B" : defenseRatio >= 0.4 ? "C" : defenseRatio >= 0.2 ? "D" : "F";
        const gradeColor = defenseRatio >= 0.6 ? "var(--good)" : defenseRatio >= 0.4 ? "var(--moderate)" : "var(--critical)";

        return (
          <div key={story.id} className={`cdd-story${isOpen ? " cdd-story-open" : ""}`}>
            <button
              type="button"
              className="cdd-story-header"
              onClick={() => setExpandedStory(isOpen ? null : story.id)}
            >
              <div className="cdd-story-left">
                <span className="cdd-story-sev" style={{ background: story.severity === "critical" ? "var(--sev-critical)" : "var(--sev-high)" }}>
                  {story.severity}
                </span>
                <div>
                  <div className="cdd-story-name">{story.name}</div>
                  <div className="cdd-story-summary">{story.summary}</div>
                </div>
              </div>
              <div className="cdd-story-right">
                <div className="cdd-story-grade" style={{ color: gradeColor, borderColor: gradeColor }}>
                  {defenseGrade}
                </div>
                <span className={`cdd-expand-arrow${isOpen ? " cdd-expand-arrow-up" : ""}`}>▼</span>
              </div>
            </button>

            {isOpen && (
              <div className="cdd-story-body">
                <div className="cdd-story-timeline">
                  {story.narrative.map((step, idx) => (
                    <div key={idx} className="cdd-story-step">
                      <div className="cdd-story-step-connector">
                        <div className="cdd-story-step-dot" style={{ background: catColor }} />
                        {idx < story.narrative.length - 1 && <div className="cdd-story-step-line" style={{ background: catColor + "33" }} />}
                      </div>
                      <div className="cdd-story-step-content">
                        <div className="cdd-story-step-phase">{step.phase}</div>
                        <div className="cdd-story-step-title">{step.title}</div>
                        <div className="cdd-story-step-desc">{step.desc}</div>
                        <div className="cdd-story-step-rules">
                          {step.rulesInvolved.map(rId => {
                            const rule = RULES.find(r => r.id === rId);
                            const st = rule?.status ?? "planned";
                            return (
                              <span key={rId} className={`cdd-badge ${statusClass(st)}`}>
                                {statusIcon(st)} {rId}
                              </span>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {story.gapExposure.length > 0 && (
                  <div className="cdd-story-gaps">
                    <div className="cdd-detail-heading">Gap Exposure</div>
                    {story.gapExposure.map(gapId => {
                      const gap = GAPS.find(g => g.id === gapId);
                      return gap ? (
                        <div key={gapId} className="cdd-gap-card">
                          <span className="cdd-gap-id">{gap.id}</span>
                          <span className="cdd-gap-name">{gap.name}</span>
                        </div>
                      ) : null;
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// Tab 4: Compliance Overlay
// ══════════════════════════════════════════════════════════════════════════════

function ComplianceTab({ cat, catRules }: { cat: (typeof THREAT_CATS)[number]; catRules: EnrichedRule[] }) {
  return (
    <div className="cdd-compliance">
      {cat.subCats.map(sc => {
        const entries = COMPLIANCE_MAP[sc.id] ?? [];
        if (entries.length === 0) return null;

        const allReqs = entries.flatMap(e => e.requirements);
        const coveredCount = allReqs.filter(r => r.covered).length;
        const pct = allReqs.length > 0 ? Math.round((coveredCount / allReqs.length) * 100) : 0;
        const scGaps = GAPS.filter(g => g.proposedSub === sc.id);

        return (
          <div key={sc.id} className="cdd-comp-subcat">
            <div className="cdd-comp-subcat-hdr">
              <span className="cdd-subcat-id" style={{ color: cat.color }}>{sc.id}</span>
              <span className="cdd-subcat-name">{sc.name}</span>
              <span className="cdd-comp-pct" style={{ color: pct >= 80 ? "var(--good)" : pct >= 50 ? "var(--moderate)" : "var(--critical)" }}>
                {pct}% covered
              </span>
            </div>

            {entries.map(fw => (
              <div key={fw.framework} className="cdd-comp-fw">
                <div className="cdd-comp-fw-header">
                  <span className="cdd-comp-fw-dot" style={{ background: fw.color }} />
                  <span className="cdd-comp-fw-name">{fw.framework}</span>
                  <span className="cdd-comp-fw-count">
                    {fw.requirements.filter(r => r.covered).length}/{fw.requirements.length}
                  </span>
                </div>
                <div className="cdd-comp-reqs">
                  {fw.requirements.map(req => (
                    <div key={req.id} className={`cdd-comp-req${req.covered ? " cdd-comp-req-covered" : ""}`}>
                      <span className="cdd-comp-req-icon">{req.covered ? "✓" : "✗"}</span>
                      <span className="cdd-comp-req-ctrl">{req.control}</span>
                      <span className="cdd-comp-req-desc">{req.desc}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {scGaps.length > 0 && (
              <div className="cdd-comp-gaps">
                {scGaps.map(gap => (
                  <div key={gap.id} className="cdd-gap-card">
                    <span className="cdd-gap-id">{gap.id}</span>
                    <span className="cdd-gap-name">{gap.name}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// Tab 5: ATLAS Technique Tree
// ══════════════════════════════════════════════════════════════════════════════

function AtlasTab({ cat, expandedAtlas, setExpandedAtlas }: {
  cat: (typeof THREAT_CATS)[number];
  expandedAtlas: string | null;
  setExpandedAtlas: (id: string | null) => void;
}) {
  const catTechniques = ATLAS_TECHNIQUES.filter(t => t.cat === cat.id);

  if (catTechniques.length === 0) {
    return (
      <div className="cdd-empty-tab">
        <span className="cdd-empty-icon">🎯</span>
        <p>No ATLAS techniques mapped to this category.</p>
      </div>
    );
  }

  return (
    <div className="cdd-atlas">
      {catTechniques.map(tech => {
        const isOpen = expandedAtlas === tech.id;
        // Overall technique coverage
        const allRuleIds = tech.subTechniques.flatMap(st => st.rules);
        const unique = [...new Set(allRuleIds)];
        const implCount = unique.filter(rId => RULES.find(r => r.id === rId)?.status === "implemented").length;
        const techCovPct = unique.length > 0 ? Math.round((implCount / unique.length) * 100) : 0;

        return (
          <div key={tech.id} className="cdd-atlas-tech">
            <button
              type="button"
              className="cdd-atlas-tech-header"
              onClick={() => setExpandedAtlas(isOpen ? null : tech.id)}
            >
              <div className="cdd-atlas-tech-left">
                <span className="cdd-atlas-tech-id">{tech.id}</span>
                <span className="cdd-atlas-tech-name">{tech.name}</span>
              </div>
              <div className="cdd-atlas-tech-right">
                <div className="cdd-atlas-cov-bar-wrap">
                  <div
                    className="cdd-atlas-cov-bar"
                    style={{
                      width: `${techCovPct}%`,
                      background: techCovPct >= 80 ? "var(--good)" : techCovPct >= 50 ? "var(--moderate)" : "var(--critical)",
                    }}
                  />
                </div>
                <span className="cdd-atlas-cov-pct">{techCovPct}%</span>
                <span className={`cdd-expand-arrow${isOpen ? " cdd-expand-arrow-up" : ""}`}>▼</span>
              </div>
            </button>

            {isOpen && (
              <div className="cdd-atlas-subs">
                {tech.subTechniques.map(sub => {
                  const subRules = sub.rules.map(rId => RULES.find(r => r.id === rId)).filter(Boolean) as EnrichedRule[];
                  const allImpl = subRules.length > 0 && subRules.every(r => r.status === "implemented");
                  const someImpl = subRules.some(r => r.status === "implemented" || r.status === "partial");
                  const borderColor = allImpl ? "var(--good)" : someImpl ? "var(--moderate)" : "var(--critical)";
                  const dotColor = borderColor;

                  return (
                    <div key={sub.id} className="cdd-atlas-sub" style={{ borderLeftColor: borderColor }}>
                      <div className="cdd-atlas-sub-header">
                        <span className="cdd-atlas-sub-dot" style={{ background: dotColor }} />
                        <span className="cdd-atlas-sub-id">{sub.id}</span>
                        <span className="cdd-atlas-sub-name">{sub.name}</span>
                      </div>
                      <div className="cdd-atlas-sub-rules">
                        {subRules.map(rule => (
                          <span key={rule.id} className={`cdd-badge ${statusClass(rule.status)}`}>
                            {statusIcon(rule.status)} {rule.id} {rule.name.length > 25 ? rule.name.slice(0, 25) + "..." : rule.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// Tab 6: Maturity Model
// ══════════════════════════════════════════════════════════════════════════════

function MaturityTab({ catColor, maturity }: { catColor: string; maturity: ReturnType<typeof computeMaturity> }) {
  const levelColors = ["", "var(--critical)", "var(--sev-high)", "var(--moderate)", "var(--good)", "var(--accent)"];

  return (
    <div className="cdd-maturity-tab">
      {/* Overall maturity hero */}
      <div className="cdd-mat-hero">
        <div className="cdd-mat-hero-score" style={{ color: levelColors[maturity.level] }}>
          {maturity.overall}
        </div>
        <div className="cdd-mat-hero-meta">
          <div className="cdd-mat-hero-level">
            Level {maturity.level}: {maturity.levelLabel}
          </div>
          <div className="cdd-mat-hero-scale">
            {[1, 2, 3, 4, 5].map(lvl => (
              <span
                key={lvl}
                className={`cdd-mat-level-dot${lvl <= maturity.level ? " cdd-mat-level-active" : ""}`}
                style={lvl <= maturity.level ? { background: levelColors[maturity.level] } : {}}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Dimension bars */}
      <div className="cdd-mat-dims">
        <div className="cdd-detail-heading">Maturity Dimensions</div>
        {maturity.dimensions.map(dim => {
          const dimColor = dim.score >= 80 ? "var(--good)" : dim.score >= 50 ? "var(--moderate)" : "var(--critical)";
          return (
            <div key={dim.name} className="cdd-mat-dim">
              <div className="cdd-mat-dim-header">
                <span className="cdd-mat-dim-name">{dim.name}</span>
                <span className="cdd-mat-dim-weight">{dim.weight}%</span>
                <span className="cdd-mat-dim-score" style={{ color: dimColor }}>{dim.score}</span>
              </div>
              <div className="cdd-mat-dim-bar-wrap">
                <div className="cdd-mat-dim-bar" style={{ width: `${dim.score}%`, background: dimColor }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Per-rule maturity */}
      <div className="cdd-mat-rules">
        <div className="cdd-detail-heading">Per-Rule Maturity Scores</div>
        <div className="cdd-mat-rules-grid">
          {maturity.perRule.map(pr => {
            const ruleColor = pr.score >= 80 ? "var(--good)" : pr.score >= 50 ? "var(--moderate)" : "var(--critical)";
            return (
              <div key={pr.id} className="cdd-mat-rule-card">
                <div className="cdd-mat-rule-top">
                  <span className="cdd-rule-id" style={{ color: catColor }}>{pr.id}</span>
                  <span className={`cdd-badge ${statusClass(pr.status)}`}>
                    {statusIcon(pr.status)} {pr.status}
                  </span>
                </div>
                <div className="cdd-mat-rule-name">{pr.name}</div>
                <div className="cdd-mat-rule-bar-wrap">
                  <div className="cdd-mat-rule-bar" style={{ width: `${pr.score}%`, background: ruleColor }} />
                </div>
                <div className="cdd-mat-rule-score" style={{ color: ruleColor }}>{pr.score}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
