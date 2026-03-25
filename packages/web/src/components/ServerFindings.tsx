"use client";

import React, { useState, useMemo } from "react";
import {
  THREAT_CATS,
  THREAT_CAT_DEV_TAGLINES,
  RULE_NAMES,
  RULE_SEVERITIES,
  SEV_ICONS,
} from "./cdd-data";
import type { ThreatCat } from "./cdd-data";

// ── Types ───────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
}

interface Tool {
  name: string;
  description: string | null;
  capability_tags: string[];
}

interface ServerFindingsProps {
  findings: Finding[];
  tools: Tool[];
  lastScannedAt: string | null;
}

// ── Constants ───────────────────────────────────────────────────────────────

const SEV_ORDER = ["critical", "high", "medium", "low", "informational"] as const;
type Severity = (typeof SEV_ORDER)[number];

// Rule prefixes that apply to specific tools (description/schema-level rules)
const TOOL_LEVEL_PREFIXES = new Set(["A", "B", "F", "G", "I"]);

// ── Helpers ─────────────────────────────────────────────────────────────────

function worstSeverity(findings: Finding[]): Severity {
  for (const sev of SEV_ORDER) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return "informational";
}

function buildRuleToCatMap(): Map<string, string> {
  const m = new Map<string, string>();
  for (const cat of THREAT_CATS) {
    for (const sc of cat.subCats) {
      for (const ruleId of sc.rules) {
        m.set(ruleId, cat.id);
      }
    }
  }
  return m;
}

function mapFindingsToTools(
  findings: Finding[],
  tools: Tool[]
): Map<string, Finding[]> {
  const m = new Map<string, Finding[]>();
  m.set("__server_wide__", []);
  for (const tool of tools) m.set(tool.name, []);

  for (const f of findings) {
    const prefix = f.rule_id.replace(/\d+$/, "");
    if (!TOOL_LEVEL_PREFIXES.has(prefix)) {
      m.get("__server_wide__")!.push(f);
      continue;
    }
    // Try to match tool name in evidence
    let matched = false;
    for (const tool of tools) {
      if (f.evidence.includes(tool.name)) {
        m.get(tool.name)!.push(f);
        matched = true;
        break;
      }
    }
    if (!matched) m.get("__server_wide__")!.push(f);
  }
  return m;
}

// ── Sub-Components ──────────────────────────────────────────────────────────

function SevIcon({ severity }: { severity: string }) {
  const icon = SEV_ICONS[severity] ?? SEV_ICONS.informational;
  return (
    <span className={`sd-sev-icon sd-sev-icon-${severity}`}>
      <svg viewBox={icon.viewBox} aria-hidden="true">
        <path d={icon.d} />
      </svg>
    </span>
  );
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      className={`sd-cat-chevron${open ? " sd-cat-chevron-open" : ""}`}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <path d="M6 4l4 4-4 4" />
    </svg>
  );
}

function FindingRow({
  finding,
  expanded,
  onToggle,
  remediationExpanded,
  onToggleRemediation,
}: {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  remediationExpanded: boolean;
  onToggleRemediation: () => void;
}) {
  return (
    <div className="sd-finding-row" role="row">
      <div
        className="sd-finding-row-summary"
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
      >
        <SevIcon severity={finding.severity} />
        <span className={`sev-badge sev-${finding.severity}`}>
          {finding.severity}
        </span>
        <span className="sd-finding-rule">{finding.rule_id}</span>
        <span className="sd-finding-name">
          {RULE_NAMES[finding.rule_id] ?? finding.rule_id}
        </span>
      </div>
      <div className="sd-finding-row-tags">
        {finding.owasp_category && (
          <span className="sd-finding-owasp">{finding.owasp_category}</span>
        )}
        {finding.mitre_technique && (
          <span className="sd-finding-mitre">{finding.mitre_technique}</span>
        )}
      </div>

      {expanded && (
        <div className="sd-finding-detail">
          <div className="sd-finding-evidence-text">{finding.evidence}</div>
          {finding.remediation && (
            <>
              <button
                className="sd-finding-fix-toggle"
                onClick={(e) => {
                  e.stopPropagation();
                  onToggleRemediation();
                }}
                aria-expanded={remediationExpanded}
              >
                {remediationExpanded ? "▾" : "▸"} How to fix
              </button>
              {remediationExpanded && (
                <div className="sd-finding-fix-content">
                  {finding.remediation}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export default function ServerFindings({
  findings,
  tools,
  lastScannedAt,
}: ServerFindingsProps) {
  // ── Derived data ──
  const ruleToCat = useMemo(() => buildRuleToCatMap(), []);

  const categoryData = useMemo(() => {
    const grouped = new Map<string, Finding[]>();
    for (const cat of THREAT_CATS) grouped.set(cat.id, []);
    for (const f of findings) {
      const catId = ruleToCat.get(f.rule_id);
      if (catId && grouped.has(catId)) {
        grouped.get(catId)!.push(f);
      }
    }
    return grouped;
  }, [findings, ruleToCat]);

  const toolFindingsMap = useMemo(
    () => mapFindingsToTools(findings, tools),
    [findings, tools]
  );

  const catsWithFindings = useMemo(
    () =>
      THREAT_CATS.filter((cat) => (categoryData.get(cat.id)?.length ?? 0) > 0)
        .sort((a, b) => {
          const sa = SEV_ORDER.indexOf(worstSeverity(categoryData.get(a.id)!));
          const sb = SEV_ORDER.indexOf(worstSeverity(categoryData.get(b.id)!));
          return sa - sb;
        }),
    [categoryData]
  );

  const cleanCats = useMemo(
    () =>
      THREAT_CATS.filter(
        (cat) => (categoryData.get(cat.id)?.length ?? 0) === 0
      ),
    [categoryData]
  );

  const toolsWithFindings = useMemo(
    () =>
      Array.from(toolFindingsMap.entries())
        .filter(([, fs]) => fs.length > 0)
        .sort((a, b) => {
          const sa = SEV_ORDER.indexOf(worstSeverity(a[1]));
          const sb = SEV_ORDER.indexOf(worstSeverity(b[1]));
          return sa - sb;
        }),
    [toolFindingsMap]
  );

  const toolsWithoutFindings = useMemo(
    () => tools.filter((t) => (toolFindingsMap.get(t.name)?.length ?? 0) === 0),
    [tools, toolFindingsMap]
  );

  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const sev of SEV_ORDER) counts[sev] = 0;
    for (const f of findings) counts[f.severity]++;
    return SEV_ORDER.map((sev) => ({ sev, count: counts[sev] }));
  }, [findings]);

  // ── State ──
  const [activeTab, setActiveTab] = useState<"categories" | "by-tool">(
    "categories"
  );
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    () => new Set(catsWithFindings.map((c) => c.id))
  );
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(() => {
    // Smart auto-expand: if a category has 1-3 findings, expand them
    const s = new Set<string>();
    for (const cat of catsWithFindings) {
      const fs = categoryData.get(cat.id) ?? [];
      if (fs.length <= 3) {
        for (const f of fs) s.add(f.id);
      }
    }
    return s;
  });
  const [expandedRemediation, setExpandedRemediation] = useState<Set<string>>(
    new Set()
  );
  const [showCleanCats, setShowCleanCats] = useState(false);

  // ── Tool-group expand state ──
  const [expandedToolGroups, setExpandedToolGroups] = useState<Set<string>>(
    () => new Set(toolsWithFindings.map(([name]) => name))
  );

  // ── Toggle helpers ──
  const toggleCategory = (id: string) =>
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const toggleFinding = (id: string) =>
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const toggleRemediation = (id: string) =>
    setExpandedRemediation((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const toggleToolGroup = (name: string) =>
    setExpandedToolGroups((prev) => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });

  // ── Verdict ──
  const verdict = useMemo(() => {
    if (!lastScannedAt)
      return {
        level: "gray" as const,
        text: "Awaiting security scan",
        sub: "This server has not been scanned yet.",
        icon: "⏳",
      };
    const hasCritical = findings.some((f) => f.severity === "critical");
    const hasHigh = findings.some((f) => f.severity === "high");
    if (hasCritical)
      return {
        level: "red" as const,
        text: "Not recommended — critical issues found",
        sub: `${findings.length} finding${findings.length !== 1 ? "s" : ""} detected across ${catsWithFindings.length} categor${catsWithFindings.length !== 1 ? "ies" : "y"}.`,
        icon: "🛑",
      };
    if (hasHigh)
      return {
        level: "amber" as const,
        text: "Review recommended — high-severity issues found",
        sub: `${findings.length} finding${findings.length !== 1 ? "s" : ""} detected. No critical issues.`,
        icon: "⚠️",
      };
    if (findings.length > 0)
      return {
        level: "green" as const,
        text: "Minor issues detected",
        sub: `${findings.length} low-severity finding${findings.length !== 1 ? "s" : ""}. No critical or high issues.`,
        icon: "✅",
      };
    return {
      level: "green" as const,
      text: "No significant issues detected",
      sub: "Scanned against 177 detection rules across 17 threat categories.",
      icon: "✅",
    };
  }, [findings, lastScannedAt, catsWithFindings.length]);

  // ── Triage: top 3 most critical findings ──
  const triageFindings = useMemo(() => {
    if (findings.length <= 20) return null;
    return [...findings]
      .sort(
        (a, b) =>
          SEV_ORDER.indexOf(a.severity as Severity) -
          SEV_ORDER.indexOf(b.severity as Severity)
      )
      .slice(0, 3);
  }, [findings]);

  // ── Tool finding indicators for tool grid ──
  const toolIndicators = useMemo(() => {
    const m = new Map<string, { count: number; worst: Severity }>();
    for (const tool of tools) {
      const fs = toolFindingsMap.get(tool.name) ?? [];
      if (fs.length > 0) {
        m.set(tool.name, { count: fs.length, worst: worstSeverity(fs) });
      }
    }
    return m;
  }, [tools, toolFindingsMap]);

  // ── Render helper for finding rows ──
  const renderFindings = (fs: Finding[]) =>
    fs.map((f) => (
      <FindingRow
        key={f.id}
        finding={f}
        expanded={expandedFindings.has(f.id)}
        onToggle={() => toggleFinding(f.id)}
        remediationExpanded={expandedRemediation.has(f.id)}
        onToggleRemediation={() => toggleRemediation(f.id)}
      />
    ));

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      {/* Verdict Banner */}
      <div
        className={`sd-verdict sd-verdict-${verdict.level}`}
        role="status"
        aria-label={verdict.text}
      >
        <span className="sd-verdict-icon" aria-hidden="true">
          {verdict.icon}
        </span>
        <div className="sd-verdict-body">
          <span className="sd-verdict-text">{verdict.text}</span>
          <span className="sd-verdict-sub">{verdict.sub}</span>
        </div>
      </div>

      {/* Severity Summary Chips */}
      {findings.length > 0 && (
        <div className="sd-sev-summary" style={{ marginBottom: "var(--s5)" }}>
          {sevCounts.map(({ sev, count }) => (
            <div key={sev} className={`sd-sev-chip sd-sev-chip-${sev}`}>
              <SevIcon severity={sev} />
              <span className="sd-sev-chip-count">{count}</span>
              <span className="sd-sev-chip-label">{sev}</span>
            </div>
          ))}
        </div>
      )}

      {/* Empty State */}
      {findings.length === 0 && lastScannedAt && (
        <div className="sd-all-clear">
          <span className="sd-all-clear-icon" aria-hidden="true">
            🛡️
          </span>
          <span className="sd-all-clear-title">All Clear</span>
          <span className="sd-all-clear-desc">
            Scanned against 177 detection rules across 17 threat categories. No
            issues found.
          </span>
        </div>
      )}

      {/* Findings Section (tabs + content) */}
      {findings.length > 0 && (
        <>
          {/* Triage Callout */}
          {triageFindings && (
            <div className="sd-triage">
              <div className="sd-triage-header">
                <span className="sd-triage-title">
                  Start here
                </span>
                <span className="sd-triage-sub">
                  — these are the most important issues to address first
                </span>
              </div>
              <div className="sd-triage-items">
                {triageFindings.map((f) => (
                  <div key={f.id} className="sd-triage-item">
                    <SevIcon severity={f.severity} />
                    <span className={`sev-badge sev-${f.severity}`}>
                      {f.severity}
                    </span>
                    <span className="sd-triage-item-name">
                      {RULE_NAMES[f.rule_id] ?? f.rule_id}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="sd-tabs" role="tablist">
            <button
              className={`sd-tab${activeTab === "categories" ? " sd-tab-active" : ""}`}
              onClick={() => setActiveTab("categories")}
              role="tab"
              aria-selected={activeTab === "categories"}
            >
              Threat Categories
              <span className="sd-tab-count">({findings.length})</span>
            </button>
            <button
              className={`sd-tab${activeTab === "by-tool" ? " sd-tab-active" : ""}`}
              onClick={() => setActiveTab("by-tool")}
              role="tab"
              aria-selected={activeTab === "by-tool"}
            >
              By Tool
              <span className="sd-tab-count">
                ({toolsWithFindings.length})
              </span>
            </button>
          </div>

          {/* Category View */}
          {activeTab === "categories" && (
            <div role="tabpanel">
              {catsWithFindings.map((cat) => {
                const fs = categoryData.get(cat.id) ?? [];
                const worst = worstSeverity(fs);
                const open = expandedCategories.has(cat.id);
                return (
                  <CategoryGroup
                    key={cat.id}
                    cat={cat}
                    findings={fs}
                    worst={worst}
                    open={open}
                    onToggle={() => toggleCategory(cat.id)}
                  >
                    {renderFindings(fs)}
                  </CategoryGroup>
                );
              })}

              {/* Clean categories footer */}
              {cleanCats.length > 0 && (
                <div className="sd-clean-footer">
                  <button
                    className="sd-clean-toggle"
                    onClick={() => setShowCleanCats((v) => !v)}
                  >
                    {showCleanCats
                      ? "Hide clean categories"
                      : `${cleanCats.length} of ${THREAT_CATS.length} categories clean — show all`}
                  </button>
                  {showCleanCats && (
                    <div
                      style={{
                        marginTop: "var(--s3)",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--r-lg)",
                        overflow: "hidden",
                      }}
                    >
                      {cleanCats.map((cat) => (
                        <div key={cat.id} className="sd-clean-cat">
                          <span className="sd-clean-check">✓</span>
                          <span>{cat.icon}</span>
                          <span>{cat.name}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* By Tool View */}
          {activeTab === "by-tool" && (
            <div role="tabpanel">
              {toolsWithFindings.map(([name, fs]) => {
                const worst = worstSeverity(fs);
                const open = expandedToolGroups.has(name);
                const displayName =
                  name === "__server_wide__" ? "Server-wide" : name;
                return (
                  <div key={name} className="sd-tool-group">
                    <button
                      className="sd-tool-group-header"
                      onClick={() => toggleToolGroup(name)}
                      aria-expanded={open}
                    >
                      <SevIcon severity={worst} />
                      <span className="sd-tool-group-name">{displayName}</span>
                      <span className={`sd-cat-badge sd-cat-badge-${worst}`}>
                        {fs.length}
                      </span>
                      <Chevron open={open} />
                    </button>
                    {open && (
                      <div className="sd-tool-group-body">
                        {renderFindings(fs)}
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Tools without findings */}
              {toolsWithoutFindings.length > 0 && (
                <div
                  style={{
                    marginTop: "var(--s4)",
                    color: "var(--text-3)",
                    fontSize: "12px",
                    fontWeight: 600,
                    marginBottom: "var(--s2)",
                  }}
                >
                  No findings for {toolsWithoutFindings.length} tool
                  {toolsWithoutFindings.length !== 1 ? "s" : ""}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Tools Grid */}
      {tools.length > 0 && (
        <section className="sd-section" style={{ marginTop: "var(--s5)" }}>
          <h2 className="sd-section-title">
            Tools
            <span className="sd-section-count">{tools.length}</span>
          </h2>
          <div className="sd-tools-grid">
            {tools.map((tool) => {
              const indicator = toolIndicators.get(tool.name);
              return (
                <div key={tool.name} className="sd-tool">
                  <div className="sd-tool-name">{tool.name}</div>
                  {tool.description && (
                    <div className="sd-tool-desc">{tool.description}</div>
                  )}
                  {tool.capability_tags.length > 0 && (
                    <div className="sd-tool-caps">
                      {tool.capability_tags.map((tag) => (
                        <span key={tag} className={`cap-tag cap-${tag}`}>
                          {tag.replace(/-/g, " ")}
                        </span>
                      ))}
                    </div>
                  )}
                  {indicator && (
                    <div className="sd-tool-findings-badge">
                      <span
                        className={`sd-tool-sev-dot sd-tool-sev-dot-${indicator.worst}`}
                      />
                      <span style={{ color: `var(--sev-${indicator.worst === "informational" ? "info" : indicator.worst})` }}>
                        {indicator.count} finding
                        {indicator.count !== 1 ? "s" : ""}
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}
    </>
  );
}

// ── Category Group Sub-Component ────────────────────────────────────────────

function CategoryGroup({
  cat,
  findings,
  worst,
  open,
  onToggle,
  children,
}: {
  cat: ThreatCat;
  findings: Finding[];
  worst: Severity;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  const devTagline = THREAT_CAT_DEV_TAGLINES[cat.id] ?? cat.tagline;
  return (
    <div className="sd-cat-group">
      <button
        className="sd-cat-header"
        onClick={onToggle}
        aria-expanded={open}
      >
        <SevIcon severity={worst} />
        <span className="sd-cat-icon">{cat.icon}</span>
        <div className="sd-cat-info">
          <span className="sd-cat-name">{cat.name}</span>
          <span className="sd-cat-tagline">{devTagline}</span>
        </div>
        <span className={`sd-cat-badge sd-cat-badge-${worst}`}>
          {findings.length}
        </span>
        <Chevron open={open} />
      </button>
      {open && <div className="sd-cat-body">{children}</div>}
    </div>
  );
}
