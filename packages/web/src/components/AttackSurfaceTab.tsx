/**
 * AttackSurfaceTab — server-specific attack surface intelligence.
 *
 * Replaces the static-taxonomy Deep Dive tab. Four sub-sections, each derived
 * from this server's actual data:
 *
 *  1. Capability Graph — tools → capability tags → unlocked risks
 *  2. Risk Coverage Matrix — 13 threat categories × 5 severity bands; cells
 *     show finding counts on this server (or "✓" clean / "·" not applicable)
 *  3. Threat Reference Provenance — every research/CVE citation across this
 *     server's evidence chains, with citation count
 *  4. Reproducibility Footer — rules version, scan time, fingerprint, link to
 *     signed compliance report
 *
 * Pure server component — all SVG inline, no client JS.
 */
import React from "react";
import { THREAT_CATS } from "./cdd-data";

interface Tool {
  name: string;
  description: string | null;
  capability_tags: string[];
}

export interface FindingForSurface {
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence_chain?: Record<string, unknown> | null;
}

interface ThreatRef {
  id: string;
  title?: string;
  url?: string;
  year?: number;
}

interface Props {
  slug: string;
  tools: Tool[];
  findings: FindingForSurface[];
  rules_version: string | null;
  last_scanned_at: string | null;
}

// Capability-tag → human label + "risks unlocked" mapping. Derived from
// MCP Sentinel's risk-matrix taxonomy (see packages/risk-matrix).
const CAP_INFO: Record<string, { label: string; risks: string[] }> = {
  "executes-code":         { label: "Executes Code",        risks: ["RCE", "Lateral movement"] },
  "writes-data":           { label: "Writes Data",          risks: ["Persistent injection", "Data tampering"] },
  "sends-network":         { label: "Sends Network",        risks: ["Exfiltration", "SSRF"] },
  "reads-data":            { label: "Reads Data",           risks: ["PII exposure", "Secrets disclosure"] },
  "accesses-filesystem":   { label: "Accesses FS",          risks: ["Path traversal", "Cred theft"] },
  "manages-credentials":   { label: "Manages Credentials",  risks: ["Token theft", "Privilege escalation"] },
};

// Rules that carry the "lethal trifecta" capability legs (private read +
// untrusted ingest + external send). Mirrors F1 / I13 from the rule set.
const TRIFECTA_LEGS: Record<string, "read" | "ingest" | "send"> = {
  "reads-data": "read",
  "manages-credentials": "read",
  "accesses-filesystem": "read",
  "executes-code": "ingest",
  "writes-data": "ingest",
  "sends-network": "send",
};

function extractThreatRefs(findings: FindingForSurface[]): ThreatRef[] {
  const seen = new Map<string, ThreatRef & { count: number }>();
  for (const f of findings) {
    const chain = f.evidence_chain as
      | { threat_reference?: ThreatRef; threat_references?: ThreatRef[] }
      | null
      | undefined;
    if (!chain) continue;
    const refs = [
      ...(chain.threat_reference ? [chain.threat_reference] : []),
      ...(Array.isArray(chain.threat_references) ? chain.threat_references : []),
    ];
    for (const r of refs) {
      if (!r?.id) continue;
      const existing = seen.get(r.id);
      if (existing) {
        existing.count++;
      } else {
        seen.set(r.id, { ...r, count: 1 });
      }
    }
  }
  return Array.from(seen.values()).sort((a, b) => (b as { count: number }).count - (a as { count: number }).count) as ThreatRef[];
}

export default function AttackSurfaceTab({ slug, tools, findings, rules_version, last_scanned_at }: Props) {
  // ── 1. Capability presence ─────────────────────────────────────────
  const capCounts: Record<string, number> = {};
  const capTools: Record<string, string[]> = {};
  for (const t of tools) {
    for (const tag of t.capability_tags) {
      capCounts[tag] = (capCounts[tag] ?? 0) + 1;
      (capTools[tag] ??= []).push(t.name);
    }
  }
  const presentCaps = Object.keys(capCounts).filter((c) => CAP_INFO[c]);

  const trifectaLegs = new Set<"read" | "ingest" | "send">();
  for (const c of presentCaps) {
    const leg = TRIFECTA_LEGS[c];
    if (leg) trifectaLegs.add(leg);
  }
  const hasTrifecta = trifectaLegs.size === 3;

  // ── 2. Risk coverage matrix ────────────────────────────────────────
  // For each threat category, aggregate this server's findings by severity.
  type Bucket = { critical: number; high: number; medium: number; low: number; informational: number };
  const ZERO_BUCKET: Bucket = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  const findingsByCat = new Map<string, Bucket>();
  for (const cat of THREAT_CATS) {
    const allRules = new Set<string>();
    for (const sc of cat.subCats) for (const r of sc.rules) allRules.add(r);
    const bucket: Bucket = { ...ZERO_BUCKET };
    for (const f of findings) {
      if (allRules.has(f.rule_id)) bucket[f.severity] += 1;
    }
    findingsByCat.set(cat.id, bucket);
  }

  // ── 3. Threat ref provenance ───────────────────────────────────────
  const threatRefs = extractThreatRefs(findings);

  // ── 4. Reproducibility footer ──────────────────────────────────────
  const apiBase = process.env["NEXT_PUBLIC_API_URL"] || "https://api.mcp-sentinel.com";
  const verifyUrl = `${apiBase}/api/v1/servers/${encodeURIComponent(slug)}/compliance/owasp_mcp.json`;

  return (
    <div className="ast-tab">
      {/* ── 1. Capability Graph ───────────────────────────── */}
      <section className="frame ast-section">
        <header className="ast-section-head">
          <span className="eyebrow-mono">01 · CAPABILITY GRAPH</span>
          <h2 className="ast-section-title">What this server can do</h2>
          {hasTrifecta && (
            <span className="ast-trifecta-badge" title="Lethal trifecta: read sensitive · ingest untrusted · send external. Score capped at 40.">
              ⚠ LETHAL TRIFECTA
            </span>
          )}
        </header>
        {presentCaps.length === 0 ? (
          <p className="ast-empty">No capabilities enumerated. Tools may have failed to load.</p>
        ) : (
          <div className="ast-cap-grid">
            {presentCaps.map((c) => {
              const info = CAP_INFO[c]!;
              const leg = TRIFECTA_LEGS[c];
              return (
                <div
                  key={c}
                  className={`ast-cap-card cap-${c}${leg ? ` ast-cap-leg-${leg}` : ""}`}
                >
                  <div className="ast-cap-head">
                    <span className="ast-cap-label">{info.label}</span>
                    <span className="ast-cap-count">×{capCounts[c]}</span>
                  </div>
                  <ul className="ast-cap-risks">
                    {info.risks.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ul>
                  <div className="ast-cap-tools">
                    {(capTools[c] ?? []).slice(0, 3).map((t) => (
                      <code key={t} className="ast-cap-tool">{t}</code>
                    ))}
                    {(capTools[c] ?? []).length > 3 && (
                      <span className="ast-cap-tools-more">+{(capTools[c] ?? []).length - 3} more</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* ── 2. Risk Coverage Matrix ───────────────────────── */}
      <section className="frame ast-section">
        <header className="ast-section-head">
          <span className="eyebrow-mono">02 · RISK COVERAGE MATRIX</span>
          <h2 className="ast-section-title">What we evaluated, what we found</h2>
        </header>
        <div className="ast-matrix">
          <div className="ast-matrix-head">
            <span></span>
            <span className="ast-matrix-h">CRITICAL</span>
            <span className="ast-matrix-h">HIGH</span>
            <span className="ast-matrix-h">MEDIUM</span>
            <span className="ast-matrix-h">LOW</span>
            <span className="ast-matrix-h">INFO</span>
          </div>
          {THREAT_CATS.map((cat) => {
            const bucket = findingsByCat.get(cat.id) ?? ZERO_BUCKET;
            const total = bucket.critical + bucket.high + bucket.medium + bucket.low + bucket.informational;
            return (
              <div key={cat.id} className={`ast-matrix-row ${total > 0 ? "ast-matrix-row-hit" : "ast-matrix-row-clean"}`}>
                <span className="ast-matrix-name">
                  <span className="ast-matrix-ico" aria-hidden>{cat.icon}</span>
                  {cat.name}
                </span>
                {(["critical", "high", "medium", "low", "informational"] as const).map((sev) => (
                  <span
                    key={sev}
                    className={`ast-matrix-cell ast-cell-${sev} ${bucket[sev] > 0 ? "ast-cell-hit" : "ast-cell-clean"}`}
                    title={`${cat.name} — ${sev}: ${bucket[sev]} finding${bucket[sev] === 1 ? "" : "s"}`}
                  >
                    {bucket[sev] > 0 ? bucket[sev] : <span className="ast-cell-dash">·</span>}
                  </span>
                ))}
              </div>
            );
          })}
        </div>
      </section>

      {/* ── 3. Threat Reference Provenance ────────────────── */}
      <section className="frame ast-section">
        <header className="ast-section-head">
          <span className="eyebrow-mono">03 · THREAT REFERENCE PROVENANCE</span>
          <h2 className="ast-section-title">Every claim cites its source</h2>
        </header>
        {threatRefs.length === 0 ? (
          <p className="ast-empty">No threat references in this server&apos;s findings yet. Most of our deterministic rules cite OWASP / MITRE / CoSAI / CVE in their evidence chain — references will populate as the rule registry continues to migrate.</p>
        ) : (
          <ul className="ast-threat-refs">
            {threatRefs.map((r) => (
              <li key={r.id} className="ast-threat-ref">
                <span className="ast-threat-id eyebrow-mono">{r.id}</span>
                <span className="ast-threat-title">{r.title ?? r.id}</span>
                {r.year && <span className="ast-threat-year">{r.year}</span>}
                <span className="ast-threat-count">
                  cited by {(r as ThreatRef & { count?: number }).count ?? 1} finding{((r as ThreatRef & { count?: number }).count ?? 1) === 1 ? "" : "s"}
                </span>
                {r.url && (
                  <a href={r.url} target="_blank" rel="noopener noreferrer" className="ast-threat-link">
                    source →
                  </a>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* ── 4. Reproducibility Footer ─────────────────────── */}
      <section className="frame frame--subtle ast-section ast-repro">
        <header className="ast-section-head">
          <span className="eyebrow-mono">04 · REPRODUCIBILITY</span>
          <h2 className="ast-section-title">Verify this report</h2>
        </header>
        <dl className="ast-repro-list">
          <div>
            <dt>Ruleset</dt>
            <dd>{rules_version ? `v${rules_version}` : "—"}</dd>
          </div>
          <div>
            <dt>Scanned</dt>
            <dd>{last_scanned_at ? new Date(last_scanned_at).toISOString() : "—"}</dd>
          </div>
          <div>
            <dt>Tools enumerated</dt>
            <dd>{tools.length}</dd>
          </div>
          <div>
            <dt>Findings emitted</dt>
            <dd>{findings.length}</dd>
          </div>
          <div>
            <dt>Categories evaluated</dt>
            <dd>{THREAT_CATS.length}</dd>
          </div>
          <div>
            <dt>Signed compliance JSON</dt>
            <dd>
              <a href={verifyUrl} target="_blank" rel="noopener noreferrer" className="ast-repro-link">
                {verifyUrl} →
              </a>
            </dd>
          </div>
        </dl>
        <p className="ast-repro-note">
          Every finding above carries a structured EvidenceChain (source → propagation → sink → mitigation → impact) signed against the ruleset version. Re-run this exact scan with{" "}
          <code>pnpm scan --server={slug}</code> on the same ruleset to reproduce byte-for-byte.
        </p>
      </section>
    </div>
  );
}
