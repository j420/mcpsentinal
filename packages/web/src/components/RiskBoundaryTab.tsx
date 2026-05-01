/**
 * RiskBoundaryTab — Cluster C Invention #3 (audit doc target IA tab #3).
 *
 * Server Component. Renders cross-config exposure for one server:
 *
 *   1. Same-config patterns (P01–P12) — risk-matrix patterns this server
 *      would trip if installed alongside other servers in the registry.
 *   2. Kill chains (KC01–KC07) — multi-step attack chains this server
 *      participates in, with narrative + contributing rule_ids + CVE
 *      evidence + mitigations.
 *
 * Contract — frozen against the API agent (Cluster C part 1):
 *
 *   GET /api/v1/servers/:slug/risk-boundary
 *
 *   {
 *     data: {
 *       server_slug: string;
 *       server_name: string;
 *       same_config_patterns: Array<{
 *         pattern_id: string;            // "P01" .. "P12"
 *         pattern_name: string;
 *         pattern_summary: string;
 *         severity: "critical" | "high" | "medium" | "low";
 *         paired_with_count: number;
 *         sample_pairings: Array<{ slug: string; name: string }>;  // ≤ 5
 *       }>;
 *       kill_chains: Array<{
 *         kc_id: string;                 // "KC01" .. "KC07"
 *         name: string;
 *         severity_score: number;        // 0..100
 *         narrative: string;
 *         contributing_rule_ids: string[];
 *         cve_evidence_ids: string[];
 *         mitigations: string[];
 *       }>;
 *     };
 *   }
 *
 * Three-layer fallback (matches FrameworkPostureMatrix):
 *   1. fetch ok + data with at least one pattern OR chain → render the
 *      data sections.
 *   2. fetch ok + both arrays empty → "no cross-config exposure on file"
 *      panel. Visible, not silently hidden — Phase 5 lesson: empty state
 *      IS a feature.
 *   3. fetch 404 / network failure / parse failure → "Risk boundary data
 *      unavailable for this scan" panel — same shape as
 *      FrameworkPostureMatrix's UnavailableSection.
 *
 * Cache — `next: { revalidate: 300 }` matches the API Cache-Control window
 * and the SignedEvidencePack pattern. Cluster B reviewer M1 lesson: the
 * page must NOT be force-dynamic, and components MUST opt into the
 * 300-second revalidate window explicitly so each page load reuses the
 * cached aggregation.
 *
 * Accessibility:
 *   - severity gauge on each kill chain carries `role="img"` with an
 *     aria-label spelling out the score.
 *   - sample pairings render as a list (`role="list"` / `role="listitem"`)
 *     so screen readers announce the count.
 */
import React from "react";

// ── Contract Types (authoritative — frozen against API agent) ──────────────

export type RiskBoundarySeverity = "critical" | "high" | "medium" | "low";

export interface RiskBoundaryPairing {
  slug: string;
  name: string;
}

export interface RiskBoundaryPattern {
  pattern_id: string;
  pattern_name: string;
  pattern_summary: string;
  severity: RiskBoundarySeverity;
  paired_with_count: number;
  sample_pairings: RiskBoundaryPairing[];
}

export interface RiskBoundaryKillChain {
  kc_id: string;
  name: string;
  severity_score: number;
  narrative: string;
  contributing_rule_ids: string[];
  cve_evidence_ids: string[];
  mitigations: string[];
}

export interface RiskBoundaryData {
  server_slug: string;
  server_name: string;
  same_config_patterns: RiskBoundaryPattern[];
  kill_chains: RiskBoundaryKillChain[];
}

interface RiskBoundaryResponse {
  data: RiskBoundaryData;
}

// ── Props ───────────────────────────────────────────────────────────────────

export interface RiskBoundaryTabProps {
  slug: string;
  apiUrl: string;
}

// ── Severity → token map ───────────────────────────────────────────────────
// Maps API severity to one of the existing declared status tokens. Cluster B
// reviewer m2 lesson: never reach for `--text-1` (undeclared). Use only the
// tokens already in globals.css.

const SEVERITY_TINT: Record<RiskBoundarySeverity, {
  textVar: string; // var() expression for the severity tint
  label: string;
}> = {
  critical: { textVar: "var(--critical)", label: "CRITICAL" },
  high:     { textVar: "var(--poor)",     label: "HIGH" },
  medium:   { textVar: "var(--moderate)", label: "MEDIUM" },
  low:      { textVar: "var(--text-2)",   label: "LOW" },
};

function severityScoreBand(score: number): "critical" | "high" | "medium" | "low" {
  // Aligned to the badge-color thresholds documented in scoring-algorithm.md.
  // Inverted (high score = bad in this context — kill-chain severity).
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

// ── Data fetch — null on any failure (mirrors SignedEvidencePack pattern) ──

async function getRiskBoundary(
  apiUrl: string,
  slug: string,
): Promise<RiskBoundaryData | null> {
  try {
    const res = await fetch(
      `${apiUrl}/api/v1/servers/${encodeURIComponent(slug)}/risk-boundary`,
      {
        next: { revalidate: 300 },
        signal: AbortSignal.timeout(4000),
      },
    );
    if (!res.ok) return null;
    const json = (await res.json()) as Partial<RiskBoundaryResponse>;
    if (!json || !json.data) return null;
    if (!Array.isArray(json.data.same_config_patterns)) return null;
    if (!Array.isArray(json.data.kill_chains)) return null;
    return json.data as RiskBoundaryData;
  } catch {
    return null;
  }
}

// ── Sub-components ─────────────────────────────────────────────────────────

function PatternRow({ pattern }: { pattern: RiskBoundaryPattern }): React.ReactElement {
  const tint = SEVERITY_TINT[pattern.severity];
  return (
    <li
      className={`rbt-pattern rbt-pattern-${pattern.severity}`}
      data-pattern-id={pattern.pattern_id}
    >
      <div className="rbt-pattern-head">
        <span
          className={`rbt-pattern-pill rbt-pattern-pill-${pattern.severity}`}
          style={{ color: tint.textVar }}
          aria-label={`${pattern.pattern_id} (${tint.label} severity)`}
        >
          {pattern.pattern_id}
        </span>
        <span className="rbt-pattern-name">{pattern.pattern_name}</span>
        <span
          className="rbt-pattern-count"
          aria-label={
            pattern.paired_with_count === 1
              ? "1 server in registry would trip this with you"
              : `${pattern.paired_with_count} servers in registry would trip this with you`
          }
        >
          {pattern.paired_with_count}{" "}
          {pattern.paired_with_count === 1 ? "server" : "servers"}
        </span>
      </div>

      <p className="rbt-pattern-summary">{pattern.pattern_summary}</p>

      {pattern.sample_pairings.length > 0 && (
        <div
          className="rbt-pairings"
          role="list"
          aria-label={`Sample servers pairing with this pattern (${pattern.sample_pairings.length} of ${pattern.paired_with_count})`}
        >
          <span className="rbt-pairings-label">paired with:</span>
          {pattern.sample_pairings.slice(0, 5).map((p) => (
            <a
              key={p.slug}
              role="listitem"
              className="rbt-pairing"
              href={`/servers/${encodeURIComponent(p.slug)}`}
            >
              {p.name}
            </a>
          ))}
        </div>
      )}
    </li>
  );
}

function KillChainCard({ chain }: { chain: RiskBoundaryKillChain }): React.ReactElement {
  const band = severityScoreBand(chain.severity_score);
  const score = Math.max(0, Math.min(100, chain.severity_score));
  const widthStyle: React.CSSProperties = { width: `${score}%` };
  return (
    <article
      className={`rbt-chain rbt-chain-${band}`}
      data-kc-id={chain.kc_id}
    >
      <header className="rbt-chain-head">
        <span className={`rbt-chain-pill rbt-chain-pill-${band}`}>{chain.kc_id}</span>
        <span className="rbt-chain-name">{chain.name}</span>
        <span
          className="rbt-chain-gauge"
          role="img"
          aria-label={`Kill chain severity score ${score} of 100 (${band})`}
        >
          <span className="rbt-chain-gauge-track">
            <span
              className={`rbt-chain-gauge-fill rbt-chain-gauge-${band}`}
              style={widthStyle}
            />
          </span>
          <span className="rbt-chain-gauge-num" aria-hidden="true">
            {score}
          </span>
        </span>
      </header>

      <p className="rbt-chain-narrative">{chain.narrative}</p>

      {chain.contributing_rule_ids.length > 0 && (
        <div className="rbt-chain-block" data-rbt-block="rules">
          <div className="rbt-chain-block-label">Contributing rules</div>
          <div className="rbt-chain-rules">
            {chain.contributing_rule_ids.map((ruleId) => (
              <a
                key={ruleId}
                className="rbt-chain-rule"
                // Deep-link path is parked — anchor for now (FindingsTab
                // hash-anchors will be wired in a follow-up).
                href={`#finding-${encodeURIComponent(ruleId)}`}
              >
                {ruleId}
              </a>
            ))}
          </div>
        </div>
      )}

      {chain.cve_evidence_ids.length > 0 && (
        <div className="rbt-chain-block" data-rbt-block="cves">
          <div className="rbt-chain-block-label">CVE evidence</div>
          <div className="rbt-chain-cves">
            {chain.cve_evidence_ids.map((cveId) => (
              <a
                key={cveId}
                className="rbt-chain-cve"
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                {cveId}
              </a>
            ))}
          </div>
        </div>
      )}

      {chain.mitigations.length > 0 && (
        <div className="rbt-chain-block" data-rbt-block="mitigations">
          <div className="rbt-chain-block-label">Mitigations</div>
          <ul className="rbt-chain-mits">
            {chain.mitigations.map((m, i) => (
              <li key={i} className="rbt-chain-mit">{m}</li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}

// ── Fallback panels ────────────────────────────────────────────────────────

function UnavailablePanel(): React.ReactElement {
  return (
    <section className="sd-section rbt-section" data-rbt-state="unavailable">
      <div className="rbt-eyebrow">CROSS-CONFIG EXPOSURE — same-config attack patterns + kill chains</div>
      <h2 className="sd-section-title">Risk Boundary</h2>
      <div className="rbt-empty" role="status">
        <div className="rbt-empty-title">Risk boundary data unavailable for this scan</div>
        <p className="rbt-empty-sub">
          The risk-boundary endpoint did not return data for this server. This may be
          because the cross-server analysis has not run yet on this scan, or because the
          API has not been upgraded. Per-finding evidence is still available in the
          Findings tab.
        </p>
      </div>
    </section>
  );
}

function NoExposurePanel({ data }: { data: RiskBoundaryData }): React.ReactElement {
  return (
    <section className="sd-section rbt-section" data-rbt-state="no-exposure">
      <div className="rbt-eyebrow">CROSS-CONFIG EXPOSURE — same-config attack patterns + kill chains</div>
      <h2 className="sd-section-title">Risk Boundary</h2>
      <div className="rbt-empty" role="status">
        <div className="rbt-empty-title">No cross-config exposure on file for this server</div>
        <p className="rbt-empty-sub">
          We have scan data for <strong>{data.server_name}</strong> but no same-config
          risk patterns (P01–P12) and no multi-step kill chains (KC01–KC07) currently
          implicate it. This is a meaningful "all clear" — when cross-server analysis
          runs again, any new pairings or chains will appear here.
        </p>
      </div>
    </section>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export default async function RiskBoundaryTab({
  slug,
  apiUrl,
}: RiskBoundaryTabProps): Promise<React.ReactElement> {
  const data = await getRiskBoundary(apiUrl, slug);

  // Layer 3 — fetch failed entirely.
  if (!data) return <UnavailablePanel />;

  // Layer 2 — fetch ok but both arrays empty.
  if (
    data.same_config_patterns.length === 0 &&
    data.kill_chains.length === 0
  ) {
    return <NoExposurePanel data={data} />;
  }

  // Layer 1 — render the data.
  const patternCount = data.same_config_patterns.length;
  const chainCount = data.kill_chains.length;

  return (
    <section className="sd-section rbt-section" data-rbt-state="ok">
      <div className="rbt-eyebrow">CROSS-CONFIG EXPOSURE — same-config attack patterns + kill chains</div>
      <h2 className="sd-section-title">Risk Boundary</h2>
      <p className="sd-section-sub rbt-summary" data-rbt-summary>
        {patternCount === 0
          ? "No same-config patterns matched."
          : `${patternCount} same-config pattern${patternCount === 1 ? "" : "s"} matched`}
        {" · "}
        {chainCount === 0
          ? "no kill chains implicate this server"
          : `${chainCount} kill chain${chainCount === 1 ? "" : "s"} implicate this server`}
        .
      </p>

      {/* ── Sub-section 1: Same-config patterns (P01–P12) ──────────────── */}
      <div className="rbt-subsection" data-rbt-subsection="patterns">
        <h3 className="rbt-subsection-title">
          Same-config patterns (P01–P12)
          <span className="rbt-subsection-count">{patternCount}</span>
        </h3>
        {patternCount === 0 ? (
          <p className="rbt-subsection-empty">
            No P01–P12 risk-matrix patterns implicate this server's capabilities.
          </p>
        ) : (
          <ul className="rbt-pattern-list" aria-label="Same-config attack patterns">
            {data.same_config_patterns.map((p) => (
              <PatternRow key={p.pattern_id} pattern={p} />
            ))}
          </ul>
        )}
      </div>

      {/* ── Sub-section 2: Kill chains (KC01–KC07) ────────────────────── */}
      <div className="rbt-subsection" data-rbt-subsection="chains">
        <h3 className="rbt-subsection-title">
          Kill chains (KC01–KC07)
          <span className="rbt-subsection-count">{chainCount}</span>
        </h3>
        {chainCount === 0 ? (
          <p className="rbt-subsection-empty">
            No KC01–KC07 kill chains currently include this server in their step flow.
          </p>
        ) : (
          <div className="rbt-chain-list" role="list" aria-label="Kill chains involving this server">
            {data.kill_chains.map((c) => (
              <div role="listitem" key={c.kc_id}>
                <KillChainCard chain={c} />
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
