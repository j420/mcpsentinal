/**
 * CapabilitySurface — at-a-glance "what makes this server attackable".
 *
 * Renders the risk-matrix capability classification for this server:
 *   - Each capability tag is a chip (color-coded by risk class).
 *   - Two structural flags (`is_injection_gateway`, `is_shared_writer`)
 *     elevate to a banner row when set — these are the two flags risk-
 *     matrix patterns key off most often (P01 trifecta gateway,
 *     H3 cross-agent memory writer).
 *   - Cross-server P-pattern memberships (from `risk_edges[]`) render
 *     underneath as a compact list of "this server is in a P0X with
 *     <peer>" bullets.
 *
 * Renders nothing when no capability data is on file. Server component —
 * pure SSR, no hooks.
 *
 * Visual language: existing dd-* / sev-* tokens. Capabilities are grouped
 * into "high-risk" and "neutral" buckets so the eye lands on what matters.
 */

import React from "react";
import type {
  DeepDiveCapabilityNode,
  DeepDiveRiskEdge,
} from "@/lib/deep-dive";

interface CapabilitySurfaceProps {
  node: DeepDiveCapabilityNode | undefined;
  edges?: DeepDiveRiskEdge[];
}

/** Capabilities the risk-matrix classifies as immediately dangerous in
 *  combination — these elevate visually so the regulator's eye lands on
 *  them first. The set mirrors the patterns in
 *  packages/risk-matrix/src/patterns.ts. */
const HIGH_RISK_CAPABILITIES = new Set<string>([
  "executes-code",
  "sends-network",
  "accesses-filesystem",
  "writes-agent-config",
  "writes-agent-memory",
  "code-generation",
  "database-admin",
]);

const CAPABILITY_LABELS: Record<string, string> = {
  "reads-data": "reads data",
  "writes-data": "writes data",
  "executes-code": "executes code",
  "sends-network": "sends network",
  "accesses-filesystem": "filesystem",
  "manages-credentials": "credentials",
  "reads-messages": "reads messages",
  "writes-agent-config": "writes agent config",
  "reads-agent-memory": "reads agent memory",
  "writes-agent-memory": "writes agent memory",
  "web-scraping": "web scraping",
  "code-generation": "code generation",
  "database-query": "database query",
  "database-admin": "database admin",
};

const SEV_BY_PATTERN: Record<string, string> = {
  // Critical patterns from risk-matrix (P01, P02, P03, P05, P07, P10, P12)
  P01: "critical",
  P02: "critical",
  P03: "critical",
  P05: "critical",
  P07: "critical",
  P10: "critical",
  P12: "critical",
  // High patterns (P04, P06, P08, P09, P11)
  P04: "high",
  P06: "high",
  P08: "high",
  P09: "high",
  P11: "high",
};

export default function CapabilitySurface({
  node,
  edges,
}: CapabilitySurfaceProps) {
  // Defensive: production data may have a node object missing the
  // capabilities array. Treat any non-array as "no capabilities on file".
  const capabilities = Array.isArray(node?.capabilities)
    ? node!.capabilities
    : [];
  if (!node || capabilities.length === 0) {
    // Honest gap: no capability classification on file. The page renders
    // nothing here rather than inventing a placeholder card.
    return null;
  }

  const high = capabilities.filter((c) => HIGH_RISK_CAPABILITIES.has(c));
  const neutral = capabilities.filter((c) => !HIGH_RISK_CAPABILITIES.has(c));

  // Group risk edges by pattern_id so the user sees "you're in P01 across
  // 2 peer servers" rather than 2 raw rows. Defensive: skip malformed
  // edges (missing pattern_id or peer-server records).
  const byPattern = new Map<string, DeepDiveRiskEdge[]>();
  for (const edge of edges ?? []) {
    if (!edge || typeof edge.pattern_id !== "string") continue;
    if (!edge.from_server || !edge.to_server) continue;
    const bucket = byPattern.get(edge.pattern_id) ?? [];
    bucket.push(edge);
    byPattern.set(edge.pattern_id, bucket);
  }
  const patternRows = Array.from(byPattern.entries()).sort(([a], [b]) =>
    a.localeCompare(b),
  );

  return (
    <section className="csurf" aria-labelledby="csurf-title">
      <header className="csurf-head">
        <h2 id="csurf-title" className="csurf-title">
          Capability surface
        </h2>
        <p className="csurf-sub">
          What this server can do, classified by the cross-server risk
          matrix. High-risk capabilities are the ones P-patterns key off.
        </p>
      </header>

      {(node.is_injection_gateway || node.is_shared_writer) && (
        <div className="csurf-flags" role="group" aria-label="Structural flags">
          {node.is_injection_gateway && (
            <span className="csurf-flag csurf-flag-gateway">
              ▲ Injection gateway — ingests untrusted external content
            </span>
          )}
          {node.is_shared_writer && (
            <span className="csurf-flag csurf-flag-writer">
              ▲ Shared writer — writes data other agents can read
            </span>
          )}
        </div>
      )}

      <div className="csurf-caps">
        {high.length > 0 && (
          <div className="csurf-cap-row">
            <span className="csurf-cap-label">High-risk</span>
            <div className="csurf-cap-chips">
              {high.map((cap) => (
                <span
                  key={cap}
                  className="csurf-chip csurf-chip-high"
                  title={cap}
                >
                  {CAPABILITY_LABELS[cap] ?? cap}
                </span>
              ))}
            </div>
          </div>
        )}
        {neutral.length > 0 && (
          <div className="csurf-cap-row">
            <span className="csurf-cap-label">Other</span>
            <div className="csurf-cap-chips">
              {neutral.map((cap) => (
                <span
                  key={cap}
                  className="csurf-chip csurf-chip-neutral"
                  title={cap}
                >
                  {CAPABILITY_LABELS[cap] ?? cap}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {patternRows.length > 0 && (
        <div className="csurf-patterns">
          <h3 className="csurf-patterns-title">
            Cross-server risk patterns this server participates in
          </h3>
          <ul className="csurf-pattern-list">
            {patternRows.map(([patternId, rows]) => {
              const sev = SEV_BY_PATTERN[patternId] ?? "medium";
              const peers = new Set<string>();
              for (const r of rows) {
                const fs = r.from_server;
                const ts = r.to_server;
                if (fs && fs.slug !== node.server_slug && fs.name)
                  peers.add(fs.name);
                if (ts && ts.slug !== node.server_slug && ts.name)
                  peers.add(ts.name);
              }
              const desc =
                rows[0] && typeof rows[0].description === "string"
                  ? rows[0].description
                  : "—";
              return (
                <li
                  key={patternId}
                  className="csurf-pattern-item"
                  data-sev={sev}
                  style={{ borderLeftColor: `var(--sev-${sev})` }}
                >
                  <span className="csurf-pattern-id">{patternId}</span>
                  <span className="csurf-pattern-desc">{desc}</span>
                  {peers.size > 0 && (
                    <span className="csurf-pattern-peers">
                      with {Array.from(peers).slice(0, 3).join(", ")}
                      {peers.size > 3 ? ` +${peers.size - 3}` : ""}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </section>
  );
}
