/**
 * FooterAttestationBar — sticky bottom bar with scan provenance + exports.
 *
 * Exports map to real, currently-shipped endpoints:
 *   JSON           → GET /api/v1/servers/:slug
 *   Compliance PDF → GET /api/v1/servers/:slug/compliance/:framework.pdf
 *   Compliance JSON→ GET /api/v1/servers/:slug/compliance/:framework.json
 *   Badge SVG      → GET /api/v1/servers/:slug/badge.svg
 *   Permalink      → current URL
 *
 * SARIF is intentionally absent — the API does not currently emit SARIF.
 * Adding it later means wiring a new endpoint, not adding a button here.
 */

import React from "react";

interface ScanStages {
  status: string;
  started_at: string | null;
  completed_at: string | null;
}

interface Props {
  slug: string;
  apiUrl: string;
  publicUrl?: string;
  findingsCount: number;
  totalRules?: number;
  scan_stages: ScanStages | null;
  rulesVersion?: string | null;
}

const FRAMEWORKS = [
  { id: "eu_ai_act",    label: "EU AI Act" },
  { id: "iso_27001",    label: "ISO 27001" },
  { id: "owasp_mcp",    label: "OWASP MCP" },
  { id: "owasp_asi",    label: "OWASP ASI" },
  { id: "cosai_mcp",    label: "CoSAI MCP" },
  { id: "maestro",      label: "MAESTRO" },
  { id: "mitre_atlas",  label: "MITRE ATLAS" },
];

function fmtDuration(started: string | null, completed: string | null): string {
  if (!started || !completed) return "—";
  const ms = new Date(completed).getTime() - new Date(started).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

export default function FooterAttestationBar({
  slug,
  apiUrl,
  findingsCount,
  totalRules = 164,
  scan_stages,
  rulesVersion,
}: Props) {
  const duration = scan_stages
    ? fmtDuration(scan_stages.started_at, scan_stages.completed_at)
    : "—";
  const status = scan_stages?.status ?? "—";

  const slugEnc = encodeURIComponent(slug);
  const jsonHref = `${apiUrl}/api/v1/servers/${slugEnc}`;
  const badgeHref = `${apiUrl}/api/v1/servers/${slugEnc}/badge.svg`;

  return (
    <footer id="footer-attestation" className="fab-bar">
      <div className="fab-meta">
        <span className="fab-mono">scan_status={status}</span>
        <span className="fab-sep">·</span>
        <span className="fab-mono">engine=rules:{totalRules}{rulesVersion ? `@${rulesVersion}` : ""}</span>
        <span className="fab-sep">·</span>
        <span className="fab-mono">findings={findingsCount}</span>
        <span className="fab-sep">·</span>
        <span className="fab-mono">duration={duration}</span>
      </div>

      <details className="fab-export">
        <summary className="fab-export-summary">Export</summary>
        <div className="fab-export-menu">
          <a className="fab-export-link" href={jsonHref} target="_blank" rel="noopener noreferrer">
            <span className="fab-export-kind">JSON</span>
            <span className="fab-export-desc">Server detail (full)</span>
          </a>

          <div className="fab-export-group">
            <div className="fab-export-group-label">Signed compliance reports</div>
            {FRAMEWORKS.map((fw) => (
              <div key={fw.id} className="fab-export-row">
                <span className="fab-export-kind">{fw.label}</span>
                <a
                  className="fab-export-fmt"
                  href={`${apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.pdf`}
                  target="_blank"
                  rel="noopener noreferrer"
                >PDF</a>
                <a
                  className="fab-export-fmt"
                  href={`${apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                >HTML</a>
                <a
                  className="fab-export-fmt"
                  href={`${apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.json`}
                  target="_blank"
                  rel="noopener noreferrer"
                >JSON</a>
              </div>
            ))}
          </div>

          <a className="fab-export-link" href={badgeHref} target="_blank" rel="noopener noreferrer">
            <span className="fab-export-kind">Badge SVG</span>
            <span className="fab-export-desc">Embed in your README</span>
          </a>

          <span className="fab-export-link fab-export-disabled" title="Coming soon — SARIF endpoint not yet shipped">
            <span className="fab-export-kind">SARIF</span>
            <span className="fab-export-desc">coming soon</span>
          </span>
        </div>
      </details>
    </footer>
  );
}
