import type { ControlResult, SignedComplianceReport } from "../types.js";
import { attestationFields, verificationInstructions } from "./shared/attestation-block.js";
import {
  anchorSlug,
  escapeHtml,
  formatIsoUtc,
  formatPercent,
  wrapFixedWidth,
} from "./shared/format-helpers.js";
import {
  CONTROL_STATUS_STYLING,
  OVERALL_STATUS_STYLING,
  severityStyle,
} from "./shared/status-styling.js";
import type { ComplianceReportRenderer } from "./types.js";

/**
 * Framework accent colour — stable per framework id so the same server's
 * report always renders with the same branded stripe. Values picked to
 * maintain AA contrast on white.
 */
const FRAMEWORK_ACCENT: Record<string, string> = {
  eu_ai_act: "#003399",
  iso_27001: "#0b5d1e",
  owasp_mcp: "#6e1a7a",
  owasp_asi: "#8a1f11",
  cosai_mcp: "#114f87",
  maestro: "#7a4a00",
  mitre_atlas: "#1a4a52",
};

function accentFor(id: string): string {
  return FRAMEWORK_ACCENT[id] ?? "#1a1a1a";
}

function renderStatusPill(status: ControlResult["status"]): string {
  const s = CONTROL_STATUS_STYLING[status];
  return `<span class="pill" style="color:${s.color};background:${s.background}"><span class="pill-glyph">${escapeHtml(s.glyph)}</span> ${escapeHtml(s.label)}</span>`;
}

function renderOverallPill(status: SignedComplianceReport["report"]["summary"]["overall_status"]): string {
  const s = OVERALL_STATUS_STYLING[status];
  return `<span class="pill pill-overall" style="color:${s.color};background:${s.background}"><span class="pill-glyph">${escapeHtml(s.glyph)}</span> ${escapeHtml(s.label)}</span>`;
}

function renderStyleBlock(accent: string): string {
  // Build status pill style rules from the shared table so HTML + PDF stay in sync.
  const statusRules: string[] = [];
  for (const key of Object.keys(CONTROL_STATUS_STYLING)) {
    const s = CONTROL_STATUS_STYLING[key as keyof typeof CONTROL_STATUS_STYLING];
    statusRules.push(
      `.pill[data-status="${key}"]{color:${s.color};background:${s.background};}`,
    );
  }
  return `
    :root {
      --accent: ${accent};
      --ink: #1a1a1a;
      --muted: #5b6770;
      --panel: #f5f6f8;
      --rule: #d7dbe0;
      --code: #f0f2f5;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: var(--ink);
      background: #ffffff;
      line-height: 1.55;
      font-size: 15px;
    }
    main.doc { max-width: 1100px; margin: 0 auto; padding: 32px 48px 96px; }
    .accent-stripe { height: 6px; background: var(--accent); }
    .doc-header { border-bottom: 1px solid var(--rule); padding-bottom: 20px; margin-bottom: 24px; }
    .doc-header h1 { font-size: 26px; margin: 0 0 6px; color: var(--accent); }
    .doc-header .subtitle { font-size: 14px; color: var(--muted); margin: 0; }
    .doc-meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px 24px; margin-top: 14px; font-size: 13px; }
    .doc-meta dt { color: var(--muted); font-weight: 500; }
    .doc-meta dd { margin: 0; color: var(--ink); }
    .draft-banner {
      background: #fde9c8;
      color: #7a4a00;
      border: 1px solid #e5c58a;
      padding: 10px 14px;
      border-radius: 4px;
      font-size: 13px;
      margin: 16px 0;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    h2 { font-size: 19px; margin: 32px 0 12px; color: var(--ink); border-bottom: 1px solid var(--rule); padding-bottom: 6px; }
    h3 { font-size: 16px; margin: 20px 0 8px; color: var(--ink); }
    p { margin: 8px 0; }
    ul { margin: 8px 0; padding-left: 22px; }
    li { margin: 2px 0; }
    .pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; line-height: 1.6; }
    .pill-glyph { display: inline-block; margin-right: 4px; }
    .pill-overall { font-size: 13px; padding: 4px 12px; }
    ${statusRules.join(" ")}
    .coverage {
      background: var(--panel);
      border-left: 4px solid var(--accent);
      padding: 14px 18px;
      margin: 12px 0;
      font-size: 14px;
    }
    .coverage dl { margin: 0; display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; }
    .coverage dt { color: var(--muted); }
    table.controls { border-collapse: collapse; width: 100%; font-size: 14px; margin: 8px 0; }
    table.controls th, table.controls td {
      text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--rule); vertical-align: top;
    }
    table.controls th { background: var(--panel); font-weight: 600; font-size: 13px; color: var(--muted); }
    table.controls td a { color: var(--accent); text-decoration: none; }
    table.controls td a:hover { text-decoration: underline; }
    .control-section {
      border: 1px solid var(--rule);
      border-radius: 6px;
      padding: 16px 20px;
      margin: 16px 0;
      background: #ffffff;
    }
    .control-section header { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 6px; }
    .control-section header h3 { margin: 0; }
    .control-section .rationale { color: var(--muted); font-size: 14px; margin: 6px 0 12px; }
    .evidence-list { margin: 8px 0; padding: 0; list-style: none; }
    .evidence-list li {
      border-left: 3px solid var(--rule);
      padding: 6px 10px;
      margin: 6px 0;
      background: var(--panel);
      font-size: 13px;
    }
    .evidence-list .sev { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 6px; }
    .evidence-list .rule-id { font-family: "SF Mono", Consolas, monospace; font-size: 12px; color: var(--muted); margin-right: 6px; }
    .evidence-list .finding-id { font-family: "SF Mono", Consolas, monospace; font-size: 11px; color: var(--muted); }
    .evidence-list .summary { display: block; margin-top: 4px; color: var(--ink); }
    .mitigations { background: var(--panel); border-radius: 4px; padding: 10px 14px 10px 30px; margin: 12px 0; }
    .mitigations strong { display: block; color: var(--muted); margin-left: -16px; font-size: 13px; margin-bottom: 4px; }
    .kill-chain {
      border: 1px solid var(--rule);
      border-left: 4px solid #8a1f11;
      border-radius: 4px;
      padding: 14px 18px;
      margin: 12px 0;
      background: #fffaf9;
    }
    .kill-chain h3 { margin: 0 0 4px; }
    .kill-chain .kc-meta { font-size: 13px; color: var(--muted); margin: 0 0 8px; }
    .kill-chain .narrative { font-size: 14px; white-space: pre-wrap; }
    .rule-tag { display: inline-block; font-family: "SF Mono", Consolas, monospace; font-size: 12px; padding: 1px 8px; margin: 2px 4px 2px 0; background: var(--code); border-radius: 3px; color: var(--ink); }
    .attestation {
      border-top: 2px solid var(--accent);
      margin-top: 40px;
      padding-top: 20px;
    }
    .attestation dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; font-size: 13px; }
    .attestation dt { color: var(--muted); }
    .attestation dd { margin: 0; }
    .attestation .mono { font-family: "SF Mono", Consolas, monospace; font-size: 12px; }
    .attestation .signature {
      display: block; margin: 12px 0;
      padding: 10px 14px; background: var(--code); border-radius: 4px;
      font-family: "SF Mono", Consolas, monospace; font-size: 12px;
      word-break: break-all; white-space: pre-wrap;
    }
    .attestation .verify-instructions { background: var(--panel); border-radius: 4px; padding: 12px 16px; font-family: "SF Mono", Consolas, monospace; font-size: 12px; white-space: pre-wrap; }
    footer.doc-footer {
      margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--rule);
      font-size: 12px; color: var(--muted); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px;
    }
    footer.doc-footer a { color: var(--accent); text-decoration: none; }
    @media print {
      body { font-size: 12px; }
      main.doc { padding: 20px; max-width: none; }
      .control-section { page-break-inside: avoid; }
      .kill-chain { page-break-inside: avoid; }
      .attestation { page-break-inside: avoid; }
    }
  `;
}

function renderHeader(signed: SignedComplianceReport): string {
  const { report } = signed;
  const { server, framework, assessment } = report;
  return `
    <header class="doc-header">
      <h1>${escapeHtml(framework.name)} — Compliance Assessment</h1>
      <p class="subtitle">${escapeHtml(framework.version)} &middot; ${escapeHtml(framework.last_updated)} registry entry</p>
      <dl class="doc-meta">
        <dt>Server</dt><dd>${escapeHtml(server.name)} <code>(${escapeHtml(server.slug)})</code></dd>
        <dt>Scan id</dt><dd class="mono">${escapeHtml(server.scan_id)}</dd>
        <dt>Assessed at</dt><dd>${escapeHtml(formatIsoUtc(assessment.assessed_at))}</dd>
        <dt>Sentinel version</dt><dd>${escapeHtml(assessment.sentinel_version)}</dd>
      </dl>
      <div class="draft-banner" role="note">DRAFT for review — not legal advice. See attestation block for verification instructions.</div>
    </header>
  `;
}

function renderExecutiveSummary(signed: SignedComplianceReport): string {
  const { summary, executive_summary } = signed.report;
  return `
    <section class="executive">
      <h2>Executive summary</h2>
      <p>${renderOverallPill(summary.overall_status)}</p>
      <p>${escapeHtml(executive_summary)}</p>
    </section>
  `;
}

function renderCoverageBlock(signed: SignedComplianceReport): string {
  const { assessment } = signed.report;
  const techniques = assessment.techniques_run.length === 0
    ? "<li><em>none declared</em></li>"
    : assessment.techniques_run.map((t) => `<li>${escapeHtml(t)}</li>`).join("");
  return `
    <section class="coverage-section">
      <h2>Coverage &amp; transparency</h2>
      <div class="coverage">
        <dl>
          <dt>Coverage band</dt><dd>${escapeHtml(assessment.coverage_band)}</dd>
          <dt>Coverage ratio</dt><dd>${escapeHtml(formatPercent(assessment.coverage_ratio))}</dd>
          <dt>Rules version</dt><dd class="mono">${escapeHtml(assessment.rules_version)}</dd>
        </dl>
        <p style="margin-top:10px;margin-bottom:4px;color:#5b6770;font-size:13px;">Analysis techniques applied:</p>
        <ul>${techniques}</ul>
      </div>
    </section>
  `;
}

function renderControlsTable(signed: SignedComplianceReport): string {
  const rows = signed.report.controls.map((c) => {
    const anchor = anchorSlug(c.control_id);
    return `<tr>
      <td class="mono">${escapeHtml(c.control_id)}</td>
      <td><a href="#${escapeHtml(anchor)}">${escapeHtml(c.control_name)}</a></td>
      <td>${renderStatusPill(c.status)}</td>
      <td>${c.evidence.length}</td>
    </tr>`;
  }).join("");
  return `
    <section class="controls-section">
      <h2>Controls (${signed.report.summary.total_controls})</h2>
      <table class="controls">
        <thead>
          <tr><th>ID</th><th>Control</th><th>Status</th><th>Evidence</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </section>
  `;
}

function renderControlDetails(signed: SignedComplianceReport): string {
  const sections = signed.report.controls.map((c) => {
    const anchor = anchorSlug(c.control_id);
    const evidence = c.evidence.length === 0
      ? ""
      : `<ul class="evidence-list">${c.evidence.map((e) => {
          const sev = severityStyle(e.severity);
          return `<li>
            <span class="sev" style="color:${sev.color};background:${sev.background}">${escapeHtml(sev.label)}</span>
            <span class="rule-id">${escapeHtml(e.rule_id)}</span>
            <span class="finding-id">(finding ${escapeHtml(e.finding_id)}, confidence ${Math.round(e.confidence * 100)}%)</span>
            <span class="summary">${escapeHtml(e.evidence_summary)}</span>
          </li>`;
        }).join("")}</ul>`;
    const mitigations = c.required_mitigations.length === 0
      ? ""
      : `<div class="mitigations"><strong>Required mitigations</strong><ul>${c.required_mitigations.map((m) => `<li>${escapeHtml(m)}</li>`).join("")}</ul></div>`;
    return `
      <section class="control-section" id="${escapeHtml(anchor)}">
        <header>
          <h3>${escapeHtml(c.control_id)} — ${escapeHtml(c.control_name)}</h3>
          ${renderStatusPill(c.status)}
        </header>
        <p class="rationale">${escapeHtml(c.rationale)}</p>
        <p style="font-size:13px;margin:4px 0;"><a href="${escapeHtml(c.source_url)}" rel="noopener noreferrer">Framework reference</a></p>
        <p style="margin:8px 0 4px;font-size:13px;color:#5b6770;">Control text:</p>
        <p style="font-size:13px;">${escapeHtml(c.control_description)}</p>
        ${evidence}
        ${mitigations}
      </section>
    `;
  }).join("");
  return `<section class="control-details"><h2>Control details</h2>${sections}</section>`;
}

function renderKillChains(signed: SignedComplianceReport): string {
  const chains = signed.report.kill_chains;
  if (chains.length === 0) {
    return `
      <section class="kill-chains">
        <h2>Multi-step attack chains</h2>
        <p>No multi-step attack chains were synthesized for this server.</p>
      </section>
    `;
  }
  const blocks = chains.map((kc) => {
    const rules = kc.contributing_rule_ids.map((r) => `<span class="rule-tag">${escapeHtml(r)}</span>`).join("");
    const cves = kc.cve_evidence_ids.length === 0
      ? ""
      : `<p style="margin:6px 0;font-size:13px;"><strong>CVE cross-refs:</strong> ${kc.cve_evidence_ids.map((id) => `<span class="rule-tag">${escapeHtml(id)}</span>`).join("")}</p>`;
    const mits = kc.mitigations.length === 0
      ? ""
      : `<div class="mitigations"><strong>Mitigations</strong><ul>${kc.mitigations.map((m) => `<li>${escapeHtml(m)}</li>`).join("")}</ul></div>`;
    return `
      <article class="kill-chain">
        <h3>${escapeHtml(kc.kc_id)} — ${escapeHtml(kc.name)}</h3>
        <p class="kc-meta">Severity score: <strong>${(kc.severity_score).toFixed(2)}</strong></p>
        <p class="narrative">${escapeHtml(kc.narrative)}</p>
        <p style="margin:6px 0;font-size:13px;"><strong>Contributing rules:</strong> ${rules}</p>
        ${cves}
        ${mits}
      </article>
    `;
  }).join("");
  return `<section class="kill-chains"><h2>Multi-step attack chains</h2>${blocks}</section>`;
}

function renderAttestation(signed: SignedComplianceReport): string {
  const fields = attestationFields(signed);
  const fieldHtml = fields.map((f) => {
    const valueHtml = f.monospace
      ? `<dd class="mono">${escapeHtml(f.value)}</dd>`
      : `<dd>${escapeHtml(f.value)}</dd>`;
    return `<dt>${escapeHtml(f.label)}</dt>${valueHtml}`;
  }).join("");
  const sigLines = wrapFixedWidth(signed.attestation.signature, 64).map(escapeHtml).join("\n");
  const instructions = verificationInstructions(signed).map(escapeHtml).join("\n");
  return `
    <section class="attestation">
      <h2>Cryptographic attestation</h2>
      <dl>${fieldHtml}</dl>
      <p style="margin:12px 0 4px;color:#5b6770;font-size:13px;">HMAC-SHA256 signature (base64, wrapped at 64 chars):</p>
      <code class="signature">${sigLines}</code>
      <p style="margin:12px 0 4px;color:#5b6770;font-size:13px;">Verification instructions:</p>
      <pre class="verify-instructions">${instructions}</pre>
    </section>
  `;
}

function renderFooter(signed: SignedComplianceReport): string {
  const { framework } = signed.report;
  return `
    <footer class="doc-footer">
      <span>Generated ${escapeHtml(formatIsoUtc(signed.attestation.signed_at))} &middot; report version ${escapeHtml(signed.report.version)}</span>
      <span><a href="${escapeHtml(framework.source_url)}" rel="noopener noreferrer">${escapeHtml(framework.name)} reference</a></span>
    </footer>
  `;
}

function renderDocument(signed: SignedComplianceReport): string {
  const { report } = signed;
  const accent = accentFor(report.framework.id);
  const title = `MCP Sentinel — ${report.framework.name} — ${report.server.slug}`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="description" content="Compliance assessment of ${escapeHtml(report.server.name)} against ${escapeHtml(report.framework.name)}, attested by MCP Sentinel.">
<title>${escapeHtml(title)}</title>
<style>${renderStyleBlock(accent)}</style>
</head>
<body data-framework-id="${escapeHtml(report.framework.id)}">
<div class="accent-stripe" aria-hidden="true"></div>
<main class="doc">
${renderHeader(signed)}
${renderExecutiveSummary(signed)}
${renderCoverageBlock(signed)}
${renderControlsTable(signed)}
${renderControlDetails(signed)}
${renderKillChains(signed)}
${renderAttestation(signed)}
${renderFooter(signed)}
</main>
</body>
</html>`;
}

/**
 * Generic HTML renderer shared by all 7 frameworks. The framework's name,
 * accent colour, and control set are read from the signed report itself —
 * one implementation, seven registrations.
 */
export const htmlRenderer: ComplianceReportRenderer = {
  format: "html",
  contentType: "text/html; charset=utf-8",
  filenameSuffix: "html",
  render(signed) {
    return renderDocument(signed);
  },
};
