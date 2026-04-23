import type { ComplianceBadgeRenderer } from "./types.js";
import type {
  ComplianceReport,
  FrameworkId,
  OverallStatus,
  SignedComplianceReport,
} from "../types.js";

// ─── Framework accent colors ─────────────────────────────────────────────────
// Per the Phase 5 brief. These are the left-side label backgrounds. Each
// framework gets its official brand color so badges are recognisable at a
// glance on GitHub READMEs, status dashboards, and compliance evidence packs.
const FRAMEWORK_ACCENT_COLORS: Record<FrameworkId, string> = {
  eu_ai_act: "#003399", // EU blue
  iso_27001: "#0068b7", // ISO blue
  owasp_mcp: "#000000", // OWASP black
  owasp_asi: "#000000", // OWASP black
  cosai_mcp: "#1976d2", // Google blue
  maestro: "#5b21b6", // Purple
  mitre_atlas: "#dc2626", // MITRE red
};

// ─── Framework short names ───────────────────────────────────────────────────
// The left-hand badge text. Intentionally short so the badge fits inline in
// READMEs. NOT the same as the framework's formal `name` field (which is the
// full title used in reports).
const FRAMEWORK_SHORT_NAMES: Record<FrameworkId, string> = {
  eu_ai_act: "EU AI Act",
  iso_27001: "ISO 27001",
  owasp_mcp: "OWASP MCP",
  owasp_asi: "OWASP ASI",
  cosai_mcp: "CoSAI",
  maestro: "MAESTRO",
  mitre_atlas: "MITRE ATLAS",
};

// ─── Status → right-side background color ────────────────────────────────────
// Matches shields.io conventions: green=good, red=fail, amber=partial,
// gray=unknown. Using shields.io's exact palette so badges render
// consistently alongside existing badges.
const STATUS_COLORS: Record<OverallStatus, string> = {
  compliant: "#4c1",            // shields.io green
  non_compliant: "#e05d44",     // shields.io red
  partially_compliant: "#dfb317", // shields.io amber
  insufficient_evidence: "#9f9f9f", // shields.io gray
};

// ─── Character width estimate for SVG layout ─────────────────────────────────
// Verdana 11px has avg char width ~6px. We use 7px to err on the side of
// slightly-wide badges rather than truncated text. Deterministic — same input
// always yields same width.
const CHAR_WIDTH_PX = 7;
const PADDING_PX = 10;

function escapeXml(s: string): string {
  // Minimal XML escaping for text content + attribute values. Applied to
  // every piece of dynamic text that enters the SVG to prevent any
  // interpolated content from breaking the markup.
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function deriveStatusLabel(report: ComplianceReport): string {
  // Right-side badge text. For partially_compliant we show "X/Y met" to give
  // regulators a numeric read; for the other three states the single word is
  // the most informative.
  const { summary } = report;
  const status = summary.overall_status;
  if (status === "compliant") return "compliant";
  if (status === "non_compliant") return "non-compliant";
  if (status === "insufficient_evidence") return "insufficient evidence";
  // partially_compliant
  const assessed = summary.total_controls - summary.not_applicable;
  return `${summary.met}/${assessed} met`;
}

function badgeXml(
  labelText: string,
  valueText: string,
  labelColor: string,
  valueColor: string,
  attestation: SignedComplianceReport["attestation"],
): string {
  // Deterministic SVG layout. Width is computed from character count *
  // approximate per-char width + fixed padding. No font metrics, no
  // measureText, no Date.now() — pure function of inputs.
  const labelWidth = labelText.length * CHAR_WIDTH_PX + PADDING_PX * 2;
  const valueWidth = valueText.length * CHAR_WIDTH_PX + PADDING_PX * 2;
  const totalWidth = labelWidth + valueWidth;
  const labelTextX = labelWidth / 2;
  const valueTextX = labelWidth + valueWidth / 2;

  const ariaLabel = escapeXml(`${labelText}: ${valueText}`);
  const labelSafe = escapeXml(labelText);
  const valueSafe = escapeXml(valueText);
  const labelColorSafe = escapeXml(labelColor);
  const valueColorSafe = escapeXml(valueColor);

  // Attestation is embedded as an XML comment at the top of the file.
  // Regulators can extract it via any XML-aware parser without having to
  // render the badge. The comment format is a stable key=value list; any
  // renderer that wants to verify the badge re-canonicalises the underlying
  // ComplianceReport and recomputes the HMAC — the comment is evidence of
  // WHICH report this badge represents, not a standalone attestation.
  const attestationComment =
    `<!-- attestation: algorithm=${escapeXml(attestation.algorithm)} ` +
    `canonicalization=${escapeXml(attestation.canonicalization)} ` +
    `signer=${escapeXml(attestation.signer)} ` +
    `key_id=${escapeXml(attestation.key_id)} ` +
    `signed_at=${escapeXml(attestation.signed_at)} ` +
    `signature=${escapeXml(attestation.signature)} -->`;

  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    attestationComment,
    `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${ariaLabel}">`,
    `<title>${ariaLabel}</title>`,
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`,
    `<clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>`,
    `<g clip-path="url(#r)">`,
    `<rect width="${labelWidth}" height="20" fill="${labelColorSafe}"/>`,
    `<rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${valueColorSafe}"/>`,
    `<rect width="${totalWidth}" height="20" fill="url(#s)"/>`,
    `</g>`,
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">`,
    `<text aria-hidden="true" x="${labelTextX * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(labelWidth - PADDING_PX * 2) * 10}">${labelSafe}</text>`,
    `<text x="${labelTextX * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="${(labelWidth - PADDING_PX * 2) * 10}">${labelSafe}</text>`,
    `<text aria-hidden="true" x="${valueTextX * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(valueWidth - PADDING_PX * 2) * 10}">${valueSafe}</text>`,
    `<text x="${valueTextX * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="${(valueWidth - PADDING_PX * 2) * 10}">${valueSafe}</text>`,
    `</g>`,
    `</svg>`,
  ].join("");
}

/**
 * Generic SVG renderer. One instance is registered under each framework id
 * with the `framework` field rebound — see `register-all.ts`. The renderer
 * itself reads the framework id off the incoming report, so the registered
 * `framework` field only disambiguates the registry key.
 */
export const SVG_BADGE_RENDERER: ComplianceBadgeRenderer = {
  // Placeholder; `register-all.ts` clones this object per framework and
  // overrides `framework` to match the registration key. Callers that hit
  // the renderer directly (outside the registry) will pass through with
  // whatever value is here.
  framework: "eu_ai_act",
  render(report, attestation): string {
    const frameworkId = report.framework.id;
    const accent = FRAMEWORK_ACCENT_COLORS[frameworkId];
    const short = FRAMEWORK_SHORT_NAMES[frameworkId];
    const statusColor = STATUS_COLORS[report.summary.overall_status];
    const statusLabel = deriveStatusLabel(report);
    return badgeXml(short, statusLabel, accent, statusColor, attestation);
  },
};

/** Exported for tests that need to verify color choices without a full report. */
export const __TESTING = {
  FRAMEWORK_ACCENT_COLORS,
  FRAMEWORK_SHORT_NAMES,
  STATUS_COLORS,
  deriveStatusLabel,
};
