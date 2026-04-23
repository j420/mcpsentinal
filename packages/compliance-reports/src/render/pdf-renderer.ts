// Determinism note
// ----------------
// pdfkit is not a designed-for-reproducibility PDF library. Two sources of
// non-determinism exist internally:
//   1. The `info.CreationDate` / `info.ModDate` fields default to `new Date()`
//      when the doc is constructed. We override BOTH with the attestation
//      `signed_at` timestamp so the XMP stream is stable input.
//   2. The document Trailer `/ID` entry is derived (in some pdfkit versions)
//      from the current time via an internal randomness source.
// We pin #1 and use only built-in fonts (Helvetica, Helvetica-Bold, Courier)
// to avoid font-loading order variance. The test suite therefore asserts the
// strong property we can guarantee — "produces a valid PDF of at least 2
// pages" — and a weaker byte-determinism check. If pdfkit emits non-identical
// bytes, the determinism test documents this as an honest failure rather
// than hiding it; see pdf-renderer.test.ts.

import PDFDocument from "pdfkit";

import type { ControlResult, KillChainNarrative, SignedComplianceReport } from "../types.js";
import { attestationFields, verificationInstructions } from "./shared/attestation-block.js";
import { formatIsoUtc, formatPercent, wrapFixedWidth } from "./shared/format-helpers.js";
import {
  CONTROL_STATUS_STYLING,
  OVERALL_STATUS_STYLING,
  severityStyle,
} from "./shared/status-styling.js";
import type { ComplianceReportRenderer } from "./types.js";

type RGB = [number, number, number];

const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const MARGIN = 72;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;

const FRAMEWORK_ACCENT: Record<string, RGB> = {
  eu_ai_act: [0x00, 0x33, 0x99],
  iso_27001: [0x0b, 0x5d, 0x1e],
  owasp_mcp: [0x6e, 0x1a, 0x7a],
  owasp_asi: [0x8a, 0x1f, 0x11],
  cosai_mcp: [0x11, 0x4f, 0x87],
  maestro: [0x7a, 0x4a, 0x00],
  mitre_atlas: [0x1a, 0x4a, 0x52],
};

function accentFor(id: string): RGB {
  return FRAMEWORK_ACCENT[id] ?? [0x1a, 0x1a, 0x1a];
}

function rgb(hex: string): RGB {
  const h = hex.startsWith("#") ? hex.slice(1) : hex;
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return [r, g, b];
}

// Palette used throughout the PDF.
const INK: RGB = [0x1a, 0x1a, 0x1a];
const MUTED: RGB = [0x5b, 0x67, 0x70];
const RULE_COLOR: RGB = [0xd7, 0xdb, 0xe0];
const BANNER_BG: RGB = [0xfd, 0xe9, 0xc8];
const BANNER_FG: RGB = [0x7a, 0x4a, 0x00];
const WATERMARK: RGB = [0xdd, 0xdd, 0xdd];
const KC_ACCENT: RGB = [0x8a, 0x1f, 0x11];

function ensureRoom(doc: PDFKit.PDFDocument, needed: number): void {
  const bottomLimit = PAGE_HEIGHT - MARGIN;
  if (doc.y + needed > bottomLimit) {
    doc.addPage();
  }
}

function drawStatusPill(
  doc: PDFKit.PDFDocument,
  label: string,
  color: RGB,
  background: RGB,
  x: number,
  y: number,
): number {
  const padX = 6;
  const padY = 2;
  doc.font("Helvetica-Bold").fontSize(9);
  const textWidth = doc.widthOfString(label);
  const h = 14;
  const w = textWidth + padX * 2;
  doc.save();
  doc.roundedRect(x, y, w, h, 7).fillColor(background).fill();
  doc.fillColor(color).text(label, x + padX, y + padY + 1, { lineBreak: false, width: textWidth });
  doc.restore();
  return w;
}

function drawTitlePage(doc: PDFKit.PDFDocument, signed: SignedComplianceReport, accent: RGB): void {
  const { report } = signed;

  // Coloured band at the top.
  doc.save();
  doc.rect(0, 0, PAGE_WIDTH, 6).fillColor(accent).fill();
  doc.restore();

  // Gray "DRAFT" watermark (rotated).
  doc.save();
  doc.translate(PAGE_WIDTH / 2, PAGE_HEIGHT / 2);
  doc.rotate(-30);
  doc.font("Helvetica-Bold").fontSize(120).fillColor(WATERMARK, 0.35);
  doc.text("DRAFT", -180, -60, { lineBreak: false, width: 360, align: "center" });
  doc.restore();

  // Title block.
  doc.fillColor(accent).font("Helvetica-Bold").fontSize(32);
  doc.text(report.framework.name, MARGIN, MARGIN + 20, { width: CONTENT_WIDTH });
  doc.moveDown(0.2);
  doc.fillColor(INK).font("Helvetica").fontSize(14);
  doc.text(`Compliance assessment — ${report.framework.version}`, { width: CONTENT_WIDTH });

  doc.moveDown(1.5);
  doc.font("Helvetica-Bold").fontSize(16).fillColor(INK);
  doc.text(`Server: ${report.server.name}`, { width: CONTENT_WIDTH });
  doc.font("Helvetica").fontSize(12).fillColor(MUTED);
  doc.text(`Slug: ${report.server.slug}`, { width: CONTENT_WIDTH });
  doc.text(`Scan id: ${report.server.scan_id}`, { width: CONTENT_WIDTH });

  doc.moveDown(1);
  doc.fontSize(12).fillColor(INK);
  doc.text(`Assessed at: ${formatIsoUtc(report.assessment.assessed_at)}`, { width: CONTENT_WIDTH });
  doc.text(`Sentinel version: ${report.assessment.sentinel_version}`, { width: CONTENT_WIDTH });
  doc.text(`Rules version: ${report.assessment.rules_version}`, { width: CONTENT_WIDTH });

  // Overall status pill.
  doc.moveDown(1.5);
  const overall = OVERALL_STATUS_STYLING[report.summary.overall_status];
  const color = rgb(overall.color);
  const bg = rgb(overall.background);
  const pillLabel = `${overall.glyph}  ${overall.label}`;
  drawStatusPill(doc, pillLabel, color, bg, MARGIN, doc.y);
  doc.moveDown(3);

  // Draft banner.
  const bannerY = doc.y;
  doc.rect(MARGIN, bannerY, CONTENT_WIDTH, 26).fillColor(BANNER_BG).fill();
  doc.font("Helvetica-Bold").fontSize(10).fillColor(BANNER_FG);
  doc.text(
    "DRAFT for review — not legal advice. See attestation block for verification instructions.",
    MARGIN + 12,
    bannerY + 8,
    { width: CONTENT_WIDTH - 24 },
  );
  doc.moveDown(2);
}

function drawSectionHeading(doc: PDFKit.PDFDocument, text: string, accent: RGB): void {
  ensureRoom(doc, 40);
  doc.moveDown(0.8);
  doc.font("Helvetica-Bold").fontSize(15).fillColor(accent);
  doc.text(text, MARGIN, doc.y, { width: CONTENT_WIDTH });
  const lineY = doc.y + 2;
  doc
    .moveTo(MARGIN, lineY)
    .lineTo(MARGIN + CONTENT_WIDTH, lineY)
    .strokeColor(accent)
    .lineWidth(0.5)
    .stroke();
  doc.moveDown(0.6);
  doc.fillColor(INK);
}

function drawParagraph(doc: PDFKit.PDFDocument, text: string, options: { size?: number; muted?: boolean } = {}): void {
  const size = options.size ?? 11;
  doc.font("Helvetica").fontSize(size);
  doc.fillColor(options.muted ? MUTED : INK);
  doc.text(text, MARGIN, doc.y, { width: CONTENT_WIDTH, align: "left" });
  doc.moveDown(0.4);
}

function drawTOC(doc: PDFKit.PDFDocument, accent: RGB): void {
  drawSectionHeading(doc, "Table of contents", accent);
  const entries = [
    "1. Executive summary",
    "2. Coverage & transparency",
    "3. Controls summary",
    "4. Control details",
    "5. Multi-step attack chains",
    "6. Cryptographic attestation",
  ];
  for (const entry of entries) {
    drawParagraph(doc, entry);
  }
}

function drawExecutiveSummary(doc: PDFKit.PDFDocument, signed: SignedComplianceReport, accent: RGB): void {
  drawSectionHeading(doc, "1. Executive summary", accent);
  drawParagraph(doc, signed.report.executive_summary);
}

function drawCoverage(doc: PDFKit.PDFDocument, signed: SignedComplianceReport, accent: RGB): void {
  drawSectionHeading(doc, "2. Coverage & transparency", accent);
  const { assessment } = signed.report;
  drawParagraph(doc, `Coverage band: ${assessment.coverage_band}`);
  drawParagraph(doc, `Coverage ratio: ${formatPercent(assessment.coverage_ratio)}`);
  drawParagraph(doc, `Rules version: ${assessment.rules_version}`);
  if (assessment.techniques_run.length > 0) {
    drawParagraph(doc, "Analysis techniques applied:", { muted: true });
    for (const t of assessment.techniques_run) {
      drawParagraph(doc, `  • ${t}`);
    }
  }
}

function drawControlsTable(doc: PDFKit.PDFDocument, controls: ControlResult[], accent: RGB): void {
  drawSectionHeading(doc, "3. Controls summary", accent);
  const colIdW = 70;
  const colNameW = CONTENT_WIDTH - colIdW - 90 - 70;
  const colStatusW = 90;
  const colEvidenceW = 70;

  doc.font("Helvetica-Bold").fontSize(10).fillColor(MUTED);
  doc.text("Control", MARGIN, doc.y, { width: colIdW, continued: true });
  doc.text("Name", { width: colNameW, continued: true });
  doc.text("Status", { width: colStatusW, continued: true });
  doc.text("Evidence", { width: colEvidenceW });
  const ruleY = doc.y + 2;
  doc
    .moveTo(MARGIN, ruleY)
    .lineTo(MARGIN + CONTENT_WIDTH, ruleY)
    .strokeColor(RULE_COLOR)
    .lineWidth(0.5)
    .stroke();
  doc.moveDown(0.4);

  doc.font("Helvetica").fontSize(10).fillColor(INK);
  for (const c of controls) {
    ensureRoom(doc, 18);
    const style = CONTROL_STATUS_STYLING[c.status];
    doc.text(c.control_id, MARGIN, doc.y, { width: colIdW, continued: true });
    doc.text(c.control_name.slice(0, 80), { width: colNameW, continued: true });
    doc.text(`${style.glyph}  ${style.label}`, { width: colStatusW, continued: true });
    doc.text(String(c.evidence.length), { width: colEvidenceW });
    doc.moveDown(0.2);
  }
}

function drawControlDetail(doc: PDFKit.PDFDocument, c: ControlResult, accent: RGB): void {
  ensureRoom(doc, 80);
  doc.moveDown(0.4);
  const style = CONTROL_STATUS_STYLING[c.status];
  doc.font("Helvetica-Bold").fontSize(12).fillColor(accent);
  doc.text(`${c.control_id} — ${c.control_name}`, MARGIN, doc.y, { width: CONTENT_WIDTH - 120 });
  const pillLabel = `${style.glyph}  ${style.label}`;
  drawStatusPill(doc, pillLabel, rgb(style.color), rgb(style.background), MARGIN + CONTENT_WIDTH - 110, doc.y - 14);

  doc.font("Helvetica").fontSize(10).fillColor(MUTED);
  doc.text(c.rationale, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.3);

  if (c.evidence.length > 0) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor(INK);
    doc.text("Evidence:", MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font("Helvetica").fontSize(9);
    for (const e of c.evidence) {
      const sev = severityStyle(e.severity);
      const confidencePct = Math.round(e.confidence * 100);
      doc.fillColor(rgb(sev.color));
      doc.text(`  [${sev.label}] `, MARGIN + 6, doc.y, { width: 70, continued: true });
      doc.fillColor(INK);
      doc.text(`${e.rule_id} (finding ${e.finding_id}, confidence ${confidencePct}%)`, { width: CONTENT_WIDTH - 80 });
      doc.fillColor(MUTED);
      doc.text(`    ${e.evidence_summary}`, MARGIN + 6, doc.y, { width: CONTENT_WIDTH - 12 });
      doc.moveDown(0.15);
    }
  }
  if (c.required_mitigations.length > 0) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor(INK);
    doc.text("Required mitigations:", MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font("Helvetica").fontSize(10);
    for (const m of c.required_mitigations) {
      doc.text(`  • ${m}`, MARGIN + 6, doc.y, { width: CONTENT_WIDTH - 12 });
    }
  }
  doc.moveDown(0.4);
}

function drawControlDetails(doc: PDFKit.PDFDocument, signed: SignedComplianceReport, accent: RGB): void {
  drawSectionHeading(doc, "4. Control details", accent);
  for (const c of signed.report.controls) {
    drawControlDetail(doc, c, accent);
  }
}

function drawKillChain(doc: PDFKit.PDFDocument, kc: KillChainNarrative): void {
  ensureRoom(doc, 100);
  doc.font("Helvetica-Bold").fontSize(12).fillColor(KC_ACCENT);
  doc.text(`${kc.kc_id} — ${kc.name}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.font("Helvetica").fontSize(10).fillColor(MUTED);
  doc.text(`Severity score: ${kc.severity_score.toFixed(2)}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.fillColor(INK).fontSize(10);
  doc.text(kc.narrative, MARGIN, doc.y + 2, { width: CONTENT_WIDTH, align: "left" });

  if (kc.contributing_rule_ids.length > 0) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor(MUTED);
    doc.text("Contributing rules:", MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font("Helvetica").fontSize(10).fillColor(INK);
    doc.text(kc.contributing_rule_ids.join(", "), MARGIN + 6, doc.y, { width: CONTENT_WIDTH - 12 });
  }
  if (kc.cve_evidence_ids.length > 0) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor(MUTED);
    doc.text("CVE cross-refs:", MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font("Helvetica").fontSize(10).fillColor(INK);
    doc.text(kc.cve_evidence_ids.join(", "), MARGIN + 6, doc.y, { width: CONTENT_WIDTH - 12 });
  }
  if (kc.mitigations.length > 0) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor(INK);
    doc.text("Mitigations:", MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font("Helvetica").fontSize(10);
    for (const m of kc.mitigations) {
      doc.text(`  • ${m}`, MARGIN + 6, doc.y, { width: CONTENT_WIDTH - 12 });
    }
  }
  doc.moveDown(0.5);
}

function drawKillChains(doc: PDFKit.PDFDocument, signed: SignedComplianceReport, accent: RGB): void {
  drawSectionHeading(doc, "5. Multi-step attack chains", accent);
  if (signed.report.kill_chains.length === 0) {
    drawParagraph(doc, "No multi-step attack chains were synthesized for this server.");
    return;
  }
  for (const kc of signed.report.kill_chains) {
    drawKillChain(doc, kc);
  }
}

function drawAttestation(doc: PDFKit.PDFDocument, signed: SignedComplianceReport, accent: RGB): void {
  drawSectionHeading(doc, "6. Cryptographic attestation", accent);
  doc.font("Helvetica").fontSize(10).fillColor(INK);
  for (const f of attestationFields(signed)) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor(MUTED);
    doc.text(`${f.label}:`, MARGIN, doc.y, { width: 120, continued: true });
    doc.font(f.monospace ? "Courier" : "Helvetica").fillColor(INK);
    doc.text(` ${f.value}`, { width: CONTENT_WIDTH - 120 });
  }
  doc.moveDown(0.6);

  doc.font("Helvetica-Bold").fontSize(10).fillColor(MUTED);
  doc.text("HMAC-SHA256 signature (base64, wrapped at 64 chars):", MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.font("Courier").fontSize(9).fillColor(INK);
  const lines = wrapFixedWidth(signed.attestation.signature, 64);
  for (const line of lines) {
    doc.text(line, MARGIN + 6, doc.y, { width: CONTENT_WIDTH - 12 });
  }

  doc.moveDown(0.6);
  doc.font("Helvetica-Bold").fontSize(10).fillColor(MUTED);
  doc.text("Verification instructions:", MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.font("Courier").fontSize(9).fillColor(INK);
  for (const line of verificationInstructions(signed)) {
    doc.text(line, MARGIN + 6, doc.y, { width: CONTENT_WIDTH - 12 });
  }
}

function drawFooterOnPage(
  doc: PDFKit.PDFDocument,
  signed: SignedComplianceReport,
  pageIndex: number,
  totalPages: number,
): void {
  const { framework, server } = signed.report;
  const text = `${pageIndex} / ${totalPages} — ${framework.name} — ${server.slug} — ${signed.attestation.signed_at}`;
  doc.save();
  doc.font("Helvetica").fontSize(8).fillColor(MUTED);
  doc.text(text, MARGIN, PAGE_HEIGHT - MARGIN / 2, { width: CONTENT_WIDTH, align: "center", lineBreak: false });
  doc.restore();
}

function renderPdf(signed: SignedComplianceReport): Buffer {
  const accent = accentFor(signed.report.framework.id);
  const signedAt = new Date(signed.attestation.signed_at);

  const doc = new PDFDocument({
    size: [PAGE_WIDTH, PAGE_HEIGHT],
    margins: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
    info: {
      Title: `${signed.report.framework.name} — ${signed.report.server.slug}`,
      Author: signed.attestation.signer,
      Subject: `Compliance assessment (${signed.report.framework.id})`,
      Producer: `MCP Sentinel ${signed.report.assessment.sentinel_version}`,
      Creator: `MCP Sentinel ${signed.report.assessment.sentinel_version}`,
      CreationDate: signedAt,
      ModDate: signedAt,
    },
    autoFirstPage: false,
  });

  const chunks: Buffer[] = [];
  doc.on("data", (chunk: Buffer) => chunks.push(chunk));

  doc.font("Helvetica");

  // Title page.
  doc.addPage();
  drawTitlePage(doc, signed, accent);

  // Content pages.
  doc.addPage();
  drawTOC(doc, accent);
  drawExecutiveSummary(doc, signed, accent);
  drawCoverage(doc, signed, accent);
  drawControlsTable(doc, signed.report.controls, accent);
  drawControlDetails(doc, signed, accent);
  drawKillChains(doc, signed, accent);
  drawAttestation(doc, signed, accent);

  // Footers.
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    drawFooterOnPage(doc, signed, range.start + i + 1, range.count);
  }

  doc.end();
  return Buffer.concat(chunks);
}

/** Generic PDF renderer shared by all 7 frameworks. */
export const pdfRenderer: ComplianceReportRenderer = {
  format: "pdf",
  contentType: "application/pdf",
  filenameSuffix: "pdf",
  render(signed) {
    return renderPdf(signed);
  },
};
