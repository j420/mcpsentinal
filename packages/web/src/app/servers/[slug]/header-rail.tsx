/**
 * HeaderRail — sticky 56px header. Server-rendered shell wrapping a tiny
 * client copy button. Carries the verdict (score + pill), the count
 * line, and the two action links (verify signature, download report).
 *
 * The score and verdict come from the view-model — derived locally from
 * findings — never from `audit_summary` (the audit panels are killed).
 */

import React from "react";
import CopyScanIdButton from "./copy-scan-id-button";
import { bandLabel } from "@/lib/score-band";
import type { PageViewModel } from "./view-model";
import type { DeepDiveServerStub, DeepDiveProvenance } from "@/lib/deep-dive";

export interface HeaderRailProps {
  vm: PageViewModel;
  server: DeepDiveServerStub;
  provenance: DeepDiveProvenance | null;
  /** Public API origin for signed-report + verify links. */
  apiOrigin: string;
  /** Default framework used for the download-report link. */
  defaultFramework?: string;
}

function shortScan(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

export default function HeaderRail({
  vm,
  server,
  provenance,
  apiOrigin,
  defaultFramework = "eu_ai_act",
}: HeaderRailProps): React.ReactElement {
  const { counts, score, band, verdict, lethalTrifectaActive } = vm;
  const scanId = provenance?.scan_id ?? null;
  const downloadHref = `${apiOrigin}/api/v1/servers/${encodeURIComponent(
    server.slug,
  )}/compliance/${defaultFramework}.pdf`;
  const verifyHref = `${apiOrigin}/api/v1/servers/${encodeURIComponent(
    server.slug,
  )}/compliance/${defaultFramework}.json`;

  return (
    <header
      className="fv-hdr"
      data-band={band}
      data-verdict={verdict.toLowerCase()}
      role="banner"
    >
      <div className="fv-hdr-inner">
        <div className="fv-hdr-left">
          <h1 className="fv-hdr-name" title={server.name}>
            {server.name}
          </h1>
          <span
            className={`fv-hdr-verdict fv-hdr-verdict-${verdict.toLowerCase()}`}
            title={
              lethalTrifectaActive
                ? "Lethal trifecta detected — score capped at 40"
                : `Verdict derived from severity counts`
            }
          >
            {verdict}
          </span>
          <span
            className={`fv-hdr-score fv-hdr-score-${band}`}
            aria-label={`Score ${score} out of 100 — ${bandLabel(band)}`}
          >
            <span className="fv-hdr-score-num">{score}</span>
            <span className="fv-hdr-score-band">{bandLabel(band)}</span>
          </span>
        </div>

        <div className="fv-hdr-center">
          <span className="fv-hdr-counts" aria-label="Scan summary">
            <span className="fv-hdr-count fv-hdr-count-findings">
              <strong>{counts.findings}</strong> finding{counts.findings === 1 ? "" : "s"}
            </span>
            <span className="fv-hdr-count-sep" aria-hidden="true">·</span>
            <span className="fv-hdr-count fv-hdr-count-skipped">
              <strong>{counts.skipped}</strong> skipped
            </span>
            <span className="fv-hdr-count-sep" aria-hidden="true">·</span>
            <span className="fv-hdr-count fv-hdr-count-passed">
              <strong>{counts.passed}</strong> passed
            </span>
            <span className="fv-hdr-count-sep" aria-hidden="true">·</span>
            <span className="fv-hdr-count fv-hdr-count-total">
              <strong>{counts.total}</strong> tested
            </span>
          </span>
        </div>

        <div className="fv-hdr-right">
          {scanId && (
            <CopyScanIdButton fullScanId={scanId} shortLabel={shortScan(scanId)} />
          )}
          <a
            className="fv-hdr-action fv-hdr-action-verify"
            href={verifyHref}
            target="_blank"
            rel="noopener noreferrer"
            title="Open the signed JSON report — verify the X-MCP-Sentinel-Signature header offline"
          >
            Verify signature
          </a>
          <a
            className="fv-hdr-action fv-hdr-action-download"
            href={downloadHref}
            target="_blank"
            rel="noopener noreferrer"
            title="Download the signed PDF compliance report"
          >
            Download report
          </a>
        </div>
      </div>
    </header>
  );
}
