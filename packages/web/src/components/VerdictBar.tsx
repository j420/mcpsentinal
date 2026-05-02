"use client";
/**
 * VerdictBar — sticky one-line verdict at the very top of the Deep Dive.
 *
 * Always present (never honest-gapped) — the bar always has SOMETHING to
 * say, even when the data is sparse (`buildVerdictHeadline` falls back to
 * "Awaiting scan data for this server."). The severity-tinted left edge
 * lets a regulator's eye land on the headline before reading anything
 * else.
 *
 * Server component — no client JS, no hooks. The "sticky" behaviour is
 * pure CSS via `position: sticky` so SSR is fully self-contained.
 *
 * Visual language: existing tokens only — `--sev-critical/high/info`,
 * `--surface`, `--border`, `--text`. No new design language.
 */

import React from "react";
import type {
  DeepDiveAttackChain,
  DeepDiveCategory,
  DeepDiveCoverageSummary,
} from "@/lib/deep-dive";
import { buildVerdictHeadline } from "@/lib/auto-narrative";

interface VerdictBarProps {
  serverName: string;
  coverage: DeepDiveCoverageSummary | undefined;
  categories: ReadonlyArray<DeepDiveCategory> | undefined;
  attackChains: ReadonlyArray<DeepDiveAttackChain> | undefined;
}

const TONE_TO_SEV: Record<string, string> = {
  critical: "critical",
  high: "high",
  info: "info",
  good: "low",
};

export default function VerdictBar({
  serverName,
  coverage,
  categories,
  attackChains,
}: VerdictBarProps) {
  const headline = buildVerdictHeadline({
    coverage,
    categories,
    attackChains,
  });
  const sev = TONE_TO_SEV[headline.tone] ?? "info";

  // Pull the verdict word ("Critical", "High", "Moderate", etc.) off the
  // front of the headline if one is present. The auto-narrative emits
  // strings like "Critical — N findings…" — splitting on the en-dash
  // lets us typeset the verdict word in a heavier weight while the rest
  // of the sentence stays book-weight, the way a court ruling reads.
  const dashSplit = headline.text.split(/\s+—\s+/);
  const verdictWord = dashSplit.length > 1 ? dashSplit[0] : null;
  const verdictRest = dashSplit.length > 1 ? dashSplit.slice(1).join(" — ") : headline.text;

  return (
    <div
      id="dd-section-verdict"
      className="vbar"
      data-tone={headline.tone}
      style={{ borderLeftColor: `var(--sev-${sev})` }}
      role="status"
      aria-live="polite"
    >
      <span className="vbar-server" title={serverName}>
        {serverName}
      </span>
      <span className="vbar-sep" aria-hidden="true">
        ·
      </span>
      <span className="vbar-headline">
        {verdictWord && (
          <>
            <span className="vbar-verdict-word" data-tone={headline.tone}>
              {verdictWord}
            </span>
            <span className="vbar-em-dash" aria-hidden="true">
              {" — "}
            </span>
          </>
        )}
        <span className="vbar-verdict-rest">{verdictRest}</span>
      </span>
      {/* Tiny attestation chip at the right edge — a one-glance receipt
          that this page's claims are signed and reproducible. Hidden on
          narrow viewports; the full attestation lives in the hero
          attestation line and the provenance footer. */}
      <span className="vbar-attest" aria-label="Signed page">
        <span className="vbar-attest-glyph" aria-hidden="true">
          ◆
        </span>
        <span className="vbar-attest-text">SIGNED</span>
      </span>
    </div>
  );
}
