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
  return (
    <div
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
      <span className="vbar-headline">{headline.text}</span>
    </div>
  );
}
