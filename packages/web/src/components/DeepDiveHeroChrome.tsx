/**
 * DeepDiveHeroChrome — single-row strip that anchors the new long-scroll
 * deep-dive page IA.
 *
 * Layout — three slots, one row, ~80px tall:
 *   [ identity (compact) ] · [ score + grade + confidence + pips ] · [ Signed Pack ▼ ]
 *
 * Why this exists separately from `<EvidenceSummaryHero/>`:
 *   The previous IA put a 3-column hero + a 7-row pack card + the OWASP grid
 *   above the tabs. The user's call ("currently it's hidden under carpet") is
 *   that this chrome competes with the deep-dive content for vertical
 *   attention. This component demotes the chrome to one strip; the long
 *   scroll IS the page now.
 *
 * `<EvidenceSummaryHero/>` is NOT deleted — other consumers (or a fallback
 * code path on this same page when the new deep-dive endpoint 404s) may
 * still need it.
 *
 * The "Signed pack" affordance reuses the same producer data
 * (`SignedEvidencePack/getAttestation()`-style fetch) so a CISO sees the
 * same attestation chips no matter which page primitive is mounted.
 */

import React from "react";
import {
  shortHash,
  fmtSignedAt,
  __TEST_FRAMEWORKS as PACK_FRAMEWORKS,
} from "./SignedEvidencePack";
import type { DeepDiveCoverageSummary } from "@/lib/deep-dive";

// ── Helpers (kept local — mirror EvidenceSummaryHero so the two stay in lock-step) ──

function scoreBand(score: number): "good" | "moderate" | "poor" | "critical" {
  if (score >= 80) return "good";
  if (score >= 60) return "moderate";
  if (score >= 40) return "poor";
  return "critical";
}

function scoreToLetter(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "A−";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  if (score >= 40) return "D−";
  return "F";
}

function bandLabel(band: ReturnType<typeof scoreBand>): string {
  return { good: "Good", moderate: "Moderate", poor: "Poor", critical: "Critical" }[band];
}

function coverageBandLabel(band: NonNullable<DeepDiveCoverageSummary["coverage_band"]>): string {
  return { high: "HIGH", medium: "MEDIUM", low: "LOW", minimal: "MINIMAL" }[band];
}

function coverageBandColor(band: NonNullable<DeepDiveCoverageSummary["coverage_band"]>): string {
  if (band === "high") return "var(--good)";
  if (band === "medium") return "var(--moderate)";
  if (band === "low") return "var(--poor)";
  return "var(--critical)";
}

// ── Attestation fetch (mirror of SignedEvidencePack.getAttestation) ─────────────────

interface AttestationChips {
  signature: string | null;
  key_id: string | null;
  signed_at: string | null;
  algorithm: string | null;
  canonicalization: string | null;
  dev_key_warning: boolean;
}

async function getAttestation(slug: string, apiUrl: string): Promise<AttestationChips | null> {
  try {
    const res = await fetch(
      `${apiUrl}/api/v1/servers/${encodeURIComponent(slug)}/compliance/eu_ai_act.json`,
      {
        signal: AbortSignal.timeout(4000),
        next: { revalidate: 300 },
      },
    );
    if (!res.ok) return null;
    return {
      signature: res.headers.get("x-mcp-sentinel-signature"),
      key_id: res.headers.get("x-mcp-sentinel-key-id"),
      signed_at: res.headers.get("x-mcp-sentinel-signed-at"),
      algorithm: res.headers.get("x-mcp-sentinel-algorithm"),
      canonicalization: res.headers.get("x-mcp-sentinel-canonicalization"),
      dev_key_warning: res.headers.get("x-mcp-sentinel-warning") === "dev-key-in-use",
    };
  } catch {
    return null;
  }
}

// ── Pip ────────────────────────────────────────────────────────────────────────────

function Pip({
  label,
  on,
  title,
}: {
  label: string;
  on: boolean;
  title: string;
}) {
  return (
    <span
      className={`dd-pip dd-pip-${on ? "on" : "off"}`}
      title={`${title}${on ? "" : " — NOT available for this scan"}`}
      aria-label={`${label}: ${on ? "available" : "missing"}`}
    >
      <span className="dd-pip-glyph" aria-hidden="true">
        {on ? "✓" : "×"}
      </span>
      <span className="dd-pip-label">{label}</span>
    </span>
  );
}

// ── Props ──────────────────────────────────────────────────────────────────────────

export interface DeepDiveHeroChromeProps {
  /** Identity ── left slot. */
  name: string;
  server_version: string | null;
  author: string | null;
  /** Score band ── center slot. */
  total_score: number | null;
  /** Whether F1/I13 fired and the scorer should cap at 40. */
  lethal: boolean;
  /** Optional confidence band. When absent the chip is hidden. */
  coverage_band: DeepDiveCoverageSummary["coverage_band"] | null;
  /** What the analyzer actually had to work with. */
  had_source_code: boolean;
  had_connection: boolean;
  had_dependencies: boolean;
  /** Right slot — fetched separately so the strip degrades gracefully. */
  slug: string;
  apiUrl: string;
}

// ── Component ──────────────────────────────────────────────────────────────────────

export default async function DeepDiveHeroChrome(props: DeepDiveHeroChromeProps) {
  const score = props.total_score;
  const effectiveScore =
    score == null ? null : props.lethal ? Math.min(score, 40) : score;
  const band = effectiveScore == null ? "critical" : scoreBand(effectiveScore);
  const letter = effectiveScore == null ? "F" : scoreToLetter(effectiveScore);

  const att = await getAttestation(props.slug, props.apiUrl);
  const slugEnc = encodeURIComponent(props.slug);

  return (
    <section
      className="dd-hero"
      aria-label="Server identity, score, and signed pack"
      data-lethal={props.lethal ? "true" : "false"}
    >
      {/* ── Left slot: identity (compact) ───────────────────────────── */}
      <div className="dd-hero-identity">
        <h1 className="dd-hero-name">{props.name}</h1>
        <div className="dd-hero-id-meta">
          {props.server_version && (
            <span className="dd-hero-meta-chip dd-hero-meta-mono">
              v{props.server_version}
            </span>
          )}
          {props.author && <span className="dd-hero-meta-chip">{props.author}</span>}
        </div>
      </div>

      {/* ── Center slot: score + grade + confidence + pips ─────────── */}
      <div className="dd-hero-score">
        {props.lethal && (
          <span
            className="dd-hero-lethal"
            title="F1/I13 detected — score capped at 40 by the scorer"
          >
            LETHAL TRIFECTA
          </span>
        )}
        <div className="dd-hero-score-row">
          <span
            className="dd-hero-score-num"
            style={{ color: `var(--${band})` }}
            aria-label={`Score ${effectiveScore ?? "unknown"} of 100`}
          >
            {effectiveScore == null ? "—" : effectiveScore}
          </span>
          <span className="dd-hero-score-of">/ 100</span>
          <span
            className="dd-hero-letter"
            style={{ color: `var(--${band})` }}
            title="Synthesized from total_score (UI label only)"
          >
            {letter}
          </span>
          <span
            className="dd-hero-band"
            style={{ color: `var(--${band})` }}
          >
            {bandLabel(band)}
          </span>
        </div>
        <div className="dd-hero-conf-row">
          {props.coverage_band && (
            <span
              className={`dd-hero-conf dd-hero-conf-${props.coverage_band}`}
              style={{
                color: coverageBandColor(props.coverage_band),
                borderColor: coverageBandColor(props.coverage_band),
              }}
              role="status"
              aria-label={`Analysis confidence: ${coverageBandLabel(
                props.coverage_band,
              ).toLowerCase()}`}
            >
              {coverageBandLabel(props.coverage_band)} confidence
            </span>
          )}
          <span className="dd-hero-pips" role="list">
            <Pip
              label="source"
              on={props.had_source_code}
              title="Source code fetched and parsed"
            />
            <Pip
              label="live"
              on={props.had_connection}
              title="Live MCP initialize+tools/list completed"
            />
            <Pip
              label="deps"
              on={props.had_dependencies}
              title="Dependency manifest audited"
            />
          </span>
        </div>
      </div>

      {/* ── Right slot: Signed Pack disclosure ─────────────────────── */}
      <details className="dd-hero-pack" data-testid="dd-hero-pack">
        <summary className="dd-hero-pack-trigger" aria-label="Open signed compliance pack">
          <span className="dd-hero-pack-trigger-label">Signed pack</span>
          <span className="dd-hero-pack-trigger-chev" aria-hidden="true">
            ▼
          </span>
          {att?.dev_key_warning && (
            <span className="dd-hero-pack-warn" title="Dev HMAC key in use">
              DEV
            </span>
          )}
        </summary>

        <div className="dd-hero-pack-panel" role="region" aria-label="Signed compliance pack">
          <div
            className="dd-hero-pack-chips"
            role="status"
            aria-label="Attestation parameters"
          >
            <span className="dd-hero-pack-chip">
              <span className="dd-hero-pack-chip-k">algorithm</span>
              <span className="dd-hero-pack-chip-v">
                {att?.algorithm ?? "HMAC-SHA256"}
              </span>
            </span>
            <span className="dd-hero-pack-chip">
              <span className="dd-hero-pack-chip-k">canon</span>
              <span className="dd-hero-pack-chip-v">
                {att?.canonicalization ?? "RFC 8785"}
              </span>
            </span>
            <span className="dd-hero-pack-chip">
              <span className="dd-hero-pack-chip-k">key</span>
              <span className="dd-hero-pack-chip-v dd-hero-pack-mono">
                {shortHash(att?.key_id ?? null, 6, 4)}
              </span>
            </span>
            <span className="dd-hero-pack-chip">
              <span className="dd-hero-pack-chip-k">signed</span>
              <span className="dd-hero-pack-chip-v">
                {fmtSignedAt(att?.signed_at ?? null)}
              </span>
            </span>
            <span
              className="dd-hero-pack-chip"
              title={att?.signature ?? "Attestation unavailable"}
            >
              <span className="dd-hero-pack-chip-k">sig</span>
              <span className="dd-hero-pack-chip-v dd-hero-pack-mono">
                {shortHash(att?.signature ?? null, 10, 4)}
              </span>
            </span>
          </div>

          <ul className="dd-hero-pack-grid" aria-label="Compliance frameworks">
            {PACK_FRAMEWORKS.map((fw) => (
              <li key={fw.id} className="dd-hero-pack-row">
                <div className="dd-hero-pack-row-id">
                  <div className="dd-hero-pack-row-name">{fw.label}</div>
                  <div className="dd-hero-pack-row-sub">{fw.sub}</div>
                </div>
                <div className="dd-hero-pack-row-actions">
                  <a
                    className="dd-hero-pack-fmt dd-hero-pack-fmt-pdf"
                    href={`${props.apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.pdf`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`Download ${fw.label} signed PDF`}
                  >
                    PDF
                  </a>
                  <a
                    className="dd-hero-pack-fmt"
                    href={`${props.apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`Open ${fw.label} signed HTML`}
                  >
                    HTML
                  </a>
                  <a
                    className="dd-hero-pack-fmt"
                    href={`${props.apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.json`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`Download ${fw.label} signed JSON`}
                  >
                    JSON
                  </a>
                  <a
                    className="dd-hero-pack-fmt"
                    href={`${props.apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}/badge.svg`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`${fw.label} signed badge SVG`}
                  >
                    Badge
                  </a>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </details>
    </section>
  );
}

// Test-only re-export of helpers so the unit test can pin behaviour.
export {
  scoreBand as __TEST_scoreBand,
  scoreToLetter as __TEST_scoreToLetter,
  bandLabel as __TEST_bandLabel,
  coverageBandLabel as __TEST_coverageBandLabel,
  coverageBandColor as __TEST_coverageBandColor,
};
