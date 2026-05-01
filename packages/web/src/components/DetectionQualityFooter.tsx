/**
 * DetectionQualityFooter — per-finding validation receipt.
 *
 * Cluster C part 3 (Invention #4): one row, rendered below the framework
 * cross-walk on every finding card, that answers an auditor's standing
 * question — "how do I know your detector works?". The signals come from
 * the red-team accuracy harness + CVE replay corpus, and are surfaced
 * through Agent 1's frozen `detection_quality` field on each finding.
 *
 * Three states render visibly (Cluster A/B honest-gap principle):
 *   A. full data         → precision · recall · fixture_count · CVE chips
 *   B. wired-but-empty   → "Validation framework wired — no fixtures or
 *                          CVE replays for this rule yet"
 *   C. not-wired         → "Detection quality not yet wired for this rule"
 *
 * Backwards-compat: when the field is `undefined` (older API), nothing
 * renders — old deployments stay green.
 *
 * This component is the SHARED PRIMITIVE — used identically from both the
 * flat list (FindingsEvidenceTab) and the grouped view (CategoryDeepDivePanel),
 * mirroring the Cluster B `<FrameworkCrosswalkRow/>` pattern. Re-rendering
 * the same markup in two views is the contract; the orchestrator can extract
 * later if a third site needs it.
 *
 * Click target: the OWASP MCP signed compliance pack PDF for this server.
 * Per the spec, the per-rule page does not exist yet — the OWASP MCP PDF
 * is the regulator-grade artifact carrying the rule's framework attribution.
 */

import React from "react";
import {
  type DetectionQuality,
  bandFor,
  type QualityBand,
} from "@/lib/detection-quality";

/** Maximum CVE chips rendered inline; the rest collapse into "+N more". */
const MAX_VISIBLE_CVE_CHIPS = 4;

interface Props {
  /**
   * Detection-quality envelope for a single finding.
   *   - non-null object → render state A or B
   *   - null            → render state C ("not yet wired")
   *   - undefined       → render NOTHING (backwards-compat)
   */
  detection_quality: DetectionQuality | null | undefined;
  /** Server slug — used to build the click-through PDF URL. */
  slug: string;
  /** API base URL — passed in so this component stays env-free for testing. */
  apiUrl: string;
  /** Rule id (e.g. "K1") — surfaced in the row's aria-label. */
  ruleId: string;
}

/**
 * Compact relative-time formatter. A private clone of SignedEvidencePack's
 * helper — per the briefing, do not reach across components for one use; the
 * duplication is fine until it crosses 3 sites.
 */
function fmtRelative(iso: string | null): { rel: string; abs: string } {
  if (!iso) return { rel: "—", abs: "" };
  try {
    const d = new Date(iso);
    const ms = Date.now() - d.getTime();
    const abs = d.toLocaleString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
    if (!Number.isFinite(ms) || ms < 0) return { rel: abs, abs };
    if (ms < 60_000) return { rel: "just now", abs };
    if (ms < 3_600_000) return { rel: `${Math.floor(ms / 60_000)}m ago`, abs };
    if (ms < 86_400_000) return { rel: `${Math.floor(ms / 3_600_000)}h ago`, abs };
    if (ms < 7 * 86_400_000) return { rel: `${Math.floor(ms / 86_400_000)}d ago`, abs };
    return {
      rel: d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
      abs,
    };
  } catch {
    return { rel: iso, abs: iso };
  }
}

function formatScalar(value: number | null): string {
  if (value === null) return "—";
  // Two-decimal precision keeps "0.95" / "0.88" readable at a glance and
  // matches the regulator-facing report style.
  return value.toFixed(2);
}

function bandColor(b: QualityBand): string {
  if (b === "good") return "var(--good)";
  if (b === "moderate") return "var(--moderate)";
  if (b === "poor") return "var(--poor)";
  return "var(--text-3)";
}

/**
 * Single precision/recall numeric chip. Color follows the band thresholds
 * declared in detection-quality.ts; null renders the muted em-dash.
 */
function MetricChip({
  label,
  value,
  ariaLabel,
}: {
  label: string;
  value: number | null;
  ariaLabel: string;
}) {
  const b = bandFor(value);
  return (
    <span
      className={`dqf-metric dqf-metric-${b}`}
      style={{ color: bandColor(b) }}
      aria-label={ariaLabel}
      title={ariaLabel}
    >
      <span className="dqf-metric-k" aria-hidden="true">{label}</span>
      <span className="dqf-metric-v">{formatScalar(value)}</span>
    </span>
  );
}

/**
 * Renders one CVE chip linking to nvd.nist.gov for that CVE id. The id is
 * passed verbatim from the contract — no normalisation, no regex parsing.
 */
function CveChip({ cve }: { cve: string }) {
  const href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
  return (
    <a
      className="dqf-cve"
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={`View ${cve} on NVD`}
      title={cve}
    >
      {cve}
    </a>
  );
}

export default function DetectionQualityFooter({
  detection_quality,
  slug,
  apiUrl,
  ruleId,
}: Props) {
  // ── State D: backwards-compat ─────────────────────────────────────────
  // Older API responses omit the field. Render nothing — pre-Cluster-C
  // deployments must stay regression-free.
  if (detection_quality === undefined) return null;

  const slugEnc = encodeURIComponent(slug);
  // Click target is the OWASP MCP PDF (per spec): the regulator-grade
  // artifact carrying the rule's framework attribution. Per-rule pages
  // do not exist yet; this is the closest signed evidence document.
  const href = `${apiUrl}/api/v1/servers/${slugEnc}/compliance/owasp_mcp.pdf`;
  const rowAriaLabel = `View signed evidence backing for ${ruleId}`;

  // ── State C: not-wired ────────────────────────────────────────────────
  // The whole envelope is null. Render the muted "not yet wired" line —
  // visibly, so the gap is acknowledged rather than buried.
  // The row is a <div> (not an <a>) because state A nests CVE anchors;
  // a wrapping <a> would create invalid nested-anchor markup. The
  // trailing chevron anchor at the end of the row IS the click target.
  if (detection_quality === null) {
    return (
      <div className="dqf-row dqf-row-unwired" aria-label={rowAriaLabel}>
        <span className="dqf-status dqf-status-unwired" aria-hidden="true">○</span>
        <span className="dqf-unwired-text">
          Detection quality not yet wired for this rule
        </span>
        <a
          className="dqf-cta"
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={rowAriaLabel}
        >
          View signed pack →
        </a>
      </div>
    );
  }

  const {
    precision,
    recall,
    fixture_count,
    cve_replay_ids,
    last_validated_at,
  } = detection_quality;

  const hasFixtures = fixture_count > 0;
  const hasCves = cve_replay_ids.length > 0;
  const hasAnyValidation = hasFixtures || hasCves;

  // ── State B: wired-but-empty ──────────────────────────────────────────
  // The harness recognises the rule but no fixtures or CVE replays back it.
  // Render quietly, but render — the gap is the point.
  if (!hasAnyValidation) {
    return (
      <div className="dqf-row dqf-row-empty" aria-label={rowAriaLabel}>
        <span className="dqf-status dqf-status-empty" aria-hidden="true">·</span>
        <span className="dqf-empty-text">
          Validation framework wired — no fixtures or CVE replays for this rule yet
        </span>
        <a
          className="dqf-cta"
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={rowAriaLabel}
        >
          View signed pack →
        </a>
      </div>
    );
  }

  // ── State A: full data ────────────────────────────────────────────────
  const visibleCves = cve_replay_ids.slice(0, MAX_VISIBLE_CVE_CHIPS);
  const overflowCves = cve_replay_ids.slice(MAX_VISIBLE_CVE_CHIPS);
  const overflowTitle = overflowCves.join(", ");
  const { rel, abs } = fmtRelative(last_validated_at);

  return (
    <div className="dqf-row dqf-row-full" aria-label={rowAriaLabel}>
      <span className="dqf-status dqf-status-validated" aria-hidden="true">✓</span>
      <span className="dqf-label">Validated</span>

      {hasFixtures && (
        <>
          <span className="dqf-sep" aria-hidden="true">·</span>
          <span className="dqf-fixtures" aria-label={`${fixture_count} red-team fixtures`}>
            {fixture_count} fixture{fixture_count === 1 ? "" : "s"}
          </span>
        </>
      )}

      {hasCves && (
        <>
          <span className="dqf-sep" aria-hidden="true">·</span>
          <span className="dqf-cve-group">
            {visibleCves.map((c, idx) => (
              <React.Fragment key={`${c}-${idx}`}>
                {idx > 0 && <span className="dqf-cve-sep" aria-hidden="true"> </span>}
                <CveChip cve={c} />
              </React.Fragment>
            ))}
            {overflowCves.length > 0 && (
              <span
                className="dqf-cve-more"
                title={overflowTitle}
                aria-label={`${overflowCves.length} additional CVE${overflowCves.length === 1 ? "" : "s"}: ${overflowTitle}`}
              >
                +{overflowCves.length} more
              </span>
            )}
          </span>
        </>
      )}

      <span className="dqf-sep" aria-hidden="true">·</span>
      <MetricChip
        label="p"
        value={precision}
        ariaLabel={`precision ${formatScalar(precision)}`}
      />
      <MetricChip
        label="r"
        value={recall}
        ariaLabel={`recall ${formatScalar(recall)}`}
      />

      {last_validated_at && (
        <>
          <span className="dqf-sep" aria-hidden="true">·</span>
          <span
            className="dqf-validated-at"
            title={abs || last_validated_at}
            aria-label={`last validated ${rel}`}
          >
            last validated {rel}
          </span>
        </>
      )}

      <a
        className="dqf-cta"
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        aria-label={rowAriaLabel}
      >
        View signed pack →
      </a>
    </div>
  );
}
