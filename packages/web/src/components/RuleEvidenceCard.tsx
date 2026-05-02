"use client";
/**
 * RuleEvidenceCard
 * ────────────────
 * The atomic unit of the Deep Dive — ONE rule, three honest-rendered states.
 *
 * Marked `"use client"` so the page-level <SectionBoundary/> wrapping
 * each category can catch any render exception in this subtree —
 * server-component SSR throws otherwise propagate to the route-level
 * error.tsx (HTTP 500) without giving the per-section graceful-
 * degradation a chance to fire.
 *

 * The page leads with what was tested and what was found. Every state
 * surfaces the methodology + backing visibly so a regulator sees the
 * testing was done; the auditor never has to guess at silent absence.
 *
 * Three render states (driven entirely by `rule.status`):
 *
 *   A. `findings`  — rule fired against this server.
 *      • Severity-tinted left border (`var(--sev-${severity})`)
 *      • Methodology block (technique · backing · last validation)
 *      • EVERY finding mounts `<EvidenceChainViz/>` independently
 *
 *   B. `passed`    — rule executed and produced no findings.
 *      • Collapsed by default but VISIBLY present (header + one-line summary)
 *      • Native `<details>` for expand/collapse — no client JS required
 *      • Green check eyebrow + status pill "PASSED"
 *
 *   C. `skipped`   — rule could not execute (input missing).
 *      • Explicit reason rendered (derived from category + missing inputs)
 *      • Methodology in `<details>` so the testing intent stays visible
 *      • Muted "○" eyebrow + status pill "SKIPPED"
 *
 * Cross-reference handling: when this card renders from a non-canonical
 * sub-category, the caller passes `crossRef` and we render a single-line
 * "see canonical" link to `#rule-<rule_id>` in lieu of the full card.
 *
 * Server component — no hooks. Long-scroll page must render fast at the
 * network seam; the methodology + finding bodies are inside `<details>`
 * so expand/collapse is native, not client-state.
 *
 * Anchor: `id={`rule-${rule_id}`}` with `scroll-margin-top: 96px` so
 * jumps clear the deep-dive chrome strip.
 *
 * Visual language: tokens only — `--text`, `--text-2`, `--text-3`,
 * `--surface`, `--surface-2`, `--border`, `--border-md`, `--good`,
 * `--moderate`, `--poor`, `--accent-2`, `--sev-${severity}`,
 * `--sev-${severity}-sub`, `--sev-${severity}-border`. No raw colours.
 */

import React from "react";
import EvidenceChainViz, {
  type EvidenceChainData,
} from "@/components/EvidenceChainViz";
import ForensicTrigger from "@/components/ForensicTrigger";
import type {
  DeepDiveRule,
  DeepDiveRuleBacking,
  DeepDiveSeverity,
  DeepDiveFrameworkControl,
  DeepDiveFinding,
} from "@/lib/deep-dive";

/* ─── Public props ──────────────────────────────────────────────────── */

export interface RuleEvidenceCardProps {
  /** One rule's deep-dive payload. */
  rule: DeepDiveRule;
  /**
   * When set, render only a one-line "see canonical" link pointing at
   * `#rule-<rule_id>`. Used by sub-categories listed in the rule's
   * `cross_referenced_in` array — the rule is rendered fully in its
   * canonical sub-category and merely cross-linked here.
   */
  crossRef?: boolean;
}

/* ─── Vocabulary ────────────────────────────────────────────────────── */

/** Pretty-print a category id into something a CISO recognises. */
const CATEGORY_LABELS: Record<string, string> = {
  "code-analysis": "Code Analysis",
  "description-analysis": "Description Analysis",
  "schema-analysis": "Schema Analysis",
  "dependency-analysis": "Dependency Analysis",
  "behavioral-analysis": "Behavioral Analysis",
  "ecosystem-context": "Ecosystem Context",
  "adversarial-ai": "Adversarial AI",
  "auth-analysis": "Authentication",
  "protocol-surface": "Protocol Surface",
  "threat-intelligence": "Threat Intelligence",
  "compliance-governance": "Compliance & Governance",
  "supply-chain-advanced": "Supply Chain",
  "ai-runtime-exploitation": "AI Runtime",
  "protocol-edge-cases": "Protocol Edge Cases",
  "data-privacy-attacks": "Data Privacy",
  "infrastructure-runtime": "Infrastructure",
  "cross-ecosystem-emergent": "Cross-Ecosystem",
};

/** Severity → ALL CAPS pill text. */
const SEVERITY_LABEL: Record<DeepDiveSeverity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  informational: "INFO",
};

/* ─── Helpers ──────────────────────────────────────────────────────── */

/**
 * Format a backing precision/recall into a 2-decimal string. Returns the
 * em-dash when the value is missing — matches the DetectionQualityFooter
 * convention so the evidence dossier reads consistently across views.
 */
function formatScalar(value: number | undefined): string {
  if (value === undefined || value === null) return "—";
  return value.toFixed(2);
}

/**
 * Compact relative-time formatter for `last_validated_at`. Mirrors the
 * `fmtRelative` private helpers elsewhere in the codebase; intentionally
 * duplicated until a third site needs it (per Cluster C policy).
 */
function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return "never validated";
  try {
    const d = new Date(iso);
    const ms = Date.now() - d.getTime();
    if (!Number.isFinite(ms)) return "unknown";
    if (ms < 0) {
      return d.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
      });
    }
    if (ms < 60_000) return "just now";
    if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
    if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
    if (ms < 7 * 86_400_000) return `${Math.floor(ms / 86_400_000)}d ago`;
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

/**
 * Reason copy for a skipped rule. Derived deterministically from the
 * rule's category — analyzer categories that need source code or a live
 * connection are the usual sources of "skipped" status. We render the
 * reason explicitly because silent absence is the gap the audit doc
 * called out.
 */
function skipReasonFor(category: string): string {
  switch (category) {
    case "code-analysis":
    case "compliance-governance":
    case "supply-chain-advanced":
    case "data-privacy-attacks":
    case "infrastructure-runtime":
    case "protocol-edge-cases":
      return "required source code (none fetched for this scan)";
    case "dependency-analysis":
      return "required a package manifest (none available)";
    case "behavioral-analysis":
      return "required a live MCP connection (none established)";
    case "ai-runtime-exploitation":
    case "cross-ecosystem-emergent":
      return "required mixed inputs not present in this scan";
    default:
      return "required inputs not available for this scan";
  }
}

/**
 * Compute aggregate "X fixtures · Y CVEs" string for the methodology
 * one-liner. Returns `null` when there is no backing at all so the caller
 * renders the honest "no validation evidence wired" copy instead.
 */
function summariseBacking(backing: DeepDiveRuleBacking | null): string | null {
  if (!backing) return null;
  const fixtureCount = backing.fixture_count ?? 0;
  const cveCount = backing.cve_replay_ids?.length ?? 0;
  const hasPrec = typeof backing.precision === "number";
  const hasRecall = typeof backing.recall === "number";
  const parts: string[] = [];
  if (fixtureCount > 0) {
    parts.push(`${fixtureCount} fixture${fixtureCount === 1 ? "" : "s"}`);
  }
  if (cveCount > 0) {
    parts.push(`${cveCount} CVE${cveCount === 1 ? "" : "s"}`);
  }
  if (hasPrec && backing.precision !== null) parts.push(`precision ${formatScalar(backing.precision)}`);
  if (hasRecall && backing.recall !== null) parts.push(`recall ${formatScalar(backing.recall)}`);
  if (parts.length === 0) return null;
  return parts.join(" · ");
}

/* ─── Sub-components ───────────────────────────────────────────────── */

/** Header eyebrow + identity row. Same shape across all three states. */
function CardEyebrow({
  rule,
  state,
}: {
  rule: DeepDiveRule;
  state: "findings" | "passed" | "skipped";
}) {
  const eyebrowGlyph =
    state === "findings" ? "▌" : state === "passed" ? "✓" : "○";
  const eyebrowClass =
    state === "findings"
      ? "rec-eyebrow-findings"
      : state === "passed"
        ? "rec-eyebrow-passed"
        : "rec-eyebrow-skipped";
  const pillLabel =
    state === "findings"
      ? SEVERITY_LABEL[rule.severity]
      : state === "passed"
        ? "PASSED"
        : "SKIPPED";
  const pillClass = `rec-status-pill rec-status-${state}`;

  // Identity lines: rule_id + name on top, framework attributions below.
  const refs: string[] = [];
  if (rule.owasp) refs.push(`OWASP ${rule.owasp}`);
  if (rule.mitre) refs.push(`MITRE ${rule.mitre}`);
  // Surface up to two extra framework crosswalks inline so the eyebrow
  // stays compact; deeper detail lives in the methodology block.
  for (const fc of rule.framework_controls) {
    if (refs.length >= 4) break;
    if (fc.framework_id === "owasp_mcp" && rule.owasp) continue;
    if (fc.framework_id === "mitre_atlas" && rule.mitre) continue;
    refs.push(controlLabel(fc));
  }

  const cat = CATEGORY_LABELS[rule.category] ?? rule.category;

  return (
    <header className="rec-head">
      <div className="rec-head-line rec-head-line-1">
        <span className={`rec-eyebrow ${eyebrowClass}`} aria-hidden="true">
          {eyebrowGlyph}
        </span>
        <span
          className="rec-rule-id"
          data-trace={`rule:${rule.rule_id}`}
          tabIndex={0}
        >
          {rule.rule_id}
        </span>
        <span className="rec-head-sep" aria-hidden="true">
          ·
        </span>
        <span className="rec-rule-name">{rule.name}</span>
        <span className={pillClass} aria-label={`Status: ${pillLabel}`}>
          {pillLabel}
        </span>
      </div>
      <div className="rec-head-line rec-head-line-2">
        <span className="rec-category" title="Detection category">
          {cat}
        </span>
        {refs.length > 0 && (
          <>
            <span className="rec-head-sep" aria-hidden="true">
              ·
            </span>
            <span className="rec-refs">{refs.join(" · ")}</span>
          </>
        )}
      </div>
      {rule.summary && (
        <p className="rec-summary" data-rec-summary>
          {rule.summary}
        </p>
      )}
      {rule.validated_by_cve && rule.validated_by_cve.length > 0 && (
        <CveValidationStrip validations={rule.validated_by_cve} />
      )}
    </header>
  );
}

/**
 * Resolve the public API origin once per render. The web package exposes
 * `NEXT_PUBLIC_API_URL` (Cluster B precedent — see `page.tsx`), so the
 * receipt link points at the api host directly rather than the web host.
 * Falls back to localhost for dev parity with the api Dockerfile EXPOSE.
 */
function publicApiOrigin(): string {
  return (
    (typeof process !== "undefined" && process.env.NEXT_PUBLIC_API_URL) ||
    "http://localhost:3100"
  );
}

/**
 * FindingReceiptLink — opens the per-finding HMAC-SHA256-signed receipt
 * in a new tab. The link target is the api origin (NEXT_PUBLIC_API_URL),
 * not the web origin, so verifiers see the canonical JSON envelope
 * straight from the api package without a same-origin reverse proxy.
 *
 * Defensive: encodeURIComponent throws on non-string input. We guard
 * against the (theoretically impossible but observed in production)
 * case of a missing finding.id by rendering nothing — the receipt is
 * an enhancement, not a critical UI element.
 */
function FindingReceiptLink({ findingId }: { findingId: string }) {
  if (!findingId || typeof findingId !== "string") return null;
  let href: string;
  try {
    href = `${publicApiOrigin()}/api/v1/findings/${encodeURIComponent(
      findingId,
    )}/receipt`;
  } catch {
    return null;
  }
  return (
    <div className="rec-finding-receipt">
      <a
        className="rec-finding-receipt-link"
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        title="HMAC-SHA256-signed canonical JSON envelope (RFC 8785)"
      >
        🔒 Signed receipt ↗
      </a>
      <span className="rec-finding-receipt-help">
        Auditors: this finding can be independently verified offline.
      </span>
    </div>
  );
}

/**
 * CveValidationStrip — small in-card pill row listing the Phase-4 CVE
 * replay corpus cases that exercise this rule. Honest "validated against
 * real attacks" signal: every entry links to NVD (or research source)
 * and shows the CVSS where present.
 *
 * Defensive: every field of the validation entry is checked at runtime
 * because production data may have shapes TS does not yet know about.
 */
function CveValidationStrip({
  validations,
}: {
  validations: NonNullable<DeepDiveRule["validated_by_cve"]>;
}) {
  const valid = validations.filter(
    (v) => v && typeof v.id === "string" && typeof v.source_url === "string",
  );
  if (valid.length === 0) return null;
  return (
    <div className="rec-cve-strip" role="group" aria-label="CVE replay validation">
      <span className="rec-cve-strip-label">
        Validated against {valid.length} replay
        {valid.length === 1 ? "" : "s"}
      </span>
      <ul className="rec-cve-strip-list">
        {valid.map((v) => {
          const titleParts: string[] = [];
          if (typeof v.title === "string") titleParts.push(v.title);
          if (typeof v.disclosed === "string") {
            titleParts.push(`disclosed ${v.disclosed}`);
          }
          if (typeof v.cvss_v3 === "number" && Number.isFinite(v.cvss_v3)) {
            titleParts.push(`CVSS ${v.cvss_v3.toFixed(1)}`);
          }
          return (
            <li key={v.id} className="rec-cve-strip-item">
              <a
                href={v.source_url}
                target="_blank"
                rel="noopener noreferrer"
                className="rec-cve-strip-link"
                title={titleParts.join(" · ")}
                data-trace={`cve:${v.id}`}
              >
                {v.id}
              </a>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/**
 * Display label for one cross-walked framework control. Defers to the
 * upstream `label` when present; otherwise falls back to a stable
 * "<framework_short> <control>" pattern derived from the contract.
 */
function controlLabel(fc: DeepDiveFrameworkControl): string {
  const fwShort: Record<string, string> = {
    owasp_mcp: "OWASP MCP",
    owasp_asi: "OWASP ASI",
    eu_ai_act: "EU AI Act",
    iso_27001: "ISO 27001",
    cosai_mcp: "CoSAI",
    maestro: "MAESTRO",
    mitre_atlas: "MITRE ATLAS",
  };
  const fw = fwShort[fc.framework_id] ?? fc.framework_id;
  return `${fw} ${fc.control_id}`;
}

/**
 * Methodology + backing block. Renders the same content in all three
 * states; only the wrapper toggles between always-visible (state A) and
 * collapsed `<details>` (states B/C). Native `<details>` keeps this a
 * server component with no client JS.
 */
function MethodologyBlock({
  rule,
  collapsible,
  defaultOpen = false,
}: {
  rule: DeepDiveRule;
  collapsible: boolean;
  defaultOpen?: boolean;
}) {
  // Cluster D reviewer B5 — `methodology` is an object, not a string.
  // The card shows `technique` as the headline + verified_edge_cases as a
  // visible body list (audit doc evidence-first principle: methodology
  // must be readable, not just a one-word tag).
  const technique = rule.methodology?.technique?.trim() ?? "";
  const verifiedEdgeCases = rule.methodology?.verified_edge_cases ?? [];
  const confidenceCap = rule.methodology?.confidence_cap ?? null;
  const backingSummary = summariseBacking(rule.backing);
  const lastValidated = fmtRelative(rule.backing?.last_validated_at ?? null);

  // The header "summary line" is what is visible when the details element
  // is collapsed — a one-shot density read of the testing posture.
  const headerLine = `${technique ? technique : "technique not declared"}${
    backingSummary ? ` · ${backingSummary}` : " · no backing data wired yet"
  }`;

  const body = (
    <div className="rec-method-body">
      <dl className="rec-method-dl">
        <div className="rec-method-row">
          <dt className="rec-method-k">Technique</dt>
          <dd className="rec-method-v">
            {technique ? (
              <code className="rec-method-mono">{technique}</code>
            ) : (
              <span className="rec-method-gap">technique not declared</span>
            )}
          </dd>
        </div>

        <div className="rec-method-row">
          <dt className="rec-method-k">Backing</dt>
          <dd className="rec-method-v">
            {backingSummary ? (
              <span>{backingSummary}</span>
            ) : (
              <span className="rec-method-gap">
                no fixtures or CVE replays for this rule yet
              </span>
            )}
          </dd>
        </div>

        {verifiedEdgeCases.length > 0 && (
          <div className="rec-method-row">
            <dt className="rec-method-k">Verified edge cases</dt>
            <dd className="rec-method-v">
              <ul className="rec-edge-list" aria-label="Verified edge cases">
                {verifiedEdgeCases.map((edge, i) => (
                  <li key={`${i}-${edge.slice(0, 24)}`}>
                    <span className="rec-edge-tick" aria-hidden="true">✓</span>
                    {edge}
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        )}

        {rule.backing && rule.backing.cve_replay_ids.length > 0 && (
          <div className="rec-method-row">
            <dt className="rec-method-k">CVE replays</dt>
            <dd className="rec-method-v">
              {rule.backing.cve_replay_ids.map((cve, i) => (
                <React.Fragment key={`${cve}-${i}`}>
                  {i > 0 && <span className="rec-method-sep"> </span>}
                  <a
                    className="rec-cve"
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(
                      cve,
                    )}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`View ${cve} on NVD`}
                  >
                    {cve}
                  </a>
                </React.Fragment>
              ))}
            </dd>
          </div>
        )}

        {rule.framework_controls.length > 0 && (
          <div className="rec-method-row">
            <dt className="rec-method-k">Frameworks</dt>
            <dd className="rec-method-v">
              <ul className="rec-fw-list" aria-label="Framework cross-walk">
                {rule.framework_controls.map((fc, i) => (
                  <li key={`${fc.framework_id}-${fc.control_id}-${i}`}>
                    <span
                      className="rec-fw-pill"
                      data-trace={`control:${fc.framework_id}:${fc.control_id}`}
                      tabIndex={0}
                    >
                      <span className="rec-fw-id">{controlLabel(fc)}</span>
                      {fc.control_title && (
                        <span className="rec-fw-title" title={fc.control_title}>
                          {fc.control_title}
                        </span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        )}

        {confidenceCap !== null && confidenceCap < 1 && (
          <div className="rec-method-row">
            <dt className="rec-method-k">Confidence cap</dt>
            <dd className="rec-method-v">
              <span className="rec-method-conf">≤ {confidenceCap.toFixed(2)}</span>
              <span className="rec-method-conf-note">
                {" "}
                — declared in CHARTER (residual uncertainty acknowledged)
              </span>
            </dd>
          </div>
        )}

        {rule.backing?.last_validated_at && (
          <div className="rec-method-row">
            <dt className="rec-method-k">Last validated</dt>
            <dd className="rec-method-v">
              <span title={rule.backing.last_validated_at}>{lastValidated}</span>
            </dd>
          </div>
        )}
      </dl>
    </div>
  );

  if (!collapsible) {
    return (
      <section className="rec-method rec-method-open" data-rec-method>
        <div className="rec-method-head" data-rec-method-head>
          <span className="rec-method-eyebrow" aria-hidden="true">
            TEST METHODOLOGY
          </span>
          <span className="rec-method-summary" aria-label="Methodology summary">
            {headerLine}
          </span>
        </div>
        {body}
      </section>
    );
  }

  // Collapsible variant: native <details>/<summary> for SSR-safe expand.
  return (
    <details
      className="rec-method rec-method-collapsible"
      data-rec-method
      open={defaultOpen || undefined}
    >
      <summary className="rec-method-head" data-rec-method-head>
        <span className="rec-method-chev" aria-hidden="true">
          ▸
        </span>
        <span className="rec-method-eyebrow">TEST METHODOLOGY</span>
        <span className="rec-method-summary" aria-label="Methodology summary">
          {headerLine}
        </span>
      </summary>
      {body}
    </details>
  );
}

/** One finding, mounting the full EvidenceChainViz. */
function FindingPanel({
  finding,
  ruleId,
  defaultOpen,
}: {
  finding: DeepDiveFinding;
  ruleId: string;
  defaultOpen: boolean;
}) {
  const sev = finding.severity;
  // The first finding for a rule is auto-expanded so the dossier reads
  // immediately on first scroll-into-view; subsequent findings collapse
  // to keep the long-scroll page navigable.
  return (
    <details
      className={`rec-finding rec-finding-${sev}`}
      open={defaultOpen || undefined}
      // Anchor: when a kill-chain or sidebar deep-link points at a
      // finding, we still want the rule anchor to land first; finding
      // anchors are the secondary `#finding-<rule_id>-<idx>` form so
      // multiple findings on the same rule are individually addressable.
      id={`finding-${ruleId}-${finding.id}`}
    >
      <summary className="rec-finding-head">
        <span
          className={`rec-finding-sev sev-badge sev-${sev}`}
          aria-label={`Severity: ${SEVERITY_LABEL[sev]}`}
        >
          {SEVERITY_LABEL[sev]}
        </span>
        <span className="rec-finding-id" title={finding.id}>
          {finding.id.length > 10 ? finding.id.slice(0, 10) + "…" : finding.id}
        </span>
        <span className="rec-finding-evidence-eyebrow">
          {finding.evidence.length > 140
            ? finding.evidence.slice(0, 140) + "…"
            : finding.evidence}
        </span>
        <span className="rec-finding-chev" aria-hidden="true">
          ▾
        </span>
      </summary>

      <div className="rec-finding-body">
        <p className="rec-finding-evidence-text">{finding.evidence}</p>

        <EvidenceChainViz
          chain={
            finding.evidence_chain as EvidenceChainData | null | undefined
          }
          confidence={finding.confidence}
        />

        {/* Cluster D reviewer B5 — `framework_controls` live on the parent
            rule, NOT per-finding. The Frameworks row in the methodology
            block above already renders them. Removed per-finding
            duplication. */}

        {finding.remediation && (
          <div className="rec-finding-rem">
            <span className="rec-finding-rem-label">Fix</span>
            <span className="rec-finding-rem-text">{finding.remediation}</span>
          </div>
        )}

        <div className="rec-finding-action-row">
          <FindingReceiptLink findingId={finding.id} />
          <ForensicTrigger findingId={finding.id} />
        </div>
      </div>
    </details>
  );
}

/* ─── Main component ──────────────────────────────────────────────── */

export default function RuleEvidenceCard({
  rule,
  crossRef = false,
}: RuleEvidenceCardProps) {
  // Cross-reference render: a one-liner pointing at the canonical card.
  // No methodology repeat, no findings repeat — purely a deep-link.
  if (crossRef) {
    return (
      <div
        className="rec-xref"
        data-rec-xref
        aria-label={`Cross-reference: ${rule.rule_id} appears in this section; canonical card lives elsewhere`}
      >
        <span className="rec-xref-glyph" aria-hidden="true">
          ↗
        </span>
        <span className="rec-xref-id">{rule.rule_id}</span>
        <span className="rec-xref-name">{rule.name}</span>
        <a
          className="rec-xref-link"
          href={`#rule-${rule.rule_id}`}
          aria-label={`Jump to canonical entry for ${rule.rule_id}`}
        >
          see canonical →
        </a>
      </div>
    );
  }

  const status = rule.status;
  const sev = rule.severity;

  // Severity-tinted left border lives on a CSS variable so we can
  // express it once here and let the stylesheet handle dark/light tints.
  const borderStyle: React.CSSProperties = {
    ["--rec-sev-color" as never]: `var(--sev-${sev})`,
    ["--rec-sev-sub" as never]: `var(--sev-${sev}-sub)`,
    ["--rec-sev-border" as never]: `var(--sev-${sev}-border)`,
  };

  // ── State A: findings ────────────────────────────────────────────
  if (status === "findings") {
    return (
      <article
        id={`rule-${rule.rule_id}`}
        className={`rec-card rec-card-findings rec-sev-${sev}`}
        style={borderStyle}
        aria-label={`${rule.rule_id} ${rule.name} — ${rule.findings.length} finding${rule.findings.length === 1 ? "" : "s"} on this server`}
        data-rec-status="findings"
      >
        <CardEyebrow rule={rule} state="findings" />
        <MethodologyBlock rule={rule} collapsible={false} />

        <section
          className="rec-findings"
          aria-label={`Evidence on this server (${rule.findings.length} finding${rule.findings.length === 1 ? "" : "s"})`}
        >
          <div className="rec-findings-head">
            <span className="rec-findings-eyebrow">EVIDENCE ON THIS SERVER</span>
            <span className="rec-findings-count">
              {rule.findings.length} finding
              {rule.findings.length === 1 ? "" : "s"}
            </span>
          </div>
          {rule.findings.map((f, i) => (
            <FindingPanel
              key={f.id}
              finding={f}
              ruleId={rule.rule_id}
              defaultOpen={i === 0}
            />
          ))}
        </section>

        {rule.remediation && (
          <div className="rec-rule-rem" aria-label="Rule-level remediation">
            <span className="rec-rule-rem-label">General fix</span>
            <span className="rec-rule-rem-text">{rule.remediation}</span>
          </div>
        )}
      </article>
    );
  }

  // ── State B: passed ──────────────────────────────────────────────
  if (status === "passed") {
    return (
      <article
        id={`rule-${rule.rule_id}`}
        className={`rec-card rec-card-passed rec-sev-${sev}`}
        style={borderStyle}
        aria-label={`${rule.rule_id} ${rule.name} — passed on this server`}
        data-rec-status="passed"
      >
        <CardEyebrow rule={rule} state="passed" />
        <MethodologyBlock rule={rule} collapsible={true} />
      </article>
    );
  }

  // ── State C: skipped ─────────────────────────────────────────────
  const reason = skipReasonFor(rule.category);
  return (
    <article
      id={`rule-${rule.rule_id}`}
      className={`rec-card rec-card-skipped rec-sev-${sev}`}
      style={borderStyle}
      aria-label={`${rule.rule_id} ${rule.name} — skipped: ${reason}`}
      data-rec-status="skipped"
    >
      <CardEyebrow rule={rule} state="skipped" />
      <p className="rec-skip-reason" data-rec-skip-reason>
        <span className="rec-skip-reason-eyebrow">Skipped</span>
        <span className="rec-skip-reason-sep" aria-hidden="true">
          —
        </span>
        <span className="rec-skip-reason-text">{reason}</span>
      </p>
      <MethodologyBlock rule={rule} collapsible={true} />
    </article>
  );
}
