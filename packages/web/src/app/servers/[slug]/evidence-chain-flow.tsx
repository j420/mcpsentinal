/**
 * EvidenceChainFlow — the page's hero element.
 *
 * Renders the structured evidence chain (source → propagation* → sink →
 * mitigation* → impact) as a horizontal rail of pills connected by
 * chevron arrows. This is the visual proof: a CISO or funder sees the
 * chain at a glance and understands what was found, why, and where.
 *
 * Input is the wire-typed `evidence_chain: Record<string, unknown> | null`
 * straight off the DeepDiveFinding. We never trust the shape — every link
 * narrows defensively before rendering. A null or malformed chain falls
 * back to the prose `evidence` string so the rule card still has a body.
 *
 * Verification steps (when present) render as a small numbered strip
 * ABOVE the chain. Confidence factors and threat reference render BELOW.
 *
 * Pure rendering. No hooks, no state, no fetch. Mobile: chain stacks
 * vertically via CSS, arrows rotate via CSS as well — no JS branch.
 */

import React from "react";

// ── Local narrowing — duplicates analyzer's evidence.ts shapes ────────
// We can't import from `@mcp-sentinel/analyzer` (boundary rule, see
// web/CLAUDE.md). The wire ships `Record<string, unknown>`; we narrow
// per-link to the minimum surface this component renders.

type LinkKind = "source" | "propagation" | "sink" | "mitigation" | "impact";

interface NormalizedLink {
  kind: LinkKind;
  /** Short label for the pill heading, e.g. "user-parameter", "exec()". */
  label: string;
  /** Human location like "tools.run.input" or "src/index.ts:42". */
  location: string;
  /** The actual text / pattern observed at this point. */
  observed: string;
  /** Optional rationale / detail (mitigation: detail; source: rationale). */
  detail: string | null;
  /** Optional CVE precedent — only on sink links. */
  cvePrecedent: string | null;
  /** Mitigation: was it present? (for present/absent badge). */
  mitigationPresent: boolean | null;
  /** Impact: exploitability hint. */
  exploitability: string | null;
}

interface NormalizedChain {
  links: NormalizedLink[];
  confidence: number | null;
  confidenceFactors: Array<{ factor: string; adjustment: number; rationale: string }>;
  threatRef: { id: string; title: string; url?: string } | null;
  verificationSteps: Array<{
    stepNumber: number;
    instruction: string;
    target: string;
    expected: string;
  }>;
}

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function asBool(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

/**
 * Render a `Location` record (or prose) into a single human label.
 * Mirrors the analyzer's `renderLocation` but operates on the unknown wire
 * shape — we don't have the typed union here.
 */
function renderLocation(loc: unknown): string {
  if (typeof loc === "string") return loc;
  const r = asRecord(loc);
  if (!r) return "";
  const kind = asString(r.kind);
  switch (kind) {
    case "source": {
      const file = asString(r.file) ?? "";
      const line = asNumber(r.line);
      const col = asNumber(r.col);
      const length = asNumber(r.length);
      const pos = col !== null ? `${line ?? ""}:${col}` : `${line ?? ""}`;
      return length !== null ? `${file}:${pos}+${length}` : `${file}:${pos}`;
    }
    case "tool":
      return `tool ${asString(r.tool_name) ?? ""}`;
    case "parameter":
      return `tool ${asString(r.tool_name) ?? ""} parameter ${asString(r.parameter_path) ?? ""}`;
    case "schema":
      return `tool ${asString(r.tool_name) ?? ""} schema ${asString(r.json_pointer) ?? ""}`;
    case "dependency":
      return `${asString(r.ecosystem) ?? ""}:${asString(r.name) ?? ""}@${asString(r.version) ?? ""}`;
    case "config":
      return `${asString(r.file) ?? ""}${asString(r.json_pointer) ?? ""}`;
    case "initialize":
      return `initialize.${asString(r.field) ?? ""}`;
    case "resource": {
      const uri = asString(r.uri) ?? "";
      const field = asString(r.field);
      return field ? `resource ${uri}#${field}` : `resource ${uri}`;
    }
    case "prompt": {
      const name = asString(r.name) ?? "";
      const field = asString(r.field);
      return field ? `prompt ${name}#${field}` : `prompt ${name}`;
    }
    case "capability":
      return `capability:${asString(r.capability) ?? ""}`;
    default:
      return "";
  }
}

function isLinkKind(v: unknown): v is LinkKind {
  return (
    v === "source" ||
    v === "propagation" ||
    v === "sink" ||
    v === "mitigation" ||
    v === "impact"
  );
}

function linkLabel(kind: LinkKind, raw: Record<string, unknown>): string {
  switch (kind) {
    case "source":
      return asString(raw.source_type) ?? "source";
    case "propagation":
      return asString(raw.propagation_type) ?? "propagation";
    case "sink":
      return asString(raw.sink_type) ?? "sink";
    case "mitigation":
      return asString(raw.mitigation_type) ?? "mitigation";
    case "impact":
      return asString(raw.impact_type) ?? "impact";
  }
}

function linkDetail(kind: LinkKind, raw: Record<string, unknown>): string | null {
  switch (kind) {
    case "source":
      return asString(raw.rationale);
    case "mitigation":
      return asString(raw.detail);
    case "impact":
      return asString(raw.scenario);
    default:
      return null;
  }
}

function normalizeChain(chain: Record<string, unknown> | null): NormalizedChain | null {
  if (!chain) return null;
  const rawLinks = asArray(chain.links);
  const links: NormalizedLink[] = [];
  for (const raw of rawLinks) {
    const rec = asRecord(raw);
    if (!rec) continue;
    const kind = rec.type;
    if (!isLinkKind(kind)) continue;
    const observed =
      kind === "impact"
        ? asString(rec.scope) ?? ""
        : asString(rec.observed) ?? "";
    links.push({
      kind,
      label: linkLabel(kind, rec),
      location:
        kind === "impact"
          ? "" // impact links have no `location`; surfaced via exploitability
          : renderLocation(rec.location),
      observed,
      detail: linkDetail(kind, rec),
      cvePrecedent: kind === "sink" ? asString(rec.cve_precedent) : null,
      mitigationPresent: kind === "mitigation" ? asBool(rec.present) : null,
      exploitability: kind === "impact" ? asString(rec.exploitability) : null,
    });
  }
  if (links.length === 0) return null;

  const rawFactors = asArray(chain.confidence_factors);
  const confidenceFactors = rawFactors
    .map((f) => asRecord(f))
    .filter((f): f is Record<string, unknown> => f !== null)
    .map((f) => ({
      factor: asString(f.factor) ?? "",
      adjustment: asNumber(f.adjustment) ?? 0,
      rationale: asString(f.rationale) ?? "",
    }));

  const ref = asRecord(chain.threat_reference);
  const threatRef = ref
    ? {
        id: asString(ref.id) ?? "",
        title: asString(ref.title) ?? "",
        url: asString(ref.url) ?? undefined,
      }
    : null;

  const rawSteps = asArray(chain.verification_steps);
  const verificationSteps = rawSteps
    .map((s) => asRecord(s))
    .filter((s): s is Record<string, unknown> => s !== null)
    .map((s, i) => ({
      stepNumber: i + 1,
      instruction: asString(s.instruction) ?? "",
      target: renderLocation(s.target),
      expected: asString(s.expected_observation) ?? "",
    }));

  return {
    links,
    confidence: asNumber(chain.confidence),
    confidenceFactors,
    threatRef,
    verificationSteps,
  };
}

// ── Component ─────────────────────────────────────────────────────────

export interface EvidenceChainFlowProps {
  chain: Record<string, unknown> | null;
  /** Prose fallback used when chain is null/empty. */
  fallbackEvidence: string;
  /** Stable id used to anchor the per-finding permalink (#finding-…). */
  findingId?: string;
}

export default function EvidenceChainFlow({
  chain,
  fallbackEvidence,
  findingId,
}: EvidenceChainFlowProps): React.ReactElement {
  const norm = normalizeChain(chain);

  if (!norm) {
    return (
      <div className="fv-chain fv-chain-empty" id={findingId}>
        <p className="fv-chain-fallback">{fallbackEvidence}</p>
        <p className="fv-chain-fallback-hint">
          Structured evidence chain not on file for this finding.
        </p>
      </div>
    );
  }

  return (
    <div className="fv-chain" id={findingId}>
      {norm.verificationSteps.length > 0 && (
        <ol className="fv-chain-verify" aria-label="Verification steps">
          {norm.verificationSteps.map((s) => (
            <li key={s.stepNumber} className="fv-chain-verify-item">
              <span className="fv-chain-verify-num">{s.stepNumber}</span>
              <span className="fv-chain-verify-body">
                <span className="fv-chain-verify-instr">{s.instruction}</span>
                {s.target && (
                  <code className="fv-chain-verify-target">{s.target}</code>
                )}
                {s.expected && (
                  <span className="fv-chain-verify-expected">
                    Expect: {s.expected}
                  </span>
                )}
              </span>
            </li>
          ))}
        </ol>
      )}

      <div className="fv-chain-rail" role="list">
        {norm.links.map((link, i) => (
          <React.Fragment key={`${link.kind}-${i}`}>
            <article
              className={`fv-chain-node fv-chain-node-${link.kind}`}
              data-kind={link.kind}
              data-mitigation-present={
                link.mitigationPresent === null
                  ? undefined
                  : link.mitigationPresent
                    ? "true"
                    : "false"
              }
              role="listitem"
            >
              <header className="fv-chain-node-head">
                <span className="fv-chain-node-kind">{link.kind}</span>
                <span className="fv-chain-node-label">{link.label}</span>
                {link.kind === "mitigation" && link.mitigationPresent !== null && (
                  <span
                    className={`fv-chain-node-mit ${
                      link.mitigationPresent
                        ? "fv-chain-node-mit-present"
                        : "fv-chain-node-mit-absent"
                    }`}
                  >
                    {link.mitigationPresent ? "present" : "absent"}
                  </span>
                )}
              </header>
              {link.location && (
                <code className="fv-chain-node-loc">{link.location}</code>
              )}
              {link.observed && (
                <pre className="fv-chain-node-observed">{link.observed}</pre>
              )}
              {link.detail && <p className="fv-chain-node-detail">{link.detail}</p>}
              {link.cvePrecedent && (
                <span className="fv-chain-node-cve">{link.cvePrecedent}</span>
              )}
              {link.exploitability && (
                <span className="fv-chain-node-expl">
                  {link.exploitability}
                </span>
              )}
            </article>
            {i < norm.links.length - 1 && (
              <span
                className="fv-chain-arrow"
                aria-hidden="true"
                role="presentation"
              >
                <svg viewBox="0 0 24 24" width="20" height="20" fill="none">
                  <path
                    d="M5 12h14M13 6l6 6-6 6"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </span>
            )}
          </React.Fragment>
        ))}
      </div>

      {(norm.confidence !== null || norm.confidenceFactors.length > 0 || norm.threatRef) && (
        <footer className="fv-chain-foot">
          {norm.confidence !== null && (
            <span className="fv-chain-conf">
              <span className="fv-chain-conf-label">Confidence</span>
              <span className="fv-chain-conf-val">
                {Math.round(norm.confidence * 100)}%
              </span>
            </span>
          )}
          {norm.threatRef && (
            <span className="fv-chain-threat">
              <span className="fv-chain-threat-id">{norm.threatRef.id}</span>
              {norm.threatRef.title && (
                <span className="fv-chain-threat-title">
                  {norm.threatRef.url ? (
                    <a
                      href={norm.threatRef.url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {norm.threatRef.title}
                    </a>
                  ) : (
                    norm.threatRef.title
                  )}
                </span>
              )}
            </span>
          )}
          {norm.confidenceFactors.length > 0 && (
            <details className="fv-chain-factors">
              <summary className="fv-chain-factors-sum">
                {norm.confidenceFactors.length} confidence factor
                {norm.confidenceFactors.length === 1 ? "" : "s"}
              </summary>
              <ul className="fv-chain-factors-list">
                {norm.confidenceFactors.map((f, i) => (
                  <li key={i} className="fv-chain-factor">
                    <span
                      className={`fv-chain-factor-adj ${
                        f.adjustment >= 0
                          ? "fv-chain-factor-pos"
                          : "fv-chain-factor-neg"
                      }`}
                    >
                      {f.adjustment >= 0 ? "+" : ""}
                      {Math.round(f.adjustment * 100) / 100}
                    </span>
                    <span className="fv-chain-factor-body">
                      <span className="fv-chain-factor-name">{f.factor}</span>
                      {f.rationale && (
                        <span className="fv-chain-factor-rat">{f.rationale}</span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </footer>
      )}
    </div>
  );
}
