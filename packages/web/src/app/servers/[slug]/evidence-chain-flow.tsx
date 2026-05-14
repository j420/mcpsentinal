/**
 * EvidenceChainFlow — the page's hero. Vertical forensic cascade.
 *
 * Each link in the chain renders as a full-width block with EVERY
 * field surfaced and labeled: a numbered step badge, the kind label
 * (SOURCE / PROPAGATION / SINK / MITIGATION / IMPACT), the sub-type
 * pill, and a definition-list of every backing field (where, what was
 * observed, rationale / detail / scenario, CVE precedent, mitigation
 * present/absent, scope, exploitability).
 *
 * Between links: a tall down-chevron arrow so the eye tracks the chain
 * as a flow.
 *
 * Confidence factors render inline below the chain — not hidden — so a
 * reviewer sees exactly how the confidence number was assembled. Threat
 * reference and verification steps render as their own labeled cards.
 *
 * Input is the wire-typed `evidence_chain: Record<string, unknown> | null`.
 * Every link narrows defensively before rendering. A null / malformed
 * chain falls back to the prose `evidence` string so the rule card
 * still has a body.
 */

import React from "react";

// ── Local narrowing — duplicates analyzer's evidence.ts shapes ────────

type LinkKind = "source" | "propagation" | "sink" | "mitigation" | "impact";

interface NormalizedLink {
  kind: LinkKind;
  subtype: string;
  location: string;
  observed: string;
  /** Source: rationale; Mitigation: detail; Impact: scenario. */
  narrative: string | null;
  cvePrecedent: string | null;
  mitigationPresent: boolean | null;
  /** Impact only. */
  impactScope: string | null;
  impactExploitability: string | null;
}

interface NormalizedConfidenceFactor {
  factor: string;
  adjustment: number;
  rationale: string;
}

interface NormalizedThreatRef {
  id: string;
  title: string;
  url?: string;
  year: number | null;
  relevance: string;
}

interface NormalizedVerification {
  stepNumber: number;
  stepType: string;
  instruction: string;
  target: string;
  expected: string;
}

interface NormalizedChain {
  links: NormalizedLink[];
  confidence: number | null;
  factors: NormalizedConfidenceFactor[];
  threatRef: NormalizedThreatRef | null;
  verificationSteps: NormalizedVerification[];
}

// ── Coercion helpers ─────────────────────────────────────────────────

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
      return `tool ${asString(r.tool_name) ?? ""} · parameter ${asString(r.parameter_path) ?? ""}`;
    case "schema":
      return `tool ${asString(r.tool_name) ?? ""} · schema ${asString(r.json_pointer) ?? ""}`;
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

function subtypeOf(kind: LinkKind, raw: Record<string, unknown>): string {
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

function narrativeOf(kind: LinkKind, raw: Record<string, unknown>): string | null {
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
    links.push({
      kind,
      subtype: subtypeOf(kind, rec),
      location: renderLocation(rec.location),
      observed: asString(rec.observed) ?? "",
      narrative: narrativeOf(kind, rec),
      cvePrecedent: kind === "sink" ? asString(rec.cve_precedent) : null,
      mitigationPresent: kind === "mitigation" ? asBool(rec.present) : null,
      impactScope: kind === "impact" ? asString(rec.scope) : null,
      impactExploitability: kind === "impact" ? asString(rec.exploitability) : null,
    });
  }
  if (links.length === 0) return null;

  const factors: NormalizedConfidenceFactor[] = asArray(chain.confidence_factors)
    .map((f) => asRecord(f))
    .filter((f): f is Record<string, unknown> => f !== null)
    .map((f) => ({
      factor: asString(f.factor) ?? "",
      adjustment: asNumber(f.adjustment) ?? 0,
      rationale: asString(f.rationale) ?? "",
    }));

  const refRec = asRecord(chain.threat_reference);
  const threatRef: NormalizedThreatRef | null = refRec
    ? {
        id: asString(refRec.id) ?? "",
        title: asString(refRec.title) ?? "",
        url: asString(refRec.url) ?? undefined,
        year: asNumber(refRec.year),
        relevance: asString(refRec.relevance) ?? "",
      }
    : null;

  const verificationSteps: NormalizedVerification[] = asArray(chain.verification_steps)
    .map((s) => asRecord(s))
    .filter((s): s is Record<string, unknown> => s !== null)
    .map((s, i) => ({
      stepNumber: i + 1,
      stepType: asString(s.step_type) ?? "",
      instruction: asString(s.instruction) ?? "",
      target: renderLocation(s.target),
      expected: asString(s.expected_observation) ?? "",
    }));

  return {
    links,
    confidence: asNumber(chain.confidence),
    factors,
    threatRef,
    verificationSteps,
  };
}

// ── Field-label vocab ─────────────────────────────────────────────────
// Each link kind has a different set of meaningful fields. The labels
// here are intentionally plain-English so a non-engineer reads the chain
// as a forensic narrative, not a dump.

const KIND_LABEL: Record<LinkKind, string> = {
  source: "Source",
  propagation: "Propagation",
  sink: "Sink",
  mitigation: "Mitigation",
  impact: "Impact",
};

function ordinal(n: number): string {
  // Circled digits 1..10; fall back to plain "N." for n > 10.
  const circled = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩"];
  return n >= 1 && n <= 10 ? circled[n - 1] : `${n}.`;
}

// Humanise kebab/snake-case sub-types into title case for the pill copy.
function humanizeSubtype(s: string): string {
  if (!s) return "";
  return s
    .replace(/[-_]+/g, " ")
    .replace(/\b([a-z])/g, (_, c) => c.toUpperCase());
}

// ── Component ────────────────────────────────────────────────────────

export interface EvidenceChainFlowProps {
  chain: Record<string, unknown> | null;
  fallbackEvidence: string;
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
      <div className="fv-ev" id={findingId}>
        <div className="fv-ev-fallback">
          <p className="fv-ev-fallback-eyebrow">Evidence (prose only)</p>
          <p className="fv-ev-fallback-body">{fallbackEvidence}</p>
          <p className="fv-ev-fallback-hint">
            Structured evidence chain not on file for this finding — the
            detector emitted only narrative text.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="fv-ev" id={findingId}>
      {/* ── Chain narrative ────────────────────────────────────────── */}
      <div className="fv-ev-narrative">
        <p className="fv-ev-narrative-eyebrow">Proof chain</p>
        <p className="fv-ev-narrative-body">
          {norm.links.length} step{norm.links.length === 1 ? "" : "s"} from
          untrusted source to potential impact. Each step is independently
          verifiable against the cited location.
        </p>
      </div>

      {/* ── Chain links ────────────────────────────────────────────── */}
      <ol className="fv-ev-chain" aria-label="Evidence chain">
        {norm.links.map((link, i) => (
          <React.Fragment key={`${link.kind}-${i}`}>
            <li
              className={`fv-ev-link fv-ev-link-${link.kind}`}
              data-kind={link.kind}
              data-mitigation-present={
                link.mitigationPresent === null
                  ? undefined
                  : link.mitigationPresent
                    ? "true"
                    : "false"
              }
            >
              <header className="fv-ev-link-head">
                <span className="fv-ev-link-num" aria-hidden="true">
                  {ordinal(i + 1)}
                </span>
                <span className="fv-ev-link-kind">{KIND_LABEL[link.kind]}</span>
                <span className="fv-ev-link-sub">{humanizeSubtype(link.subtype)}</span>
                {link.kind === "mitigation" && link.mitigationPresent !== null && (
                  <span
                    className={
                      link.mitigationPresent
                        ? "fv-ev-mit-badge fv-ev-mit-present"
                        : "fv-ev-mit-badge fv-ev-mit-absent"
                    }
                    role="status"
                  >
                    <span className="fv-ev-mit-icon" aria-hidden="true">
                      {link.mitigationPresent ? "✓" : "✕"}
                    </span>
                    <span className="fv-ev-mit-text">
                      {link.mitigationPresent ? "Present" : "Absent"}
                    </span>
                  </span>
                )}
              </header>

              <dl className="fv-ev-link-fields">
                {link.location && (
                  <>
                    <dt>{link.kind === "impact" ? "Affected" : link.kind === "propagation" ? "At" : "Where"}</dt>
                    <dd>
                      <code className="fv-ev-loc">{link.location}</code>
                    </dd>
                  </>
                )}

                {link.kind === "impact" && link.impactScope && (
                  <>
                    <dt>Scope</dt>
                    <dd className="fv-ev-fld-scope">{link.impactScope}</dd>
                  </>
                )}

                {link.kind === "impact" && link.impactExploitability && (
                  <>
                    <dt>Exploitability</dt>
                    <dd>
                      <span
                        className={`fv-ev-expl fv-ev-expl-${link.impactExploitability}`}
                      >
                        {humanizeSubtype(link.impactExploitability)}
                      </span>
                    </dd>
                  </>
                )}

                {link.observed && link.kind !== "impact" && (
                  <>
                    <dt>{link.kind === "mitigation" ? "Pattern" : "Observed"}</dt>
                    <dd>
                      <pre className="fv-ev-observed">{link.observed}</pre>
                    </dd>
                  </>
                )}

                {link.narrative && (
                  <>
                    <dt>
                      {link.kind === "source"
                        ? "Why untrusted"
                        : link.kind === "mitigation"
                          ? "Detail"
                          : "Scenario"}
                    </dt>
                    <dd className="fv-ev-narrative-cell">{link.narrative}</dd>
                  </>
                )}

                {link.cvePrecedent && (
                  <>
                    <dt>CVE precedent</dt>
                    <dd>
                      <code className="fv-ev-cve">{link.cvePrecedent}</code>
                    </dd>
                  </>
                )}
              </dl>
            </li>

            {i < norm.links.length - 1 && (
              <li
                className="fv-ev-arrow"
                aria-hidden="true"
                role="presentation"
              >
                <svg viewBox="0 0 24 32" width="24" height="32" fill="none">
                  <path
                    d="M12 2v22"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeDasharray="2 4"
                  />
                  <path
                    d="M6 22l6 6 6-6"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </li>
            )}
          </React.Fragment>
        ))}
      </ol>

      {/* ── Confidence breakdown (inline, NOT hidden) ──────────────── */}
      {(norm.confidence !== null || norm.factors.length > 0) && (
        <section className="fv-ev-conf" aria-labelledby={`${findingId}-conf-h`}>
          <header className="fv-ev-sub-head">
            <span className="fv-ev-sub-eyebrow" id={`${findingId}-conf-h`}>
              Confidence
            </span>
            {norm.confidence !== null && (
              <span className="fv-ev-conf-pct">
                {Math.round(norm.confidence * 100)}%
              </span>
            )}
          </header>
          {norm.factors.length > 0 ? (
            <ul className="fv-ev-conf-factors">
              {norm.factors.map((f, i) => (
                <li key={i} className="fv-ev-conf-factor">
                  <span
                    className={
                      f.adjustment >= 0
                        ? "fv-ev-conf-adj fv-ev-conf-adj-pos"
                        : "fv-ev-conf-adj fv-ev-conf-adj-neg"
                    }
                  >
                    {f.adjustment >= 0 ? "+" : ""}
                    {Math.round(f.adjustment * 100) / 100}
                  </span>
                  <div className="fv-ev-conf-text">
                    <span className="fv-ev-conf-name">{f.factor}</span>
                    {f.rationale && (
                      <span className="fv-ev-conf-rat">{f.rationale}</span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="fv-ev-conf-empty">
              No factor breakdown on file — the detector emitted a single
              confidence value without per-factor adjustments.
            </p>
          )}
        </section>
      )}

      {/* ── Threat reference (real-world precedent) ─────────────────── */}
      {norm.threatRef && (
        <section className="fv-ev-threat">
          <header className="fv-ev-sub-head">
            <span className="fv-ev-sub-eyebrow">Real-world precedent</span>
          </header>
          <div className="fv-ev-threat-body">
            <div className="fv-ev-threat-id-row">
              <code className="fv-ev-threat-id">{norm.threatRef.id}</code>
              {norm.threatRef.year !== null && (
                <span className="fv-ev-threat-year">{norm.threatRef.year}</span>
              )}
            </div>
            <p className="fv-ev-threat-title">
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
            </p>
            {norm.threatRef.relevance && (
              <p className="fv-ev-threat-rel">{norm.threatRef.relevance}</p>
            )}
          </div>
        </section>
      )}

      {/* ── Verification steps (how to reproduce / audit) ───────────── */}
      {norm.verificationSteps.length > 0 && (
        <section className="fv-ev-verify">
          <header className="fv-ev-sub-head">
            <span className="fv-ev-sub-eyebrow">
              How to verify this finding
            </span>
            <span className="fv-ev-sub-count">
              {norm.verificationSteps.length} step
              {norm.verificationSteps.length === 1 ? "" : "s"}
            </span>
          </header>
          <ol className="fv-ev-verify-list">
            {norm.verificationSteps.map((s) => (
              <li key={s.stepNumber} className="fv-ev-verify-item">
                <span className="fv-ev-verify-num">{s.stepNumber}</span>
                <div className="fv-ev-verify-body">
                  {s.stepType && (
                    <code className="fv-ev-verify-type">{s.stepType}</code>
                  )}
                  <p className="fv-ev-verify-instr">{s.instruction}</p>
                  {s.target && (
                    <p className="fv-ev-verify-target">
                      <span className="fv-ev-verify-key">Target:</span>{" "}
                      <code>{s.target}</code>
                    </p>
                  )}
                  {s.expected && (
                    <p className="fv-ev-verify-expected">
                      <span className="fv-ev-verify-key">Expect:</span>{" "}
                      {s.expected}
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  );
}
