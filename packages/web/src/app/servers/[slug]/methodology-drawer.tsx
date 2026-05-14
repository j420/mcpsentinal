/**
 * MethodologyDrawer — collapsed-by-default footer on each rule card.
 *
 * Demoted by design: the evidence chain is the hero, the methodology is
 * the receipt you pull out when someone challenges the finding. Native
 * `<details>` so it works server-rendered without React state.
 *
 * Rows: Technique · Confidence cap · Tests · Lethal edge cases ·
 * Frameworks · Backing (precision/recall/CVE replays · last validated).
 *
 * Empty states render an honest sentinel rather than an empty cell, so
 * the user can see whether we have data on file vs. don't.
 */

import React from "react";
import type {
  DeepDiveMethodology,
  DeepDiveFrameworkControl,
  DetectionQuality,
  DeepDiveCveValidation,
} from "@/lib/deep-dive";
import {
  FRAMEWORK_SHORT_LABELS,
  type FrameworkId,
} from "@/lib/framework-labels";

export interface MethodologyDrawerProps {
  methodology: DeepDiveMethodology;
  frameworks: DeepDiveFrameworkControl[];
  backing: DetectionQuality | null;
  cveValidations: DeepDiveCveValidation[];
}

function shortLabel(id: string): string {
  return (
    FRAMEWORK_SHORT_LABELS[id as FrameworkId] ??
    id.replace(/_/g, " ").toUpperCase()
  );
}

function dateLabel(iso: string | null): string {
  if (!iso) return "—";
  // Render the date portion only; full ISO is in the title for ops.
  return iso.slice(0, 10);
}

export default function MethodologyDrawer({
  methodology,
  frameworks,
  backing,
  cveValidations,
}: MethodologyDrawerProps): React.ReactElement {
  const m = methodology ?? {
    technique: "",
    verified_edge_cases: [],
    edge_case_strategies: [],
    confidence_cap: null,
  };
  const verified = Array.isArray(m.verified_edge_cases)
    ? m.verified_edge_cases
    : [];
  const hasCap = m.confidence_cap !== null && m.confidence_cap !== undefined;
  const unspecified =
    verified.length === 0 &&
    frameworks.length === 0 &&
    !backing &&
    cveValidations.length === 0 &&
    !hasCap;

  return (
    <details className="fv-method">
      <summary className="fv-method-sum">
        <span className="fv-method-sum-icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none">
            <path
              d="M4 6l4 4 4-4"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
        <span className="fv-method-sum-label">More — frameworks, edge cases, backing</span>
        <span className="fv-method-sum-meta">
          {verified.length > 0 && `${verified.length} edge case${verified.length === 1 ? "" : "s"}`}
          {frameworks.length > 0 && `${verified.length > 0 ? " · " : ""}${frameworks.length} framework${frameworks.length === 1 ? "" : "s"}`}
          {cveValidations.length > 0 && ` · ${cveValidations.length} CVE replay${cveValidations.length === 1 ? "" : "s"}`}
        </span>
      </summary>

      <div className="fv-method-body">
        {unspecified ? (
          <p className="fv-method-unspec">
            No secondary metadata on file — see the rule&apos;s CHARTER.md in
            source for the authoritative description.
          </p>
        ) : (
          <dl className="fv-method-grid">
            <dt>
              Lethal edge cases{" "}
              <span className="fv-method-count">({verified.length})</span>
            </dt>
            <dd>
              {verified.length === 0 ? (
                <span className="fv-method-empty">none recorded</span>
              ) : (
                <ul className="fv-method-edges">
                  {verified.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              )}
            </dd>

            <dt>Confidence cap</dt>
            <dd>
              {m.confidence_cap === null || m.confidence_cap === undefined ? (
                <span className="fv-method-empty">unbounded</span>
              ) : (
                <span className="fv-method-cap">
                  ≤ {Math.round(m.confidence_cap * 100)}%
                </span>
              )}
            </dd>

            <dt>
              Frameworks{" "}
              <span className="fv-method-count">({frameworks.length})</span>
            </dt>
            <dd>
              {frameworks.length === 0 ? (
                <span className="fv-method-empty">no cross-walk on file</span>
              ) : (
                <ul className="fv-method-fws">
                  {frameworks.map((f) => (
                    <li
                      key={`${f.framework_id}-${f.control_id}`}
                      className="fv-method-fw"
                    >
                      <span className="fv-method-fw-id">
                        {shortLabel(f.framework_id)}
                      </span>
                      <code className="fv-method-fw-ctrl">{f.control_id}</code>
                      <span className="fv-method-fw-title">
                        {f.control_title}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </dd>

            <dt>Backing</dt>
            <dd>
              {!backing ? (
                <span className="fv-method-empty">
                  not yet wired into validation harnesses
                </span>
              ) : (
                <ul className="fv-method-backing">
                  <li>
                    Precision:{" "}
                    {backing.precision === null ? (
                      <span className="fv-method-empty">—</span>
                    ) : (
                      <strong>{Math.round(backing.precision * 100)}%</strong>
                    )}
                  </li>
                  <li>
                    Recall:{" "}
                    {backing.recall === null ? (
                      <span className="fv-method-empty">—</span>
                    ) : (
                      <strong>{Math.round(backing.recall * 100)}%</strong>
                    )}
                  </li>
                  <li>
                    Red-team fixtures:{" "}
                    <strong>{backing.fixture_count}</strong>
                  </li>
                  <li>
                    CVE replays:{" "}
                    {backing.cve_replay_ids.length === 0 ? (
                      <span className="fv-method-empty">none</span>
                    ) : (
                      <strong>
                        {backing.cve_replay_ids.join(", ")}
                      </strong>
                    )}
                  </li>
                  <li
                    title={backing.last_validated_at ?? undefined}
                    className="fv-method-back-date"
                  >
                    Last validated: <strong>{dateLabel(backing.last_validated_at)}</strong>
                  </li>
                </ul>
              )}
            </dd>

            {cveValidations.length > 0 && (
              <>
                <dt>CVE replay corpus</dt>
                <dd>
                  <ul className="fv-method-cves">
                    {cveValidations.map((c) => (
                      <li key={c.id} className="fv-method-cve">
                        <a
                          href={c.source_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="fv-method-cve-id"
                        >
                          {c.id}
                        </a>
                        <span className="fv-method-cve-title">{c.title}</span>
                        {c.cvss_v3 !== null && (
                          <span className="fv-method-cve-cvss">
                            CVSS {c.cvss_v3}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
          </dl>
        )}
      </div>
    </details>
  );
}
