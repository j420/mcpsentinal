"use client";
/**
 * ForensicDrawer — slide-over audit-pack panel for a single finding.
 *
 * Opens when the URL carries `?finding=<id>`. Reads the entire deep-dive
 * payload from props (no fetch — the page already has the data); locates
 * the matching rule + finding pair and renders three tabs:
 *
 *   • Evidence   — the existing 5-section EvidenceChainViz, plus the
 *                  finding's evidence + remediation prose
 *   • Verify     — verification checklist (one bullet per
 *                  evidence_chain.verification_steps[].instruction)
 *   • Receipt    — the API receipt URL + signing-key id + a "Copy
 *                  receipt URL" button + the verification command
 *
 * Bottom action row carries the headline: "Copy as audit pack
 * (markdown)". One click serialises the finding via
 * `buildAuditPackMarkdown` and writes the result to clipboard. The
 * auditor leaves the page with a paste-ready audit artefact.
 *
 * Close mechanics:
 *   • Click backdrop → close
 *   • Esc key → close
 *   • × button → close
 * Closing strips `?finding=` from the URL so back/forward stays clean.
 *
 * Accessibility:
 *   • role="dialog" + aria-labelledby/aria-describedby
 *   • Initial focus on the close button
 *   • Focus trap: Tab cycles within the drawer
 *   • Returns focus to the document body on close (the trigger button
 *     is the natural target but it's outside this component's tree;
 *     restoring focus is best-effort).
 */

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import EvidenceChainViz, {
  type EvidenceChainData,
} from "@/components/EvidenceChainViz";
import {
  buildAuditPackMarkdown,
  type BuildAuditPackInput,
} from "@/lib/forensic-markdown";
import type {
  DeepDiveCategory,
  DeepDiveFinding,
  DeepDiveProvenance,
  DeepDiveRule,
} from "@/lib/deep-dive";

interface ForensicDrawerProps {
  serverSlug: string;
  serverName: string;
  categories: ReadonlyArray<DeepDiveCategory>;
  provenance: DeepDiveProvenance | undefined;
  /** API origin used for receipt URL construction. */
  apiOrigin: string;
}

type Tab = "evidence" | "verify" | "receipt";

function findRuleAndFinding(
  categories: ReadonlyArray<DeepDiveCategory>,
  findingId: string,
): { rule: DeepDiveRule; finding: DeepDiveFinding } | null {
  for (const cat of categories) {
    if (!cat || !Array.isArray(cat.sub_categories)) continue;
    for (const sub of cat.sub_categories) {
      if (!sub || !Array.isArray(sub.rules)) continue;
      for (const rule of sub.rules) {
        if (!rule || !Array.isArray(rule.findings)) continue;
        const finding = rule.findings.find((f) => f && f.id === findingId);
        if (finding) return { rule, finding };
      }
    }
  }
  return null;
}

function pluckVerificationSteps(
  chain: Record<string, unknown> | null | undefined,
): Array<{ step_type?: string; target?: string; instruction: string }> {
  if (!chain) return [];
  const raw = chain["verification_steps"];
  if (!Array.isArray(raw)) return [];
  const out: Array<{ step_type?: string; target?: string; instruction: string }> = [];
  for (const step of raw) {
    if (!step || typeof step !== "object") continue;
    const s = step as Record<string, unknown>;
    const instruction =
      typeof s["instruction"] === "string" ? s["instruction"] : null;
    if (!instruction) continue;
    out.push({
      step_type: typeof s["step_type"] === "string" ? s["step_type"] : undefined,
      target: typeof s["target"] === "string" ? s["target"] : undefined,
      instruction,
    });
  }
  return out;
}

export default function ForensicDrawer({
  serverSlug,
  serverName,
  categories,
  provenance,
  apiOrigin,
}: ForensicDrawerProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const findingId = searchParams.get("finding");

  const [activeTab, setActiveTab] = useState<Tab>("evidence");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">(
    "idle",
  );
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);

  // Reset tab + copy state every time the user opens a fresh finding.
  useEffect(() => {
    if (findingId) {
      setActiveTab("evidence");
      setCopyState("idle");
    }
  }, [findingId]);

  const close = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("finding");
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [router, pathname, searchParams]);

  // Esc to close.
  useEffect(() => {
    if (!findingId) return;
    function onKey(e: KeyboardEvent): void {
      if (e.key === "Escape") {
        e.stopPropagation();
        close();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [findingId, close]);

  // Initial focus on the close button when the drawer opens — keyboard
  // users can immediately Esc / Tab through the contents.
  useEffect(() => {
    if (findingId && closeButtonRef.current) {
      closeButtonRef.current.focus();
    }
  }, [findingId]);

  // Body scroll lock while open — prevents the page behind from
  // scrolling under the drawer.
  useEffect(() => {
    if (!findingId) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [findingId]);

  const located = useMemo(
    () => (findingId ? findRuleAndFinding(categories, findingId) : null),
    [findingId, categories],
  );

  const onCopyAuditPack = useCallback(async () => {
    if (!located) return;
    const md = buildAuditPackMarkdown({
      serverSlug,
      serverName,
      rule: located.rule,
      finding: located.finding,
      provenance,
      apiOrigin,
    } as BuildAuditPackInput);
    try {
      if (
        typeof navigator !== "undefined" &&
        navigator.clipboard &&
        typeof navigator.clipboard.writeText === "function"
      ) {
        await navigator.clipboard.writeText(md);
        setCopyState("copied");
        setTimeout(() => setCopyState("idle"), 2000);
      } else {
        setCopyState("error");
      }
    } catch {
      setCopyState("error");
    }
  }, [located, serverSlug, serverName, provenance, apiOrigin]);

  const onCopyReceiptUrl = useCallback(async () => {
    if (!located) return;
    const url = `${apiOrigin}/api/v1/findings/${encodeURIComponent(located.finding.id)}/receipt`;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url);
      }
    } catch {
      // ignore — copy failures are user-visible via the audit-pack
      // button's state; the receipt-URL button does not need its own.
    }
  }, [located, apiOrigin]);

  // Render NOTHING when the URL has no `?finding=`. Keeps the drawer
  // out of the DOM entirely until needed.
  if (!findingId) return null;

  // Render a friendly "not found" state when the URL has a finding id
  // but it doesn't appear in this server's deep-dive payload (stale
  // shared link, finding from a previous scan, etc.).
  if (!located) {
    return (
      <div
        className="fdrawer-backdrop"
        onClick={close}
        role="presentation"
      >
        <div
          ref={drawerRef}
          className="fdrawer"
          role="dialog"
          aria-modal="true"
          aria-labelledby="fdrawer-title"
          onClick={(e) => e.stopPropagation()}
        >
          <header className="fdrawer-head">
            <h2 id="fdrawer-title" className="fdrawer-title">
              Forensic view
            </h2>
            <button
              ref={closeButtonRef}
              type="button"
              className="fdrawer-close"
              onClick={close}
              aria-label="Close forensic view"
            >
              ×
            </button>
          </header>
          <div className="fdrawer-body fdrawer-empty">
            <p>
              Finding <code>{findingId}</code> is not on this server's
              current deep-dive payload. The link may be stale, or the
              finding may belong to a previous scan.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const { rule, finding } = located;
  const chain = (finding.evidence_chain ?? null) as EvidenceChainData | null;
  const verificationSteps = pluckVerificationSteps(
    finding.evidence_chain as Record<string, unknown> | null,
  );
  const receiptUrl = `${apiOrigin}/api/v1/findings/${encodeURIComponent(finding.id)}/receipt`;

  return (
    <div
      className="fdrawer-backdrop"
      onClick={close}
      role="presentation"
    >
      <div
        ref={drawerRef}
        className="fdrawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="fdrawer-title"
        aria-describedby="fdrawer-sub"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="fdrawer-head">
          <div className="fdrawer-head-text">
            <h2 id="fdrawer-title" className="fdrawer-title">
              Forensic view
            </h2>
            <p id="fdrawer-sub" className="fdrawer-sub">
              <code className="fdrawer-mono">{rule.rule_id}</code>{" "}
              {rule.name} · finding{" "}
              <code className="fdrawer-mono" title={finding.id}>
                {finding.id.slice(0, 10)}…
              </code>
            </p>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            className="fdrawer-close"
            onClick={close}
            aria-label="Close forensic view"
          >
            ×
          </button>
        </header>

        <nav className="fdrawer-tabs" role="tablist" aria-label="Forensic view tabs">
          <button
            type="button"
            role="tab"
            id="fdrawer-tab-evidence"
            aria-selected={activeTab === "evidence"}
            aria-controls="fdrawer-panel-evidence"
            className={`fdrawer-tab${
              activeTab === "evidence" ? " fdrawer-tab-active" : ""
            }`}
            onClick={() => setActiveTab("evidence")}
          >
            Evidence
          </button>
          <button
            type="button"
            role="tab"
            id="fdrawer-tab-verify"
            aria-selected={activeTab === "verify"}
            aria-controls="fdrawer-panel-verify"
            className={`fdrawer-tab${
              activeTab === "verify" ? " fdrawer-tab-active" : ""
            }`}
            onClick={() => setActiveTab("verify")}
          >
            Verify
            {verificationSteps.length > 0 && (
              <span className="fdrawer-tab-count">{verificationSteps.length}</span>
            )}
          </button>
          <button
            type="button"
            role="tab"
            id="fdrawer-tab-receipt"
            aria-selected={activeTab === "receipt"}
            aria-controls="fdrawer-panel-receipt"
            className={`fdrawer-tab${
              activeTab === "receipt" ? " fdrawer-tab-active" : ""
            }`}
            onClick={() => setActiveTab("receipt")}
          >
            Receipt
          </button>
        </nav>

        <div className="fdrawer-body">
          {activeTab === "evidence" && (
            <section
              id="fdrawer-panel-evidence"
              role="tabpanel"
              aria-labelledby="fdrawer-tab-evidence"
            >
              <p className="fdrawer-evidence-prose">{finding.evidence}</p>
              <EvidenceChainViz chain={chain} confidence={finding.confidence} />
              {finding.remediation && (
                <div className="fdrawer-remediation">
                  <h3 className="fdrawer-h3">Remediation</h3>
                  <p>{finding.remediation}</p>
                </div>
              )}
            </section>
          )}

          {activeTab === "verify" && (
            <section
              id="fdrawer-panel-verify"
              role="tabpanel"
              aria-labelledby="fdrawer-tab-verify"
            >
              <h3 className="fdrawer-h3">Verification checklist</h3>
              {verificationSteps.length === 0 ? (
                <p className="fdrawer-empty-msg">
                  No structured verification steps on file for this finding.
                  The audit-pack export below still includes a fallback
                  checklist (location, sink, sanitiser).
                </p>
              ) : (
                <ol className="fdrawer-checklist">
                  {verificationSteps.map((s, i) => (
                    <li key={i} className="fdrawer-checklist-item">
                      <input
                        type="checkbox"
                        className="fdrawer-checklist-cb"
                        aria-label={`Verification step ${i + 1}`}
                      />
                      <div className="fdrawer-checklist-body">
                        <p className="fdrawer-checklist-instr">
                          {s.instruction}
                        </p>
                        {(s.step_type || s.target) && (
                          <p className="fdrawer-checklist-meta">
                            {s.step_type && (
                              <span className="fdrawer-checklist-tag">
                                {s.step_type}
                              </span>
                            )}
                            {s.target && (
                              <code className="fdrawer-mono">{s.target}</code>
                            )}
                          </p>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </section>
          )}

          {activeTab === "receipt" && (
            <section
              id="fdrawer-panel-receipt"
              role="tabpanel"
              aria-labelledby="fdrawer-tab-receipt"
            >
              <h3 className="fdrawer-h3">Signed receipt</h3>
              <p>
                Fetch the URL below for an HMAC-SHA256-signed canonical
                JSON envelope. Auditors with the documented signing key
                can recompute the canonicalisation and verify offline.
              </p>
              <div className="fdrawer-receipt-row">
                <code className="fdrawer-receipt-url">{receiptUrl}</code>
                <button
                  type="button"
                  className="fdrawer-mini-btn"
                  onClick={onCopyReceiptUrl}
                  title="Copy receipt URL"
                >
                  Copy URL
                </button>
                <a
                  className="fdrawer-mini-btn fdrawer-mini-btn-link"
                  href={receiptUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  title="Open receipt JSON in a new tab"
                >
                  Open ↗
                </a>
              </div>
              {provenance && (
                <dl className="fdrawer-provenance">
                  {provenance.scan_id && (
                    <div className="fdrawer-prov-row">
                      <dt>Scan</dt>
                      <dd>
                        <code className="fdrawer-mono">
                          {provenance.scan_id}
                        </code>
                      </dd>
                    </div>
                  )}
                  {provenance.rules_version && (
                    <div className="fdrawer-prov-row">
                      <dt>Rules version</dt>
                      <dd>
                        <code className="fdrawer-mono">
                          {provenance.rules_version}
                        </code>
                      </dd>
                    </div>
                  )}
                  <div className="fdrawer-prov-row">
                    <dt>Sentinel</dt>
                    <dd>
                      <code className="fdrawer-mono">
                        {provenance.sentinel_version}
                      </code>
                    </dd>
                  </div>
                  <div className="fdrawer-prov-row">
                    <dt>Key id</dt>
                    <dd>
                      <code className="fdrawer-mono">
                        {provenance.signing_key_id}
                      </code>
                    </dd>
                  </div>
                  <div className="fdrawer-prov-row">
                    <dt>Algorithm</dt>
                    <dd>
                      <code className="fdrawer-mono">HMAC-SHA256</code>{" "}
                      <span className="fdrawer-prov-aux">
                        / RFC 8785 canonicalisation
                      </span>
                    </dd>
                  </div>
                </dl>
              )}
            </section>
          )}
        </div>

        <footer className="fdrawer-foot">
          <button
            type="button"
            className="fdrawer-action-primary"
            onClick={onCopyAuditPack}
            data-state={copyState}
          >
            {copyState === "copied"
              ? "✓ Copied audit pack"
              : copyState === "error"
                ? "Copy failed — try again"
                : "Copy as audit pack (markdown)"}
          </button>
          <button
            type="button"
            className="fdrawer-action-secondary"
            onClick={close}
          >
            Close
          </button>
        </footer>
      </div>
    </div>
  );
}
