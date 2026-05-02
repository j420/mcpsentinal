"use client";
/**
 * ProvenanceFooter — every claim on the page traces back to here.
 *
 * Renders the (scan_id, scan_completed_at, rules_version, sentinel_version,
 * signing_key_id) triple as a single audit-grade footer line. Auditors use
 * the values to recompute things offline:
 *   - the rules_version pins the rule set used for analysis
 *   - the scan_id ties findings to a specific persisted scan row
 *   - the signing_key_id identifies the HMAC secret used to sign per-
 *     finding receipts (`/api/v1/findings/:id/receipt`)
 *
 * Renders the field as "honest gap" copy when a value is missing — never
 * synthesises a placeholder. Server component, no hooks.
 *
 * Visual: monospace, low contrast, fixed width — looks like a print
 * footer at the bottom of a regulator-grade document.
 */

import React from "react";
import type { DeepDiveProvenance } from "@/lib/deep-dive";

interface ProvenanceFooterProps {
  provenance: DeepDiveProvenance | undefined;
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toISOString().replace(".000Z", "Z");
}

function shortId(uuid: string | null | undefined): string {
  if (!uuid) return "—";
  // Show first 8 chars to keep the footer compact; full id is in the
  // title attribute for hover.
  return uuid.slice(0, 8);
}

export default function ProvenanceFooter({ provenance }: ProvenanceFooterProps) {
  if (!provenance) return null;
  const {
    scan_id,
    scan_completed_at,
    rules_version,
    sentinel_version,
    signing_key_id,
  } = provenance;

  return (
    <footer className="prov-footer" aria-labelledby="prov-footer-title">
      <h2 id="prov-footer-title" className="prov-footer-title">
        Provenance &amp; attestation
      </h2>
      <dl className="prov-footer-dl">
        <div className="prov-footer-row">
          <dt className="prov-footer-k">Scan</dt>
          <dd className="prov-footer-v" title={scan_id ?? "no scan on file"}>
            <code className="prov-mono">{shortId(scan_id)}</code>
            {scan_completed_at && (
              <span className="prov-footer-when">
                {" · completed "}
                {fmtDate(scan_completed_at)}
              </span>
            )}
            {!scan_id && (
              <span className="prov-footer-gap">no completed scan on file</span>
            )}
          </dd>
        </div>
        <div className="prov-footer-row">
          <dt className="prov-footer-k">Rules version</dt>
          <dd className="prov-footer-v">
            <code className="prov-mono">{rules_version ?? "—"}</code>
          </dd>
        </div>
        <div className="prov-footer-row">
          <dt className="prov-footer-k">Sentinel</dt>
          <dd className="prov-footer-v">
            <code className="prov-mono">{sentinel_version}</code>
          </dd>
        </div>
        <div className="prov-footer-row">
          <dt className="prov-footer-k">Attestation</dt>
          <dd className="prov-footer-v">
            <code className="prov-mono">HMAC-SHA256</code>
            <span className="prov-footer-when">
              {" · key id "}
              <code className="prov-mono">{signing_key_id}</code>
            </span>
            <span className="prov-footer-when">{" · RFC 8785"}</span>
          </dd>
        </div>
      </dl>
      <p className="prov-footer-note">
        Each finding can be independently verified: fetch{" "}
        <code className="prov-mono">/api/v1/findings/&lt;id&gt;/receipt</code>{" "}
        for an HMAC-SHA256-signed canonical JSON envelope. The signing key
        id above identifies the secret used; auditors with the secret can
        recompute the canonicalisation and verify offline.
      </p>
    </footer>
  );
}
