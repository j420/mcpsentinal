/**
 * SignedEvidencePack — top-of-page CTA promoting the signed compliance reports.
 *
 * The 7 framework × 3 format download endpoints already ship from
 * packages/api/src/compliance-report-routes.ts and are listed inside
 * <FooterAttestationBar>'s collapsed details menu. This component promotes
 * them to first-screen with the actual HMAC-SHA256 / RFC 8785 attestation
 * chips visible — turning the registry from a listing card into an
 * auditor-ready dossier in one click.
 *
 * The single fetch reads attestation headers from the EU AI Act JSON
 * endpoint. EU AI Act is the canonical pick — it drives the August 2026
 * commercial deadline. The body is dropped; only headers feed the chips.
 *
 * Headers come from packages/api/src/compliance-report-routes.ts ::
 * writeAttestationHeaders(). Header keys are case-insensitive in fetch().
 *
 * Resilience: if the attestation fetch fails, chips show "—" but every
 * download link still works — the user can always pull the report and
 * read its embedded signature directly.
 */

import React from "react";

const FRAMEWORKS: ReadonlyArray<{ id: string; label: string; sub: string }> = [
  { id: "eu_ai_act",   label: "EU AI Act",        sub: "Reg (EU) 2024/1689 · Art. 9, 12, 13, 14, 15" },
  { id: "iso_27001",   label: "ISO 27001:2022",   sub: "Annex A controls · A.5 / A.8 series" },
  { id: "owasp_mcp",   label: "OWASP MCP Top 10", sub: "MCP01 — MCP10" },
  { id: "owasp_asi",   label: "OWASP Agentic",    sub: "ASI01 — ASI09 (ASI10 honest gap)" },
  { id: "cosai_mcp",   label: "CoSAI MCP",        sub: "Threat taxonomy T1 — T12" },
  { id: "maestro",     label: "MAESTRO",          sub: "Layers L1 — L7" },
  { id: "mitre_atlas", label: "MITRE ATLAS",      sub: "Agent technique cross-walk" },
];

interface AttestationChips {
  signature: string | null;
  key_id: string | null;
  signed_at: string | null;
  algorithm: string | null;
  canonicalization: string | null;
  dev_key_warning: boolean;
}

async function getAttestation(
  slug: string,
  apiUrl: string,
): Promise<AttestationChips | null> {
  try {
    const res = await fetch(
      `${apiUrl}/api/v1/servers/${encodeURIComponent(slug)}/compliance/eu_ai_act.json`,
      {
        signal: AbortSignal.timeout(4000),
        // Aligns with the API's Cache-Control: public, max-age=300.
        // Same scan_id → same canonical bytes → same signature, so the chips
        // are stable for the cache window.
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

export function shortHash(hash: string | null, head = 10, tail = 4): string {
  if (!hash) return "—";
  if (hash.length <= head + tail + 1) return hash;
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`;
}

export function fmtSignedAt(iso: string | null): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    const ms = Date.now() - d.getTime();
    if (!Number.isFinite(ms) || ms < 0) {
      return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    }
    if (ms < 60_000) return "just now";
    if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
    if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  } catch {
    return iso;
  }
}

interface Props {
  slug: string;
  apiUrl: string;
}

export default async function SignedEvidencePack({ slug, apiUrl }: Props) {
  const att = await getAttestation(slug, apiUrl);
  const slugEnc = encodeURIComponent(slug);

  return (
    <section className="sep-card" aria-labelledby="sep-heading">
      <header className="sep-head">
        <div className="sep-head-text">
          <div className="sep-eyebrow">Auditor-ready · HMAC-SHA256 · RFC 8785</div>
          <h2 id="sep-heading" className="sep-title">
            Signed Compliance Pack
          </h2>
          <p className="sep-tagline">
            Hand a regulator the signed PDF for any of seven frameworks. Each artifact
            is HMAC-attested over the canonical bytes — verifiable offline against the
            published key.
          </p>
        </div>

        {att?.dev_key_warning && (
          <span
            className="sep-warn"
            title="Production HMAC key not yet wired (COMPLIANCE_SIGNING_KEY env). Dev key in use."
          >
            DEV KEY
          </span>
        )}
      </header>

      <div className="sep-chips" role="status" aria-label="Attestation parameters">
        <span className="sep-chip">
          <span className="sep-chip-k">algorithm</span>
          <span className="sep-chip-v">{att?.algorithm ?? "HMAC-SHA256"}</span>
        </span>
        <span className="sep-chip">
          <span className="sep-chip-k">canonicalization</span>
          <span className="sep-chip-v">{att?.canonicalization ?? "RFC 8785"}</span>
        </span>
        <span className="sep-chip">
          <span className="sep-chip-k">key</span>
          <span className="sep-chip-v sep-chip-mono">{shortHash(att?.key_id ?? null, 8, 4)}</span>
        </span>
        <span className="sep-chip">
          <span className="sep-chip-k">signed</span>
          <span className="sep-chip-v">{fmtSignedAt(att?.signed_at ?? null)}</span>
        </span>
        <span
          className="sep-chip sep-chip-sig"
          title={att?.signature ?? "Attestation unavailable"}
        >
          <span className="sep-chip-k">signature</span>
          <span className="sep-chip-v sep-chip-mono">
            {shortHash(att?.signature ?? null, 12, 4)}
          </span>
        </span>
      </div>

      <ul className="sep-grid" aria-label="Compliance frameworks">
        {FRAMEWORKS.map((fw) => (
          <li key={fw.id} className="sep-row">
            <div className="sep-row-id">
              <div className="sep-row-name">{fw.label}</div>
              <div className="sep-row-sub">{fw.sub}</div>
            </div>
            <div className="sep-row-actions">
              <a
                className="sep-fmt sep-fmt-pdf"
                href={`${apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.pdf`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Download ${fw.label} signed PDF`}
              >
                PDF
              </a>
              <a
                className="sep-fmt"
                href={`${apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.html`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Open ${fw.label} signed HTML`}
              >
                HTML
              </a>
              <a
                className="sep-fmt"
                href={`${apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}.json`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Download ${fw.label} signed JSON envelope`}
              >
                JSON
              </a>
              <a
                className="sep-fmt sep-fmt-badge"
                href={`${apiUrl}/api/v1/servers/${slugEnc}/compliance/${fw.id}/badge.svg`}
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

      <p className="sep-foot">
        Verify offline:{" "}
        <code className="sep-mono">
          openssl dgst -sha256 -hmac &lt;key&gt; &lt;canonicalised-body&gt;
        </code>
        . Canonical bytes are reproducible by any RFC 8785-compliant JSON library.
      </p>
    </section>
  );
}

// Test-only export of the framework list so the unit test stays in lockstep
// with the source-of-truth registry in packages/compliance-reports/frameworks/.
export { FRAMEWORKS as __TEST_FRAMEWORKS };
