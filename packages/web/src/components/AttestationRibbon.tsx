/**
 * Attestation Ribbon — "How we know."
 *
 * Slim full-width strip directly under the Trust Signature. Every datum is
 * observable from the API response or derivable client-side; nothing is
 * decorative. This is the section that proves the analysis is real.
 *
 * Client component because it derives a tool-fingerprint hash via crypto.subtle
 * — pure browser computation, no network round-trip.
 */
"use client";

import React, { useEffect, useMemo, useState } from "react";

interface ToolForFingerprint {
  name: string;
  description: string | null;
  capability_tags: string[];
}

interface ScanStages {
  stages: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
  status: string | null;
}

interface SourceRef {
  source_name: string;
  external_id: string | null;
}

interface CorpusEntry {
  fixture_count: number;
  cve_replays: string[];
}

interface Props {
  rules_version: string | null;
  scan_stages: ScanStages | null;
  sources: SourceRef[];
  tools: ToolForFingerprint[];
  red_team_corpus_links: Record<string, CorpusEntry> | null;
  finding_rule_ids: string[];
  connection_status: string | null;
}

const STAGE_ORDER = [
  { key: "source_fetched", label: "SOURCE" },
  { key: "connection_attempted", label: "CONNECT" },
  { key: "connection_succeeded", label: "ENUM" },
  { key: "dependencies_audited", label: "DEPS" },
] as const;

const SOURCE_DISPLAY: Record<string, string> = {
  pulsemcp: "PulseMCP",
  smithery: "Smithery",
  npm: "npm",
  pypi: "PyPI",
  github: "GitHub",
  "official-registry": "Official",
  glama: "Glama",
  "awesome-mcp-servers": "Awesome",
  "docker-hub": "Docker",
  zarq: "Zarq",
  manual: "Manual",
};

function useToolFingerprint(tools: ToolForFingerprint[]): string | null {
  const [hash, setHash] = useState<string | null>(null);
  const payload = useMemo(
    () =>
      JSON.stringify(
        tools.map((t) => ({
          name: t.name,
          description: t.description ?? "",
          capability_tags: [...t.capability_tags].sort(),
        }))
      ),
    [tools]
  );
  useEffect(() => {
    if (!tools.length) return;
    if (typeof crypto === "undefined" || !crypto.subtle) return;
    const data = new TextEncoder().encode(payload);
    crypto.subtle
      .digest("SHA-256", data)
      .then((buf) => {
        const hex = Array.from(new Uint8Array(buf))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        setHash(hex);
      })
      .catch(() => setHash(null));
  }, [payload, tools.length]);
  return hash;
}

export default function AttestationRibbon(props: Props) {
  const {
    rules_version, scan_stages, sources, tools,
    red_team_corpus_links, finding_rule_ids, connection_status,
  } = props;

  const fingerprint = useToolFingerprint(tools);

  // Aggregate: of the rules that fired on this server, how many fixtures + CVE
  // replays back them up? Strongest funding signal — proves we tested for what
  // we found.
  const corpusTotals = useMemo(() => {
    if (!red_team_corpus_links) return null;
    const seenCves = new Set<string>();
    let fixtures = 0;
    for (const ruleId of finding_rule_ids) {
      const entry = red_team_corpus_links[ruleId];
      if (!entry) continue;
      fixtures += entry.fixture_count;
      for (const c of entry.cve_replays) seenCves.add(c);
    }
    return { fixtures, cve_replays: seenCves.size, rules_covered: finding_rule_ids.length };
  }, [red_team_corpus_links, finding_rule_ids]);

  const stagesObj = (scan_stages?.stages ?? {}) as Record<string, boolean>;

  return (
    <section className="attestation-ribbon" aria-label="Analysis attestation">
      <div className="attestation-track">
        {/* Pipeline stages */}
        <details className="attestation-cell attestation-pipeline">
          <summary>
            <span className="eyebrow-mono">PIPELINE</span>
            <span className="attestation-stages">
              {STAGE_ORDER.map((s) => {
                const ok = Boolean(stagesObj[s.key]);
                return (
                  <span
                    key={s.key}
                    className={`attestation-stage ${ok ? "stage-ok" : "stage-fail"}`}
                    title={`${s.label}: ${ok ? "completed" : "missed"}`}
                  >
                    {s.label}
                  </span>
                );
              })}
            </span>
          </summary>
          <div className="attestation-pipeline-detail">
            {scan_stages?.started_at && (
              <span>started {new Date(scan_stages.started_at).toISOString()}</span>
            )}
            {scan_stages?.completed_at && (
              <span> · completed {new Date(scan_stages.completed_at).toISOString()}</span>
            )}
            {scan_stages?.status && <span> · status: {scan_stages.status}</span>}
          </div>
        </details>

        {/* Discovery sources */}
        {sources.length > 0 && (
          <div className="attestation-cell">
            <span className="eyebrow-mono">DISCOVERED VIA</span>
            <span className="attestation-val">
              {sources.map((s) => SOURCE_DISPLAY[s.source_name] ?? s.source_name).join(" · ")}
            </span>
          </div>
        )}

        {/* Rules version */}
        {rules_version && (
          <div className="attestation-cell">
            <span className="eyebrow-mono">RULESET</span>
            <span className="attestation-val">v{rules_version}</span>
          </div>
        )}

        {/* Connection */}
        {connection_status && (
          <div className="attestation-cell">
            <span className="eyebrow-mono">CONNECTION</span>
            <span className={`attestation-val attestation-conn-${connection_status}`}>
              {connection_status}
            </span>
          </div>
        )}

        {/* Tool fingerprint */}
        {fingerprint && (
          <div className="attestation-cell" title={`SHA-256 of normalised tool metadata — changes when this server adds, removes, or modifies a tool. Underpins rug-pull detection (G6).`}>
            <span className="eyebrow-mono">FINGERPRINT</span>
            <span className="attestation-val attestation-mono">
              {fingerprint.slice(0, 12)}…
            </span>
          </div>
        )}

        {/* Adversarial validation */}
        {corpusTotals && corpusTotals.fixtures > 0 && (
          <div className="attestation-cell">
            <span className="eyebrow-mono">VALIDATED</span>
            <span className="attestation-val">
              {corpusTotals.fixtures.toLocaleString()} fixtures
              {corpusTotals.cve_replays > 0 && ` + ${corpusTotals.cve_replays} CVE replays`}
            </span>
          </div>
        )}
      </div>
    </section>
  );
}
