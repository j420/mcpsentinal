/**
 * EvidenceSummaryHero — top-of-page summary for /servers/[slug].
 *
 * Three-column grid (score · identity+verdict · scan metadata) anchored to
 * the v5.1 institutional dark token system in globals.css. All colors come
 * from CSS vars (--good/--moderate/--poor/--critical for score bands,
 * --sev-* for severity emphasis, --accent for CTAs). Letter grade is a
 * derived UI label, NOT a stored field — see scoreToLetter() below.
 *
 * Lethal-trifecta detection: rules F1 and I13 force the score color to
 * --critical and surface a small chip, mirroring the scorer cap at 40
 * documented in agent_docs/scoring-algorithm.md.
 */

import React from "react";

interface Finding {
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
}

interface Tool {
  name: string;
  capability_tags: string[];
}

interface ScoreDetail {
  total_score: number;
}

interface ScanStages {
  stages: unknown;
  started_at: string | null;
  completed_at: string | null;
  status: string;
}

interface Props {
  name: string;
  description: string | null;
  author: string | null;
  license: string | null;
  server_version: string | null;
  endpoint_url: string | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  last_scanned_at: string | null;
  score_detail: ScoreDetail | null;
  scan_stages: ScanStages | null;
  findings: Finding[];
  tools: Tool[];
  total_rules?: number;
  rescanHref?: string;
  exportHref?: string;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

export function scoreBand(score: number): "good" | "moderate" | "poor" | "critical" {
  if (score >= 80) return "good";
  if (score >= 60) return "moderate";
  if (score >= 40) return "poor";
  return "critical";
}

export function scoreToLetter(score: number): string {
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

function deriveTransport(endpoint_url: string | null): string | null {
  if (!endpoint_url) return "stdio";
  const u = endpoint_url.toLowerCase();
  if (u.startsWith("sse://") || u.includes("/sse")) return "sse";
  if (u.startsWith("http://") || u.startsWith("https://")) return "streamable-http";
  return null;
}

function pluralize(n: number, s: string): string {
  return n === 1 ? `${n} ${s}` : `${n} ${s}s`;
}

function fmtDuration(started: string | null, completed: string | null): string {
  if (!started || !completed) return "—";
  const ms = new Date(completed).getTime() - new Date(started).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function fmtDateTime(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("en-US", {
      month: "short", day: "numeric", year: "numeric",
      hour: "numeric", minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

// ── Verdict generation (deterministic, no LLM per ADR-006) ───────────────────

const DOMAIN_BY_TAG: Record<string, string> = {
  "executes-code": "Shell / Code Execution",
  "manages-credentials": "Credentials & Secrets",
  "sends-network": "Network",
  "accesses-filesystem": "Filesystem",
  "writes-data": "Filesystem",
  "reads-data": "Filesystem",
};

const DOMAIN_PRIORITY = [
  "Shell / Code Execution",
  "Credentials & Secrets",
  "Network",
  "Filesystem",
];

function distinctDomains(tools: Tool[]): string[] {
  const set = new Set<string>();
  for (const t of tools) {
    for (const tag of t.capability_tags ?? []) {
      const d = DOMAIN_BY_TAG[tag];
      if (d) set.add(d);
    }
  }
  return [...set].sort(
    (a, b) => DOMAIN_PRIORITY.indexOf(a) - DOMAIN_PRIORITY.indexOf(b),
  );
}

function buildVerdict(toolCount: number, tools: Tool[], findings: Finding[]): string {
  const domains = distinctDomains(tools);
  const c = findings.filter((f) => f.severity === "critical").length;
  const h = findings.filter((f) => f.severity === "high").length;

  const exposurePart = toolCount === 0
    ? "This server exposes no enumerated tools"
    : `This server exposes ${pluralize(toolCount, "tool")} across ${pluralize(domains.length, "capability domain")}` +
      (domains.length ? ` — including ${domains.slice(0, 3).join(", ")}` : "");

  const sevPart = c + h === 0
    ? "We found no critical or high-severity issues; remaining findings are medium or below."
    : (() => {
        const worst = findings.find((f) => f.severity === "critical")
          ?? findings.find((f) => f.severity === "high");
        const worstSentence = worst
          ? `; the most severe being ${worst.rule_id} — ${(worst.evidence ?? "").split(/[.!?](\s|$)/)[0].trim()}`
          : "";
        return `We found ${pluralize(c, "critical")} and ${pluralize(h, "high")}-severity issue${c + h === 1 ? "" : "s"}${worstSentence}.`;
      })();

  return `${exposurePart}. ${sevPart}`;
}

// ── Component ────────────────────────────────────────────────────────────────

export default function EvidenceSummaryHero(props: Props) {
  const score = props.score_detail?.total_score ?? null;
  const lethal = props.findings.some(
    (f) => f.rule_id === "F1" || f.rule_id === "I13",
  );
  const effectiveScore = score == null ? null : (lethal ? Math.min(score, 40) : score);
  const band = effectiveScore == null ? "critical" : scoreBand(effectiveScore);
  const letter = effectiveScore == null ? "F" : scoreToLetter(effectiveScore);

  const transport = deriveTransport(props.endpoint_url);
  const verdict = buildVerdict(props.tools.length, props.tools, props.findings);

  const findingsCount = props.findings.length;
  const totalRules = props.total_rules ?? 164;

  return (
    <section className="esh-hero">
      {/* ── Left column: score + grade + band ─────────────────────────── */}
      <div className="esh-col esh-col-score">
        {lethal && (
          <span className="esh-lethal-chip" title="F1/I13 detected — score capped at 40 by the scorer">
            LETHAL TRIFECTA
          </span>
        )}
        <div
          className="esh-score-num"
          style={{ color: `var(--${band})` }}
          aria-label={`Score ${effectiveScore ?? "unknown"} of 100`}
        >
          {effectiveScore == null ? "—" : effectiveScore}
        </div>
        <div className="esh-score-of">/ 100</div>
        <div
          className="esh-letter"
          title="Synthesized from total_score (UI label only)"
          style={{ color: `var(--${band})` }}
        >
          {letter}
        </div>
        <div
          className="esh-band-word"
          style={{ color: `var(--${band})` }}
        >
          {bandLabel(band)}
        </div>
      </div>

      {/* ── Middle column: identity + verdict ─────────────────────────── */}
      <div className="esh-col esh-col-identity">
        <h1 className="esh-name">{props.name}</h1>

        <div className="esh-id-meta">
          {props.server_version && (
            <span className="esh-meta-chip esh-meta-mono">v{props.server_version}</span>
          )}
          {props.license && (
            <span className="esh-meta-chip">{props.license}</span>
          )}
          {transport && (
            <span className="esh-meta-chip esh-meta-mono">{transport}</span>
          )}
        </div>

        <div className="esh-publisher">
          {props.author && <span>{props.author}</span>}
          <span className="esh-publisher-unverified" title="Verification ships in a future milestone">
            publisher not yet verified
          </span>
        </div>

        <p className="esh-verdict">{verdict}</p>

        {props.description && (
          <p className="esh-description">{props.description}</p>
        )}

        <div className="esh-links">
          {props.github_url && (
            <a href={props.github_url} target="_blank" rel="noopener noreferrer" className="esh-link">
              GitHub
            </a>
          )}
          {props.npm_package && (
            <a href={`https://www.npmjs.com/package/${props.npm_package}`} target="_blank" rel="noopener noreferrer" className="esh-link">
              npm
            </a>
          )}
          {props.pypi_package && (
            <a href={`https://pypi.org/project/${props.pypi_package}`} target="_blank" rel="noopener noreferrer" className="esh-link">
              PyPI
            </a>
          )}
        </div>
      </div>

      {/* ── Right column: scan metadata + actions ─────────────────────── */}
      <div className="esh-col esh-col-meta">
        <div className="esh-meta-row">
          <span className="esh-meta-label">Last scanned</span>
          <span className="esh-meta-val esh-meta-mono">
            {fmtDateTime(props.last_scanned_at ?? props.scan_stages?.completed_at ?? null)}
          </span>
        </div>
        <div className="esh-meta-row">
          <span className="esh-meta-label">Engine</span>
          <span className="esh-meta-val esh-meta-mono">
            rules:{totalRules}
          </span>
        </div>
        <div className="esh-meta-row">
          <span className="esh-meta-label">Findings</span>
          <span className="esh-meta-val esh-meta-mono">
            {findingsCount} of {totalRules} rules
          </span>
        </div>
        <div className="esh-meta-row">
          <span className="esh-meta-label">Scan duration</span>
          <span className="esh-meta-val esh-meta-mono">
            {props.scan_stages
              ? fmtDuration(props.scan_stages.started_at, props.scan_stages.completed_at)
              : "—"}
          </span>
        </div>

        <div className="esh-actions">
          <a
            className="esh-btn esh-btn-primary"
            href={props.rescanHref ?? "/about#rescan"}
            title="Rescans run on the weekly crawl. Contact us to request an out-of-band rescan."
          >
            Rescan
          </a>
          <a
            className="esh-btn esh-btn-secondary"
            href={props.exportHref ?? "#footer-attestation"}
          >
            Export
          </a>
        </div>
      </div>
    </section>
  );
}
