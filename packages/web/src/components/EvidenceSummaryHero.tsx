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
 *
 * v6 coverage upgrade (esh-cov-*): when score_detail carries an
 * analysis_coverage block AND/OR a v2_sub_scores block we surface honest
 * confidence bounds beside the score — coverage_band chip, three "what we
 * analysed" pips (source / live / deps), and an 8-bucket v2 sub-score row.
 * When both fields are absent the hero renders exactly as before — backwards
 * compat is non-negotiable.
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

/**
 * v6 coverage extension — Cluster A part 1 ships this on the API. When both
 * analysis_coverage and v2_sub_scores are null the hero falls back to the
 * legacy single-total rendering so older scans still look right.
 */
interface ScoreDetailV2SubScores {
  schema_score: number;
  ecosystem_score: number;
  protocol_score: number;
  adversarial_score: number;
  compliance_score: number;
  supply_chain_score: number;
  infrastructure_score: number;
  code_score: number;
}

interface AnalysisCoverage {
  had_source_code: boolean;
  had_connection: boolean;
  had_dependencies: boolean;
  coverage_ratio: number;
  techniques_run: string[];
  rules_executed: number;
  rules_skipped_no_data: number;
}

type CoverageBand = "high" | "medium" | "low" | "minimal";

interface ScoreDetail {
  total_score: number;
  coverage_band?: CoverageBand | null;
  v2_sub_scores?: ScoreDetailV2SubScores | null;
  analysis_coverage?: AnalysisCoverage | null;
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

// ── Coverage helpers (v6) ────────────────────────────────────────────────────

/**
 * Coverage band → CSS color token. Maps to the existing --good/--moderate/
 * --poor/--critical scale (kept identical to score-band tokens so a CISO
 * sees confidence-color matching the score-color story without learning a
 * second palette).
 */
function coverageBandColor(band: CoverageBand): string {
  if (band === "high") return "var(--good)";
  if (band === "medium") return "var(--moderate)";
  if (band === "low") return "var(--poor)";
  return "var(--critical)"; // minimal
}

function coverageBandLabel(band: CoverageBand): string {
  return { high: "HIGH", medium: "MEDIUM", low: "LOW", minimal: "MINIMAL" }[band];
}

/**
 * 8-bucket v2 sub-score row. Order is fixed and tested. Each row is a
 * label/value pair rendered in a two-column grid via dl/dt/dd for screen
 * readers. "code" is intentionally last — it migrates out of the legacy
 * code_score bucket into the v2 row so all eight risk domains read as
 * a single coherent set.
 */
const V2_SUB_SCORE_BUCKETS: ReadonlyArray<{
  key: keyof ScoreDetailV2SubScores;
  label: string;
}> = [
  { key: "schema_score", label: "Schema" },
  { key: "ecosystem_score", label: "Ecosystem" },
  { key: "protocol_score", label: "Protocol" },
  { key: "adversarial_score", label: "Adversarial" },
  { key: "compliance_score", label: "Compliance" },
  { key: "supply_chain_score", label: "Supply chain" },
  { key: "infrastructure_score", label: "Infrastructure" },
  { key: "code_score", label: "Code" },
];

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

export function distinctDomains(tools: Tool[]): string[] {
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

export function buildVerdict(toolCount: number, tools: Tool[], findings: Finding[]): string {
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

// ── Coverage sub-components ──────────────────────────────────────────────────

function CoverageBandChip({ band }: { band: CoverageBand }) {
  const label = coverageBandLabel(band);
  const color = coverageBandColor(band);
  return (
    <span
      className={`esh-cov-chip esh-cov-chip-${band}`}
      style={{ color, borderColor: color }}
      role="status"
      aria-label={`Analysis confidence: ${label.toLowerCase()}`}
      title={
        band === "high"
          ? "High confidence: source code parsed, live initialize+tools/list completed, dependency manifest audited."
          : band === "medium"
          ? "Medium confidence: most analyzer techniques ran, but some inputs were missing."
          : band === "low"
          ? "Low confidence: core inputs were missing — score is indicative, not definitive."
          : "Minimal confidence: almost no inputs were available. Treat the score as a placeholder."
      }
    >
      {label} confidence
    </span>
  );
}

function CoveragePips({ coverage }: { coverage: AnalysisCoverage }) {
  const pips: Array<{ key: string; label: string; present: boolean; title: string }> = [
    {
      key: "source",
      label: "source",
      present: coverage.had_source_code,
      title: "Source code fetched and parsed",
    },
    {
      key: "live",
      label: "live",
      present: coverage.had_connection,
      title: "Live MCP initialize+tools/list completed",
    },
    {
      key: "deps",
      label: "deps",
      present: coverage.had_dependencies,
      title: "Dependency manifest audited",
    },
  ];
  return (
    <ul className="esh-cov-pips" role="list" aria-label="Inputs available to the analyzer">
      {pips.map((p) => (
        <li
          key={p.key}
          className={`esh-cov-pip esh-cov-pip-${p.present ? "on" : "off"}`}
          title={`${p.title}${p.present ? "" : " — NOT available for this scan"}`}
          aria-label={`${p.label}: ${p.present ? "available" : "missing"}`}
        >
          <span className="esh-cov-pip-glyph" aria-hidden="true">
            {p.present ? "✓" : "×"}
          </span>
          <span className="esh-cov-pip-label">{p.label}</span>
        </li>
      ))}
    </ul>
  );
}

function V2SubScoreRow({ subs }: { subs: ScoreDetailV2SubScores }) {
  return (
    <dl className="esh-cov-subscores" aria-label="Risk-domain sub-scores">
      {V2_SUB_SCORE_BUCKETS.map(({ key, label }) => {
        const value = subs[key];
        const band = scoreBand(value);
        return (
          <div key={key} className="esh-cov-subscore" data-bucket={key}>
            <dt className="esh-cov-subscore-label">{label}</dt>
            <dd
              className={`esh-cov-subscore-val esh-cov-subscore-val-${band}`}
              style={{ color: `var(--${band})` }}
            >
              {value}
            </dd>
          </div>
        );
      })}
    </dl>
  );
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
  // No fallback — Cluster A reviewer M4: hard-coding the active rule count
  // here drifts every time the registry changes (177 → 164 already happened).
  // When the prop is absent, render an honest em-dash; the truth lives in
  // analysis_coverage's rules_executed + rules_skipped_no_data, surfaced
  // separately as the "Coverage" meta row below.
  const totalRules: number | null = props.total_rules ?? null;

  // v6 coverage extensions — both null on legacy scans → fall back to the
  // existing rendering exactly as before.
  const coverage = props.score_detail?.analysis_coverage ?? null;
  const v2Subs = props.score_detail?.v2_sub_scores ?? null;
  const coverageBand = props.score_detail?.coverage_band ?? null;
  const hasCoverageExtras = Boolean(coverage || v2Subs || coverageBand);

  // "X of Y rules executed" — only when analysis_coverage is present.
  const rulesExecutedMeta = coverage
    ? `${coverage.rules_executed} of ${coverage.rules_executed + coverage.rules_skipped_no_data} rules executed`
    : null;

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

        {/* v6 — confidence chip + coverage pips. Only render when we have
            actual coverage signal; otherwise the legacy hero looks unchanged. */}
        {hasCoverageExtras && (
          <div className="esh-cov-cluster" data-testid="esh-cov-cluster">
            {coverageBand && <CoverageBandChip band={coverageBand} />}
            {coverage && <CoveragePips coverage={coverage} />}
          </div>
        )}
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

        {/* v6 — 8-bucket sub-score row. Sits under the verdict so a CISO
            scanning the page sees the breakdown right after the prose. When
            v2_sub_scores is null we keep the legacy single-total story. */}
        {v2Subs && <V2SubScoreRow subs={v2Subs} />}
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
            rules:{totalRules ?? "—"}
          </span>
        </div>
        {rulesExecutedMeta && (
          <div className="esh-meta-row" data-testid="esh-cov-rules-executed">
            <span className="esh-meta-label">Coverage</span>
            <span
              className="esh-meta-val esh-meta-mono"
              title="Rules whose required inputs were available on this scan"
            >
              {rulesExecutedMeta}
            </span>
          </div>
        )}
        <div className="esh-meta-row">
          <span className="esh-meta-label">Findings</span>
          <span className="esh-meta-val esh-meta-mono">
            {findingsCount} of {totalRules ?? "—"} rules
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
