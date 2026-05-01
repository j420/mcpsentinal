import React from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import ServerProfileCard from "@/components/ServerProfileCard";
import type { ServerProfileData } from "@/components/ServerProfileCard";
import AttackChainCard from "@/components/AttackChainCard";
import type { AttackChainItem } from "@/components/AttackChainCard";
import EvidenceSummaryHero from "@/components/EvidenceSummaryHero";
import SignedEvidencePack from "@/components/SignedEvidencePack";
import AttackSurfaceStrip from "@/components/AttackSurfaceStrip";
import FrameworkPostureMatrix from "@/components/FrameworkPostureMatrix";
import FindingsEvidenceTab from "@/components/FindingsEvidenceTab";
import GradeBreakdownTab from "@/components/GradeBreakdownTab";
import RiskBoundaryTab from "@/components/RiskBoundaryTab";
import DriftAndHistoryTab from "@/components/DriftAndHistoryTab";
import FooterAttestationBar from "@/components/FooterAttestationBar";
import HonestGaps from "@/components/HonestGaps";
import DeepDiveHeroChrome from "@/components/DeepDiveHeroChrome";
import DeepDiveLayout from "@/components/DeepDiveLayout";
import CategorySection from "@/components/CategorySection";
import DeepDiveSidebar from "@/components/DeepDiveSidebar";
import ComplianceTab from "./ComplianceTab";
import type { DeepDiveResponse, DeepDiveData } from "@/lib/deep-dive";

// Cluster B reviewer M1 — `force-dynamic` was disabling RSC fetch caching
// across the entire page tree, silently making `<SignedEvidencePack/>`'s
// `next: { revalidate: 300 }` and `<FrameworkPostureMatrix/>`'s identical
// hint into no-ops. Each page load triggered 7× buildReport() on the API
// + a fresh /compliance/eu_ai_act.json HEAD-equivalent for the attestation
// chips. Removed: the page already opts into dynamic rendering implicitly
// via `searchParams` (Next 15 makes that route segment dynamic
// automatically), so the explicit `force-dynamic` was redundant for
// correctness and harmful for performance.
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

// NOTE: at runtime, every finding row also carries `framework_controls[]`
// (Cluster B — populated by getFrameworkControlsForRule()) and
// `detection_quality` (Cluster C — populated by getDetectionQualityForRule()).
// They are NOT declared on this page-level type because:
//   (a) the page only forwards findings into <FindingsEvidenceTab/>, which
//       has its own richer Finding type that DOES declare them, and TS's
//       structural subtyping accepts the wider runtime shape;
//   (b) co-locating the canonical shape with the consuming component
//       (FindingsEvidenceTab) keeps the source-of-truth in one place.
// Cluster C reviewer m2 lesson — surface this explicitly so a future
// contributor reading this file does not conclude the fields don't exist.
interface Finding {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  /** Phase 1: per-finding confidence score (0.0–1.0). Absent on pre-Phase-1 data. */
  confidence?: number;
  /** Phase 1: structured evidence chain proving the finding. Absent on pre-Phase-1 data. */
  evidence_chain?: Record<string, unknown> | null;
}

interface Tool {
  name: string;
  description: string | null;
  capability_tags: string[];
}

interface ScoreDetail {
  total_score: number;
  code_score: number;
  deps_score: number;
  config_score: number;
  description_score: number;
  behavior_score: number;
  /**
   * Coverage band for the score — honest confidence label rendered next to the
   * total. "minimal" means we had so little to go on (no source code, no live
   * connection, no deps manifest) that the score is closer to a guess than a
   * measurement. Absent on pre-coverage scans.
   */
  coverage_band?: "high" | "medium" | "low" | "minimal" | null;
  /**
   * Phase-2 8-bucket sub-scores (each 0–100). When present, replaces the
   * legacy 5-bucket display with the v2 risk-domain breakdown. Absent on
   * pre-Phase-2 scans — the hero falls back to legacy rendering.
   */
  v2_sub_scores?: {
    schema_score: number;
    ecosystem_score: number;
    protocol_score: number;
    adversarial_score: number;
    compliance_score: number;
    supply_chain_score: number;
    infrastructure_score: number;
    code_score: number;
  } | null;
  /**
   * What the analyzer actually had to work with on this scan — drives the
   * "what we analysed" pips and the "X of Y rules executed" inline meta.
   * Absent on pre-coverage scans.
   */
  analysis_coverage?: {
    had_source_code: boolean;
    had_connection: boolean;
    had_dependencies: boolean;
    coverage_ratio: number;
    techniques_run: string[];
    rules_executed: number;
    rules_skipped_no_data: number;
  } | null;
}

interface ScanStages {
  stages: unknown;
  started_at: string | null;
  completed_at: string | null;
  status: string;
  rules_version?: string | null;
}

interface ServerDetail {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  author: string | null;
  category: string | null;
  language: string | null;
  license: string | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  github_stars: number | null;
  npm_downloads: number | null;
  last_commit: string | null;
  last_scanned_at: string | null;
  endpoint_url: string | null;
  connection_status: string | null;
  server_version: string | null;
  tool_count: number;
  tools: Tool[];
  findings: Finding[];
  owasp_coverage?: Record<string, boolean>;
  /** Phase 1 score sub-breakdown — used by GradeBreakdownTab. */
  score_detail?: ScoreDetail | null;
  /** Latest scan timing/status — used by hero + footer. */
  scan_stages?: ScanStages | null;
  /** Phase 1: server capability profile. Absent until API serves Phase 1 data. */
  profile?: ServerProfileData | null;
  /** Attack chains involving this server. Absent until API serves attack chain data. */
  attack_chains?: AttackChainItem[] | null;
  // NOTE: `analysis_coverage` is nested under `score_detail.analysis_coverage`
  // (per the API contract in packages/database/src/schemas.ts ::
  // ScoreDetailResponseSchema). Do not declare it here as a top-level field
  // — Cluster A reviewer B2 caught the divergence: a top-level reference is
  // always undefined, which makes HonestGaps lie about coverage on every
  // page view.
}

// ── Data Fetching ─────────────────────────────────────────────────────────────

async function getServer(slug: string): Promise<ServerDetail | null> {
  try {
    const res = await fetch(
      `${API_URL}/api/v1/servers/${encodeURIComponent(slug)}`,
      { signal: AbortSignal.timeout(4000) }
    );
    if (!res.ok) return null;
    const data = await res.json();
    return data.data ?? null;
  } catch {
    return null;
  }
}

/**
 * Fetch the deep-dive payload (long-scroll content). Absent until Agent 2's
 * endpoint lands; the page falls back to the legacy Cluster-A/B/C-shape view
 * (`<EvidenceSummaryHero/>` + `<FrameworkPostureMatrix/>`) when this returns
 * null. Mirrors `<SignedEvidencePack/>` resilience pattern: 4-second timeout,
 * 5-minute revalidate, never throws.
 */
async function getDeepDive(slug: string): Promise<DeepDiveData | null> {
  try {
    const res = await fetch(
      `${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/deep-dive`,
      {
        signal: AbortSignal.timeout(4000),
        next: { revalidate: 300 },
      },
    );
    if (!res.ok) return null;
    const body = (await res.json()) as DeepDiveResponse;
    return body?.data ?? null;
  } catch {
    return null;
  }
}

// ── SEO Metadata ──────────────────────────────────────────────────────────────

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const server = await getServer(slug);
  if (!server) return { title: "Server Not Found" };
  const findCount = server.findings?.length ?? 0;
  return {
    title: `${server.name} Security Report`,
    description: `Security analysis of ${server.name} MCP server. ${findCount} finding${findCount !== 1 ? "s" : ""} detected across 164 active detection rules.`,
  };
}

// ── Page ──────────────────────────────────────────────────────────────────────

// ── Relocated section: Tools.
// Was a separate "Tools" tab; demoted in this page to a collapsed
// `<details>` accordion below the deep-dive long-scroll content. The
// existing component has no separate re-export, so the markup stays
// inline here.
function ToolsSection({ tools }: { tools: Tool[] }) {
  return (
    <section id="tools" className="sd-section">
      <h2 className="sd-section-title">
        Tools
        <span className="sd-section-count">{tools.length}</span>
      </h2>
      {tools.length === 0 ? (
        <p className="sd-section-sub">No tools enumerated for this server.</p>
      ) : (
        <div className="sd-tools-grid">
          {tools.map((tool) => (
            <div key={tool.name} className="sd-tool">
              <div className="sd-tool-name">{tool.name}</div>
              {tool.description && (
                <div className="sd-tool-desc">{tool.description}</div>
              )}
              {tool.capability_tags.length > 0 && (
                <div className="sd-tool-caps">
                  {tool.capability_tags.map((tag) => (
                    <span key={tag} className={`cap-tag cap-${tag}`}>
                      {tag.replace(/-/g, " ")}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

/**
 * Render a chrome subsection wrapped in a closed-by-default `<details>`
 * accordion. The Cluster-A/B/C tab content survives — it just lives one
 * click away from the deep-dive scroll instead of competing with it.
 */
function DemotedSection({
  id,
  title,
  count,
  children,
}: {
  id: string;
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <details id={id} className="dd-demote" data-section={id}>
      <summary className="dd-demote-summary">
        <span className="dd-demote-title">{title}</span>
        {typeof count === "number" && (
          <span className="dd-demote-count">{count}</span>
        )}
        <span className="dd-demote-chev" aria-hidden="true">
          ▼
        </span>
      </summary>
      <div className="dd-demote-body">{children}</div>
    </details>
  );
}

// ── DEEP DIVE main column placeholder ────────────────────────────────────
//
// Cluster D reviewer B1 fix — the placeholder DeepDiveMainPlaceholder /
// DeepDiveSidebarPlaceholder helpers that lived here were the bug: they
// rendered category titles + counts only, never the per-rule evidence.
// They have been replaced by the canonical `<CategorySection/>` and
// `<DeepDiveSidebar/>` mounts in the page body. Do NOT re-introduce
// placeholder helpers without explicit product approval.

export default async function ServerDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ slug: string }>;
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { slug } = await params;
  // Next 15 — searchParams is a Promise. Defaulted to an empty object so
  // routes that didn't pass it (e.g. tests, prerender) don't crash.
  const sp = (await searchParams) ?? {};
  const groupRaw = Array.isArray(sp.group) ? sp.group[0] : sp.group;
  const groupByCategory = groupRaw === "category";

  // Drift window — `?days=` from searchParams. Snapped to 30 / 90 / 365 by the
  // component itself; we just pull the numeric here so the demoted accordion
  // construction stays declarative.
  const daysRaw = Array.isArray(sp.days) ? sp.days[0] : sp.days;
  const driftDays = (() => {
    const n = daysRaw == null ? NaN : Number(daysRaw);
    return n === 30 || n === 90 || n === 365 ? n : 90;
  })();

  // Two parallel fetches: server stays the source of truth for hero +
  // demoted chrome; deep-dive provides the new long-scroll payload.
  const [server, deepDive] = await Promise.all([
    getServer(slug),
    getDeepDive(slug),
  ]);

  if (!server) return notFound();

  const findings = server.findings ?? [];
  const tools = server.tools ?? [];

  const findingsLabel = groupByCategory
    ? "Findings & Evidence (grouped)"
    : "Findings & Evidence";

  const findingsPanel = (
    <>
      <div className="sd-findings-toggle" role="group" aria-label="Findings view">
        <a
          className={`sd-toggle-link${!groupByCategory ? " sd-toggle-active" : ""}`}
          href={`?`}
          aria-current={!groupByCategory ? "page" : undefined}
        >
          Flat list
        </a>
        <span className="sd-toggle-sep" aria-hidden="true">·</span>
        <a
          className={`sd-toggle-link${groupByCategory ? " sd-toggle-active" : ""}`}
          href={`?group=category`}
          aria-current={groupByCategory ? "page" : undefined}
        >
          Group by OWASP category
        </a>
      </div>
      <FindingsEvidenceTab
        findings={findings}
        scanId={null}
        slug={slug}
        groupByCategory={groupByCategory}
      />
    </>
  );

  // Lethal-trifecta — F1/I13 cap. Computed from findings on the legacy slug
  // payload; identical to the analyzer's `score_detail.coverage_band` cap.
  const lethal = findings.some((f) => f.rule_id === "F1" || f.rule_id === "I13");

  // ──────────────────────────────────────────────────────────────────
  // Mode A: deep-dive endpoint succeeded → long-scroll layout
  // Mode B: deep-dive endpoint failed   → legacy Cluster-A/B/C view
  //
  // Both modes render the same demoted-chrome accordions below so the
  // user never loses access to Phase-5 content even if the new endpoint
  // is missing. The difference is the hero + main scroll.
  // ──────────────────────────────────────────────────────────────────
  // Cluster D reviewer M4 — `categories: []` (taxonomy missing in prod
  // image, yaml dep unresolvable, etc.) used to enter Mode A and render
  // a thin chrome strip with no content. Now: Mode A only when we have
  // real deep-dive content (categories non-empty). Empty categories
  // degrade to Mode B (legacy hero) so the user always sees something
  // useful.
  const hasDeepDiveContent =
    deepDive != null && deepDive.categories.length > 0;
  const heroSlot =
    hasDeepDiveContent ? (
      <DeepDiveHeroChrome
        slug={slug}
        apiUrl={API_URL}
        name={server.name}
        server_version={server.server_version}
        author={server.author}
        total_score={server.score_detail?.total_score ?? null}
        lethal={lethal}
        coverage_band={
          deepDive.coverage.coverage_band ??
          server.score_detail?.coverage_band ??
          null
        }
        had_source_code={
          server.score_detail?.analysis_coverage?.had_source_code ?? false
        }
        had_connection={
          server.score_detail?.analysis_coverage?.had_connection ?? false
        }
        had_dependencies={
          server.score_detail?.analysis_coverage?.had_dependencies ?? false
        }
      />
    ) : (
      // Degraded fallback — keep the original 3-column hero so the page
      // never 500s when `/deep-dive` is absent. SignedEvidencePack ships
      // its own card; we keep it so the legacy fallback view is no worse
      // than what shipped before this PR.
      <>
        <EvidenceSummaryHero
          name={server.name}
          description={server.description}
          author={server.author}
          license={server.license}
          server_version={server.server_version}
          endpoint_url={server.endpoint_url}
          github_url={server.github_url}
          npm_package={server.npm_package}
          pypi_package={server.pypi_package}
          last_scanned_at={server.last_scanned_at}
          score_detail={server.score_detail ?? null}
          scan_stages={server.scan_stages ?? null}
          findings={findings}
          tools={tools}
        />
        <SignedEvidencePack slug={slug} apiUrl={API_URL} />
      </>
    );

  // The demoted-chrome accordions — present in BOTH modes, closed by
  // default. Demotion-not-deletion: every Cluster A/B/C component still
  // renders at one click of a `<details>` summary.
  const demotedChrome = (
    <div className="dd-demote-stack" aria-label="Supporting sections">
      <DemotedSection id="posture-matrix" title="Framework Posture Matrix">
        <FrameworkPostureMatrix
          slug={slug}
          apiUrl={API_URL}
          owasp_coverage_fallback={server.owasp_coverage ?? null}
        />
      </DemotedSection>

      <DemotedSection
        id="findings-evidence"
        title={findingsLabel}
        count={findings.length}
      >
        {findingsPanel}
      </DemotedSection>

      <DemotedSection id="compliance" title="Compliance">
        <ComplianceTab slug={slug} />
      </DemotedSection>

      <DemotedSection id="risk-boundary" title="Risk Boundary">
        <RiskBoundaryTab slug={slug} apiUrl={API_URL} />
      </DemotedSection>

      <DemotedSection id="drift-history" title="Drift & History">
        <DriftAndHistoryTab slug={slug} apiUrl={API_URL} days={driftDays} />
      </DemotedSection>

      <DemotedSection id="attack-surface" title="Attack Surface">
        <AttackSurfaceStrip tools={tools} findings={findings} />
      </DemotedSection>

      <DemotedSection id="tools" title="Tools" count={tools.length}>
        <ToolsSection tools={tools} />
      </DemotedSection>

      <DemotedSection id="grade-breakdown" title="Grade Breakdown">
        <GradeBreakdownTab
          score_detail={server.score_detail ?? null}
          findings={findings}
        />
      </DemotedSection>

      <DemotedSection id="server-profile" title="Server Capability Profile">
        <ServerProfileCard profile={server.profile ?? null} />
      </DemotedSection>

      <DemotedSection id="attack-chains" title="Attack Chains">
        <AttackChainCard
          chains={server.attack_chains ?? null}
          currentServerId={server.id}
        />
      </DemotedSection>

      <DemotedSection id="honest-gaps" title="Honest Gaps">
        <HonestGaps
          analysis_coverage={server.score_detail?.analysis_coverage ?? null}
          findingsCount={findings.length}
        />
      </DemotedSection>
    </div>
  );

  return (
    <div className="dd-page">
      {/* Breadcrumb */}
      <nav className="sd-breadcrumb">
        <a href="/">Home</a>
        <span className="sd-bread-sep">/</span>
        <a href="/servers">Servers</a>
        <span className="sd-bread-sep">/</span>
        <span className="sd-bread-current">{server.name}</span>
      </nav>

      {/* ── Hero chrome: thin strip OR legacy 3-column degraded fallback ── */}
      {heroSlot}

      {/* ── Deep dive long scroll OR nothing in degraded mode ─────────────
          Cluster D reviewer B1 — wire the real components in. Cluster D
          shipped <CategorySection/> (Agent 4) + <DeepDiveSidebar/>
          (Agent 5) + the per-rule <RuleEvidenceCard/> chain underneath;
          before this fix the page mounted local placeholders that
          rendered category titles only. The user's product call ("make
          Deep Dive section the hero on the server page") is delivered
          here.
          Reviewer M4 — only enter Mode A (Deep Dive) when categories
          actually exist. With empty categories the legacy hero in
          `heroSlot` already renders fully. */}
      {deepDive != null && deepDive.categories.length > 0 && (
        <DeepDiveLayout
          sidebar={<DeepDiveSidebar categories={deepDive.categories} />}
          main={
            <div className="dd-main">
              {deepDive.categories.map((cat) => (
                <CategorySection key={cat.id} cat={cat} />
              ))}
            </div>
          }
        />
      )}

      {/* ── Demoted chrome accordions (Cluster A/B/C) ───────────────────── */}
      {demotedChrome}

      {/* ── Footer attestation bar ──────────────────────────────────────── */}
      <FooterAttestationBar
        slug={slug}
        apiUrl={API_URL}
        findingsCount={findings.length}
        scan_stages={server.scan_stages ?? null}
        rulesVersion={server.scan_stages?.rules_version ?? null}
      />
    </div>
  );
}
