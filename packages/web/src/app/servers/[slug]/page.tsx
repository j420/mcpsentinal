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
import VersionHistoryTab from "@/components/VersionHistoryTab";
import FooterAttestationBar from "@/components/FooterAttestationBar";
import HonestGaps from "@/components/HonestGaps";
import ServerTabs, { type ServerTab } from "./ServerTabs";
import ComplianceTab from "./ComplianceTab";

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

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
// Was a separate "Tools" tab; now lives between AttackSurfaceStrip and
// the relocated Grade Breakdown so the capability inventory sits with
// the rest of the surface picture. Markup is the original inline grid
// — only the location changed.
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

  const server = await getServer(slug);

  if (!server) return notFound();

  const findings = server.findings ?? [];
  const tools = server.tools ?? [];

  // ── Tab panels (rendered as RSC subtrees, passed across the boundary) ─────
  // Tab consolidation (audit Invention #5):
  //   Removed: Grade Breakdown, Deep Dive, Tools
  //   Relocated: Grade + Tools to dedicated sections above the tabs;
  //              Deep Dive collapsed into Findings via ?group=category.
  // Cluster A ships 3 tabs (Findings · Compliance · Version History). The
  // audit doc's target IA is 4 — "Risk Boundary" (Invention #3) is the
  // missing tab and is deliberately deferred to Cluster B per the staged
  // rollout in /root/.claude/plans/have-a-go-through-valiant-lollipop.md.
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
        groupByCategory={groupByCategory}
      />
    </>
  );

  const versionHistoryPanel = <VersionHistoryTab slug={slug} apiUrl={API_URL} />;

  const tabs: ServerTab[] = [
    {
      id: "findings",
      label: findingsLabel,
      count: findings.length,
      content: findingsPanel,
    },
    {
      id: "compliance",
      label: "Compliance",
      content: <ComplianceTab slug={slug} />,
    },
    {
      id: "version-history",
      label: "Version History",
      content: versionHistoryPanel,
    },
  ];

  return (
    <div className="sd-page">
      {/* Breadcrumb */}
      <nav className="sd-breadcrumb">
        <a href="/">Home</a>
        <span className="sd-bread-sep">/</span>
        <a href="/servers">Servers</a>
        <span className="sd-bread-sep">/</span>
        <span className="sd-bread-current">{server.name}</span>
      </nav>

      {/* ── Evidence Summary Hero (replaces previous identity hero) ────── */}
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

      {/* ── Signed Compliance Pack (Phase 6 invention #1 — top-of-page CTA) ─ */}
      <SignedEvidencePack slug={slug} apiUrl={API_URL} />

      {/* ── Attack Surface Strip (capability domain cards) ─────────────── */}
      <AttackSurfaceStrip tools={tools} findings={findings} />

      {/* ── Tools (relocated from killed tab — audit Invention #5) ─────── */}
      <ToolsSection tools={tools} />

      {/* ── Grade Breakdown (relocated from killed tab — audit Inv. #5) ── */}
      <section id="grade-breakdown" className="sd-section">
        <GradeBreakdownTab
          score_detail={server.score_detail ?? null}
          findings={findings}
        />
      </section>

      {/* ── Framework Posture Matrix (Cluster B Invention #3) ─────────────
          Replaces the legacy OWASP MCP Top 10 grid with a 7-framework ×
          control-status matrix. The component owns its own fetch against
          the new aggregate /compliance endpoint; on 404 / network error it
          falls back to rendering the OWASP grid via the
          `owasp_coverage_fallback` prop, so older API deployments stay
          functional. */}
      <FrameworkPostureMatrix
        slug={slug}
        apiUrl={API_URL}
        owasp_coverage_fallback={server.owasp_coverage ?? null}
      />

      {/* ── Server Profile (Phase 1 — renders nothing if profile absent) ── */}
      <ServerProfileCard profile={server.profile ?? null} />

      {/* ── Attack Chains (renders nothing if no chains) ──── */}
      <AttackChainCard
        chains={server.attack_chains ?? null}
        currentServerId={server.id}
      />

      {/* ── Tabbed Detail Sections ─────────────────────────── */}
      <ServerTabs tabs={tabs} />

      {/* ── Honest Gaps (Invention #4) — what we did NOT analyse ─ */}
      <HonestGaps
        analysis_coverage={server.score_detail?.analysis_coverage ?? null}
        findingsCount={findings.length}
      />

      {/* ── Footer attestation bar ─────────────────────────── */}
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
