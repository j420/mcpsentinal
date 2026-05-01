import React from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import CategoryDeepDivePanel from "@/components/CategoryDeepDivePanel";
import type { CddFinding } from "@/components/cdd-data";
import ServerProfileCard from "@/components/ServerProfileCard";
import type { ServerProfileData } from "@/components/ServerProfileCard";
import AttackChainCard from "@/components/AttackChainCard";
import type { AttackChainItem } from "@/components/AttackChainCard";
import EvidenceSummaryHero from "@/components/EvidenceSummaryHero";
import SignedEvidencePack from "@/components/SignedEvidencePack";
import AttackSurfaceStrip from "@/components/AttackSurfaceStrip";
import FindingsEvidenceTab from "@/components/FindingsEvidenceTab";
import GradeBreakdownTab from "@/components/GradeBreakdownTab";
import VersionHistoryTab from "@/components/VersionHistoryTab";
import FooterAttestationBar from "@/components/FooterAttestationBar";
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

// ── Helpers ───────────────────────────────────────────────────────────────────

const OWASP_NAMES: Record<string, string> = {
  MCP01: "Prompt Injection",
  MCP02: "Tool Poisoning",
  MCP03: "Command Injection",
  MCP04: "Data Exfiltration",
  MCP05: "Privilege Escalation",
  MCP06: "Excessive Permissions",
  MCP07: "Insecure Configuration",
  MCP08: "Dependency Vulnerabilities",
  MCP09: "Logging & Monitoring",
  MCP10: "Supply Chain",
};

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function ServerDetailPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const server = await getServer(slug);

  if (!server) return notFound();

  const findings = server.findings ?? [];
  const tools = server.tools ?? [];
  const cddFindings: CddFinding[] = findings.map((f) => ({
    rule_id: f.rule_id,
    severity: f.severity,
  }));

  // ── Tab panels (rendered as RSC subtrees, passed across the boundary) ─────
  const findingsPanel = (
    <FindingsEvidenceTab findings={findings} scanId={null} />
  );

  const gradeBreakdownPanel = (
    <GradeBreakdownTab
      score_detail={server.score_detail ?? null}
      findings={findings}
    />
  );

  const deepDivePanel = (
    <div id="deep-dive">
      <CategoryDeepDivePanel findings={cddFindings} fullFindings={findings} />
    </div>
  );

  const versionHistoryPanel = <VersionHistoryTab slug={slug} apiUrl={API_URL} />;

  const toolsPanel = (
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

  const tabs: ServerTab[] = [
    {
      id: "findings",
      label: "Findings & Evidence",
      count: findings.length,
      content: findingsPanel,
    },
    {
      id: "grade-breakdown",
      label: "Grade Breakdown",
      content: gradeBreakdownPanel,
    },
    {
      id: "deep-dive",
      label: "Deep Dive",
      content: deepDivePanel,
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
    {
      id: "tools",
      label: "Tools",
      count: tools.length,
      content: toolsPanel,
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

      {/* ── OWASP Coverage (kept exactly as-is) ────────────────────────── */}
      {server.owasp_coverage && Object.keys(server.owasp_coverage).length > 0 && (
        <section id="owasp" className="sd-section">
          <h2 className="sd-section-title">
            OWASP MCP Top 10 Coverage
          </h2>
          <p className="sd-section-sub">Pass = no findings in this category. Fail = issues detected.</p>
          <div className="sd-owasp-grid">
            {Object.entries(server.owasp_coverage).map(([id, clean]) => (
              <div
                key={id}
                className={`sd-owasp-item ${clean ? "sd-owasp-clean" : "sd-owasp-dirty"}`}
              >
                <span className="sd-owasp-indicator" />
                <span className="sd-owasp-id">{id}</span>
                <span className="sd-owasp-name">{OWASP_NAMES[id] ?? id}</span>
                <span className="sd-owasp-status">{clean ? "Pass" : "Fail"}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Server Profile (Phase 1 — renders nothing if profile absent) ── */}
      <ServerProfileCard profile={server.profile ?? null} />

      {/* ── Attack Chains (renders nothing if no chains) ──── */}
      <AttackChainCard
        chains={server.attack_chains ?? null}
        currentServerId={server.id}
      />

      {/* ── Tabbed Detail Sections ─────────────────────────── */}
      <ServerTabs tabs={tabs} />

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
