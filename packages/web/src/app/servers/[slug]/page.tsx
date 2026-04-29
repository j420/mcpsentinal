import React from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import ServerProfileCard from "@/components/ServerProfileCard";
import type { ServerProfileData } from "@/components/ServerProfileCard";
import AttackChainCard from "@/components/AttackChainCard";
import type { AttackChainItem } from "@/components/AttackChainCard";
import TrustSignature from "@/components/TrustSignature";
import AttestationRibbon from "@/components/AttestationRibbon";
import FindingCard, { type FindingForCard } from "@/components/FindingCard";
import AttackSurfaceTab from "@/components/AttackSurfaceTab";
import ServerTabs, { type ServerTab } from "./ServerTabs";
import ComplianceTab from "./ComplianceTab";

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Finding extends FindingForCard {}

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
  owasp_coverage?: Record<string, boolean>;
  total_score_v2?: number | null;
  techniques_v2?: Record<string, string>;
}

interface SourceRef {
  source_name: string;
  external_id: string | null;
  last_synced?: string;
}

interface ScanStages {
  stages: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
  status: string | null;
}

interface DependenciesSummary {
  total: number;
  with_cve: number;
}

interface CorpusEntry {
  fixture_count: number;
  cve_replays: string[];
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
  score_detail?: ScoreDetail | null;
  sources?: SourceRef[];
  scan_stages?: ScanStages | null;
  dependencies_summary?: DependenciesSummary;
  red_team_corpus_links?: Record<string, CorpusEntry>;
  profile?: ServerProfileData | null;
  attack_chains?: AttackChainItem[] | null;
}

interface ScoreHistoryPoint {
  score: number | null;
  recorded_at: string;
  rules_version?: string | null;
}

// ── Data fetching ────────────────────────────────────────────────────────────

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

async function getHistory(slug: string): Promise<ScoreHistoryPoint[]> {
  try {
    const res = await fetch(
      `${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/history`,
      { signal: AbortSignal.timeout(3000) }
    );
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.data) ? data.data : [];
  } catch {
    return [];
  }
}

// ── SEO Metadata ─────────────────────────────────────────────────────────────

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
    description: `Security analysis of ${server.name} MCP server. ${findCount} finding${findCount !== 1 ? "s" : ""} detected with structured evidence chains.`,
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function groupByOwaspThenSeverity(findings: Finding[]) {
  const SEV_ORDER: Record<Finding["severity"], number> = {
    critical: 0, high: 1, medium: 2, low: 3, informational: 4,
  };
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.owasp_category ?? "Uncategorised";
    const arr = groups.get(key) ?? [];
    arr.push(f);
    groups.set(key, arr);
  }
  for (const arr of groups.values()) {
    arr.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  }
  return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b));
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default async function ServerDetailPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const [server, history] = await Promise.all([getServer(slug), getHistory(slug)]);

  if (!server) return notFound();

  const findings = server.findings ?? [];
  const tools = server.tools ?? [];
  const corpus = server.red_team_corpus_links ?? null;

  // The API doesn't yet return a top-level rules_version; the freshest scan
  // carries it. Pull from history (newest first).
  const rulesVersion =
    history.find((h) => h.rules_version)?.rules_version ?? null;

  const groupedFindings = groupByOwaspThenSeverity(findings);
  const findingRuleIds = Array.from(new Set(findings.map((f) => f.rule_id)));

  // ── Findings panel ────────────────────────────────────
  const findingsPanel = (
    <section className="sd-section">
      <header className="fcv2-panel-head">
        <span className="eyebrow-mono">EVIDENCE</span>
        <h2 className="sd-section-title">
          Findings <span className="sd-section-count">{findings.length}</span>
        </h2>
        <p className="sd-section-sub">
          {findings.length === 0
            ? `Clean. No findings emitted by the active rule set across ${tools.length} tool${tools.length === 1 ? "" : "s"}.`
            : `Grouped by OWASP category, then severity. Each card carries a structured evidence chain (source → propagation → sink → mitigation → impact). Expand to see verification steps and remediation.`}
        </p>
      </header>
      {groupedFindings.map(([owaspId, group]) => (
        <div key={owaspId} className="fcv2-group">
          <h3 className="fcv2-group-title eyebrow-mono">
            <span>{owaspId}</span>
            <span className="fcv2-group-count">
              {group.length} finding{group.length === 1 ? "" : "s"}
            </span>
          </h3>
          {group.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              corpus={corpus?.[f.rule_id]}
            />
          ))}
        </div>
      ))}
    </section>
  );

  // ── Tools panel ───────────────────────────────────────
  const toolsPanel = (
    <section className="sd-section">
      <header className="fcv2-panel-head">
        <span className="eyebrow-mono">SURFACE</span>
        <h2 className="sd-section-title">
          Tools <span className="sd-section-count">{tools.length}</span>
        </h2>
        <p className="sd-section-sub">
          Every tool the server exposes via <code>tools/list</code>. Capability tags drive the Attack Surface analysis.
        </p>
      </header>
      {tools.length === 0 ? (
        <p className="sd-section-sub">No tools enumerated for this server.</p>
      ) : (
        <div className="sd-tools-grid">
          {tools.map((tool) => (
            <div key={tool.name} className="sd-tool">
              <div className="sd-tool-name">{tool.name}</div>
              {tool.description && <div className="sd-tool-desc">{tool.description}</div>}
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

  // ── Attack Surface tab (replaces Deep Dive) ──────────
  const attackSurfacePanel = (
    <AttackSurfaceTab
      slug={slug}
      tools={tools}
      findings={findings}
      rules_version={rulesVersion}
      last_scanned_at={server.last_scanned_at}
    />
  );

  const tabs: ServerTab[] = [
    {
      id: "findings",
      label: "Findings",
      count: findings.length,
      content: findingsPanel,
    },
    {
      id: "attack-surface",
      label: "Attack Surface",
      content: attackSurfacePanel,
    },
    {
      id: "compliance",
      label: "Compliance",
      content: <ComplianceTab slug={slug} />,
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

      {/* ── 1. Trust Signature (verdict) ──────────────────── */}
      <TrustSignature
        name={server.name}
        description={server.description}
        author={server.author}
        category={server.category}
        language={server.language}
        license={server.license}
        server_version={server.server_version}
        github_url={server.github_url}
        npm_package={server.npm_package}
        pypi_package={server.pypi_package}
        connection_status={server.connection_status}
        last_scanned_at={server.last_scanned_at}
        rules_version={rulesVersion}
        score_detail={server.score_detail ?? null}
        history={history}
      />

      {/* ── 2. Attestation Ribbon ("How we know") ─────────── */}
      <AttestationRibbon
        rules_version={rulesVersion}
        scan_stages={server.scan_stages ?? null}
        sources={server.sources ?? []}
        tools={tools}
        red_team_corpus_links={corpus}
        finding_rule_ids={findingRuleIds}
        connection_status={server.connection_status}
      />

      {/* ── 3. Lineage (capability profile + attack chains) ── */}
      <ServerProfileCard profile={server.profile ?? null} />
      <AttackChainCard
        chains={server.attack_chains ?? null}
        currentServerId={server.id}
      />

      {/* ── 4. Tabs (Findings · Attack Surface · Compliance · Tools) ── */}
      <ServerTabs tabs={tabs} />
    </div>
  );
}
