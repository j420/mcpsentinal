/**
 * /servers/[slug] — Deep Dive only.
 *
 * Strip-down per user product call:
 *   "remove everything from the servers page, i just need to see the
 *    deep dive with the details of sub-categories/rules/tests/evidences"
 *
 * The page is now a thin shell: one fetch (`/deep-dive`), breadcrumb,
 * and the long-scroll Deep Dive layout (sidebar TOC + main column of
 * `<CategorySection/>` → `<SubCategorySection/>` → `<RuleEvidenceCard/>`).
 *
 * Cluster A/B/C inventions (signed pack download, posture matrix,
 * risk boundary, drift, compliance findings, evidence summary hero,
 * footer attestation bar, etc.) are NOT mounted here — their components
 * still ship in `packages/web/src/components/` and remain available for
 * future surfaces, but no path on `/servers/[slug]` renders them.
 *
 * Page-level dynamic rendering: deliberate. The route consumes a
 * server-side fetch on every request; Next 15 marks it dynamic
 * automatically. We do NOT add `force-dynamic` (Cluster B M1 lesson).
 */

import React, { Suspense } from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import DeepDiveLayout from "@/components/DeepDiveLayout";
import CategorySection from "@/components/CategorySection";
import DeepDiveSidebar from "@/components/DeepDiveSidebar";
import KillChainReel from "@/components/KillChainReel";
import CapabilitySurface from "@/components/CapabilitySurface";
import ProvenanceFooter from "@/components/ProvenanceFooter";
import HeroBlock from "@/components/HeroBlock";
import CoverageLedger from "@/components/CoverageLedger";
import LensDensityControls from "@/components/LensDensityControls";
// Phase 3 — Senior Security Architect verdict layer. The 8 panels render
// the audit summary at the top of the page; the existing CategorySection
// cascade is demoted into a <details> "Forensic Detail" appendix so
// technical depth stays one click away.
import VerdictPanel from "@/components/audit/VerdictPanel";
import RecommendationPanel from "@/components/audit/RecommendationPanel";
import ScoreForecasterPanel from "@/components/audit/ScoreForecasterPanel";
import TestingDepthPanel from "@/components/audit/TestingDepthPanel";
import RiskSummaryPanel from "@/components/audit/RiskSummaryPanel";
import AttackIntelPanel from "@/components/audit/AttackIntelPanel";
import GapsPanel from "@/components/audit/GapsPanel";
import ConfidencePanel from "@/components/audit/ConfidencePanel";
import EvidenceTrustPanel from "@/components/audit/EvidenceTrustPanel";
// `resolveLensDensity` lives in lib/ (server-callable). Importing it from
// the "use client" controls module — as the original code did — produces
// a Next-15 boundary-violation crash:
//   "Attempted to call resolveLensDensity() from the server but
//    resolveLensDensity is on the client." (digest 1244316665)
// The error is framework-level and bypasses every <SectionBoundary/>.
import { resolveLensDensity } from "@/lib/lens-density";
import SectionBoundary from "@/components/SectionBoundary";
import HoverTraceController from "@/components/HoverTraceController";
import ForensicDrawer from "@/components/ForensicDrawer";
import ComplianceLensView from "@/components/ComplianceLensView";
import MobileViewportStripe from "@/components/MobileViewportStripe";
import MobileNavigateFAB from "@/components/MobileNavigateFAB";
import type { DeepDiveResponse, DeepDiveData } from "@/lib/deep-dive";

// Public api origin for receipt-URL construction. NEXT_PUBLIC_API_URL
// is read at build / SSR time and embedded for the client drawer to use.
const PUBLIC_API_ORIGIN =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Data fetch ──────────────────────────────────────────────────────────

/**
 * Fetch the Deep Dive aggregate. Returns null on any failure
 * (server unknown, network timeout, parse error). The page treats null
 * as 404 — there is no other reason to land on `/servers/<slug>` once
 * everything besides Deep Dive has been stripped from the route.
 *
 * `next: { revalidate: 300 }` matches the API's `Cache-Control: public,
 * max-age=300, stale-while-revalidate=60` so a CISO refreshing the page
 * sees identical bytes within the 5-minute window.
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
    return body.data ?? null;
  } catch {
    return null;
  }
}

// ── SEO metadata ────────────────────────────────────────────────────────

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  try {
    const { slug } = await params;
    const dd = await getDeepDive(slug);
    if (!dd) return { title: "Server Not Found" };
    // Defensive — production data may have a null / partial coverage
    // object. We never want metadata generation to throw, since that
    // would block the page from rendering even though the page itself
    // is fully resilient.
    const name = dd.server?.name ?? slug;
    const total = Number(dd.coverage?.total_findings) || 0;
    const totalRules = Number(dd.coverage?.total_rules) || 0;
    return {
      title: `${name} Security Deep Dive`,
      description:
        `Deep dive into ${name}: ${total} finding${total === 1 ? "" : "s"} ` +
        `across ${totalRules} detection rules. Sub-categories, rules, ` +
        `methodology, and evidence per rule.`,
    };
  } catch {
    return { title: "Security Deep Dive" };
  }
}

// ── Page ────────────────────────────────────────────────────────────────

export default async function ServerDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ slug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { slug } = await params;
  const sp = await searchParams;
  const dd = await getDeepDive(slug);
  if (!dd) return notFound();

  // Defensive coercion of every nested array on the deep-dive payload.
  // The TS types say these are required, but at runtime an older api
  // deploy or a partial-response edge case can land here with undefined
  // / null fields. The page MUST NOT throw at the server-component
  // level — that bypasses every per-section boundary and triggers the
  // route-level error.tsx (HTTP 500). Coercing once up front means the
  // rest of the render reads from arrays that are guaranteed to exist.
  const safeCategories = Array.isArray(dd.categories) ? dd.categories : [];
  const safeAttackChains = Array.isArray(dd.attack_chains)
    ? dd.attack_chains
    : undefined;
  const safeRiskEdges = Array.isArray(dd.risk_edges) ? dd.risk_edges : undefined;
  // Phase 3.1 — audit summary coercion. Stale SWR cache entries from
  // before the Phase 2 wire-up will not carry `audit_summary`. A pre-
  // 014_v2_score_persistence scan also produces a degraded summary
  // (verdict pill conservative, recommendation NO, gaps empty). In both
  // cases the panels render their own empty state — we just need to
  // ensure the field exists as either a structured object or null so
  // panel props are well-typed.
  const safeAudit =
    dd.audit_summary && typeof dd.audit_summary === "object"
      ? dd.audit_summary
      : null;
  const hasContent = safeCategories.length > 0;
  // Phase 4.4 kill-switch — `MCPS_AUDIT_LAYOUT_DISABLED=1` reverts the
  // page to the pre-redesign layout (audit panels skipped; detail
  // cascade rendered top-level). Documented in agent_docs/architecture.md
  // Recovery section.
  const auditLayoutDisabled = process.env.MCPS_AUDIT_LAYOUT_DISABLED === "1";

  // Phase 4 lens + density. Resolved server-side from the URL so SSR and
  // first paint match the client's eventual hydration — no flash. The
  // client-side controls component re-syncs from localStorage on mount
  // when the URL omits the params and the user has a stored preference.
  const { lens, density } = resolveLensDensity(sp);

  return (
    <div
      className="dd-page dd-page-stripped"
      data-lens={lens}
      data-density={density}
    >
      {/* Phase 5 — mobile viewport stripe (4-px severity-coloured strip
          pinned to the very top of the viewport). Hidden via CSS on
          desktop. Always-visible status the user can never miss while
          scrolling on a phone. */}
      <SectionBoundary section="mobile-stripe" label="Mobile severity strip">
        <MobileViewportStripe coverage={dd.coverage} />
      </SectionBoundary>

      {/* Phase 5 — page-wide hover-to-trace controller. Mounts once per
          page; emits no markup. Delegated mouseover/focusin listener
          wires every [data-trace] element into the same highlight cluster
          so a buyer/CISO can hover a tool, capability, server, rule, cve,
          kill-chain id, pattern, or framework control and see every
          reference light up across the page. */}
      <HoverTraceController />

      {/* Each major section is wrapped in its own SectionBoundary so a
          single render exception degrades to a quiet skeleton instead of
          taking down the whole page via the route-level error.tsx. The
          `section` prop lands in a hidden data attribute on the fallback
          so an operator can pinpoint which block failed without server
          logs. */}

      {/* Phase 3.4 — view controls + breadcrumb stay above the fold so
          the user can switch lens / density / navigate up regardless of
          which layout (audit-summary or kill-switch) is active. */}
      <SectionBoundary section="lens-density-controls" label="View controls">
        <Suspense fallback={<div className="lds-controls-skeleton" aria-hidden="true" />}>
          <LensDensityControls lens={lens} density={density} />
        </Suspense>
      </SectionBoundary>

      <nav className="sd-breadcrumb" aria-label="Breadcrumb">
        <a href="/">Home</a>
        <span className="sd-bread-sep" aria-hidden="true">/</span>
        <a href="/servers">Servers</a>
        <span className="sd-bread-sep" aria-hidden="true">/</span>
        <span className="sd-bread-current">{dd.server?.name ?? slug}</span>
        {dd.provenance?.scan_id && (
          <span
            className="sd-bread-scan"
            title={
              dd.provenance.scan_completed_at
                ? `Scan ${dd.provenance.scan_id} · completed ${dd.provenance.scan_completed_at}`
                : `Scan ${dd.provenance.scan_id}`
            }
            aria-label="Scan reference"
          >
            <span className="sd-bread-scan-eyebrow">Scan</span>
            <code className="sd-bread-scan-id">
              {dd.provenance.scan_id.slice(0, 8)}
            </code>
          </span>
        )}
      </nav>

      <SectionBoundary section="hero" label="Hero">
        <HeroBlock
          serverName={dd.server?.name ?? slug}
          coverage={dd.coverage}
          categories={safeCategories}
          attackChains={safeAttackChains}
          provenance={dd.provenance}
        />
      </SectionBoundary>

      {/* ── Audit Summary layer (Phase 2/3 redesign) ──────────────────
          Renders the 8-section Senior Security Architect verdict at the
          top. Falls back to the pre-redesign layout when:
            (a) MCPS_AUDIT_LAYOUT_DISABLED=1 is set in the env, OR
            (b) the deep-dive payload omits audit_summary (stale cache
                during the rollout window).
          Each panel is wrapped in its own SectionBoundary so a render
          exception inside one panel degrades gracefully. */}
      {!auditLayoutDisabled && safeAudit && (
        <div className="audit-summary-stack" data-audit-layout="v1">
          <SectionBoundary section="audit-verdict" label="Verdict">
            <VerdictPanel verdict={safeAudit.verdict} />
          </SectionBoundary>
          <SectionBoundary section="audit-recommendation" label="Recommendation">
            <RecommendationPanel recommendation={safeAudit.recommendation} />
          </SectionBoundary>
          {/* Phase X — Score Forecaster. Interactive "what if I fix these
              findings?" panel. Sits between Recommendation and Testing
              Depth so the reading order is verdict → what to do →
              concrete fix impact → coverage proof. */}
          <SectionBoundary section="audit-forecaster" label="Score forecaster">
            <ScoreForecasterPanel
              currentScore={safeAudit.verdict.score}
              categories={safeCategories}
            />
          </SectionBoundary>
          <SectionBoundary section="audit-testing-depth" label="Testing depth">
            <TestingDepthPanel depth={safeAudit.testing_depth} />
          </SectionBoundary>
          <SectionBoundary section="audit-risk-summary" label="Risk by category">
            <RiskSummaryPanel summary={safeAudit.risk_summary} />
          </SectionBoundary>
          <SectionBoundary section="audit-attack-intel" label="Attack intelligence">
            <AttackIntelPanel intel={safeAudit.attack_intelligence} />
          </SectionBoundary>
          <SectionBoundary section="audit-gaps" label="Gaps">
            <GapsPanel gaps={safeAudit.gaps} />
          </SectionBoundary>
          <SectionBoundary section="audit-confidence" label="Confidence">
            <ConfidencePanel confidence={safeAudit.confidence} />
          </SectionBoundary>
          <SectionBoundary section="audit-evidence-trust" label="Evidence trust">
            <EvidenceTrustPanel
              trust={safeAudit.evidence_trust}
              apiOrigin={PUBLIC_API_ORIGIN}
            />
          </SectionBoundary>
        </div>
      )}

      {/* ── Forensic Detail (drill-down) ────────────────────────────
          When the audit layout is active, the detail cascade lives
          inside a closed <details> so technical depth is one click
          away — preserved verbatim per the user's hard requirement
          ("Do NOT remove technical depth").
          When the kill-switch is engaged or audit_summary is absent,
          the same content renders top-level (the pre-redesign layout). */}
      {(() => {
        const detail = (
          <>
            <div className="dd-story-lens">
              <SectionBoundary section="kill-chain-reel" label="Attack stories">
                <KillChainReel
                  chains={safeAttackChains}
                  currentServerSlug={dd.server?.slug ?? slug}
                />
              </SectionBoundary>
              <SectionBoundary section="capability-surface" label="Capability surface">
                <CapabilitySurface
                  node={dd.capability_node}
                  edges={safeRiskEdges}
                />
              </SectionBoundary>
            </div>

            <SectionBoundary section="coverage-ledger" label="Coverage ledger">
              <CoverageLedger
                coverage={dd.coverage}
                categories={safeCategories}
              />
            </SectionBoundary>

            {lens === "compliance" ? (
              <SectionBoundary section="compliance-view" label="Compliance posture">
                <ComplianceLensView
                  serverSlug={dd.server?.slug ?? slug}
                  categories={safeCategories}
                  apiOrigin={PUBLIC_API_ORIGIN}
                />
              </SectionBoundary>
            ) : (
              <SectionBoundary section="taxonomy" label="Per-rule taxonomy">
                {hasContent ? (
                  <DeepDiveLayout
                    sidebar={
                      <SectionBoundary section="taxonomy-sidebar" label="Sidebar">
                        <Suspense fallback={null}>
                          <DeepDiveSidebar categories={safeCategories} />
                        </Suspense>
                      </SectionBoundary>
                    }
                    main={
                      <div className="dd-main">
                        {safeCategories.map((cat, ci) => (
                          <SectionBoundary
                            key={cat?.id ?? `cat-${ci}`}
                            section={`category-${cat?.id ?? "unknown"}`}
                            label={cat?.title ?? cat?.id ?? "Category"}
                          >
                            <CategorySection cat={cat} />
                          </SectionBoundary>
                        ))}
                      </div>
                    }
                  />
                ) : (
                  <section className="dd-empty" aria-labelledby="dd-empty-title">
                    <h1 id="dd-empty-title" className="dd-empty-title">
                      {dd.server?.name ?? slug}
                    </h1>
                    <p className="dd-empty-msg">
                      Deep-dive evidence is not yet on file for this server. The
                      attack-vector taxonomy and rule-methodology manifest data
                      sources may not have been wired for this scan. Check back
                      after the next scheduled scan, or contact the registry
                      maintainers.
                    </p>
                  </section>
                )}
              </SectionBoundary>
            )}

            <SectionBoundary section="provenance" label="Provenance footer">
              <ProvenanceFooter provenance={dd.provenance} />
            </SectionBoundary>
          </>
        );

        // When the audit layout is active, demote the detail cascade into
        // a closed <details>. Otherwise render top-level (kill-switch path).
        if (!auditLayoutDisabled && safeAudit) {
          return (
            <details className="audit-forensic-detail">
              <summary className="audit-forensic-detail-summary">
                Forensic detail — every rule, sub-category, finding, and
                evidence chain
              </summary>
              <p className="audit-forensic-detail-hint">
                Drill-down view of the same data the audit summary above is
                derived from. Open this when you need to inspect a specific
                rule's chain, framework cross-walk, or backing data.
              </p>
              {detail}
            </details>
          );
        }
        return detail;
      })()}

      {/* Phase 5 — Forensic drawer. Mounts once at the page root; opens
          when the URL carries `?finding=<id>`. Renders nothing when the
          param is absent. Inside its own SectionBoundary so a render
          exception doesn't cascade. */}
      <SectionBoundary section="forensic-drawer" label="Forensic view">
        <Suspense fallback={null}>
          <ForensicDrawer
            serverSlug={dd.server?.slug ?? slug}
            serverName={dd.server?.name ?? slug}
            categories={safeCategories}
            provenance={dd.provenance}
            apiOrigin={PUBLIC_API_ORIGIN}
          />
        </Suspense>
      </SectionBoundary>

      {/* Phase 5 — mobile navigate FAB. Hidden via CSS above 720px;
          appears once the user scrolls past the verdict bar. Opens a
          bottom-sheet TOC anchored to each section's stable id. Uses
          useSearchParams so wrapped in Suspense per Next 15. */}
      <SectionBoundary section="mobile-navigate-fab" label="Mobile navigate">
        <Suspense fallback={null}>
          <MobileNavigateFAB
            categories={safeCategories}
            lens={lens}
            hasChains={
              Array.isArray(safeAttackChains) && safeAttackChains.length > 0
            }
            hasSurface={Boolean(dd.capability_node)}
            hasCoverageLedger={(dd.coverage?.rules_skipped_no_data ?? 0) > 0}
          />
        </Suspense>
      </SectionBoundary>
    </div>
  );
}
