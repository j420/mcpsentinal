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
import VerdictBar from "@/components/VerdictBar";
import HeroBlock from "@/components/HeroBlock";
import CoverageLedger from "@/components/CoverageLedger";
import LensDensityControls, {
  resolveLensDensity,
} from "@/components/LensDensityControls";
import SectionBoundary from "@/components/SectionBoundary";
import type { DeepDiveResponse, DeepDiveData } from "@/lib/deep-dive";

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

  const hasContent = dd.categories.length > 0;

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
      {/* Each major section is wrapped in its own SectionBoundary so a
          single render exception degrades to a quiet skeleton instead of
          taking down the whole page via the route-level error.tsx. The
          `section` prop lands in a hidden data attribute on the fallback
          so an operator can pinpoint which block failed without server
          logs. */}

      <SectionBoundary section="verdict-bar" label="Verdict bar">
        <VerdictBar
          serverName={dd.server?.name ?? slug}
          coverage={dd.coverage}
          categories={dd.categories}
          attackChains={dd.attack_chains}
        />
      </SectionBoundary>

      {/* Suspense boundary required by Next 15 because the client
          component reads useSearchParams. SectionBoundary catches any
          render exception inside the controls. */}
      <SectionBoundary section="lens-density-controls" label="View controls">
        <Suspense fallback={<div className="lds-controls-skeleton" aria-hidden="true" />}>
          <LensDensityControls lens={lens} density={density} />
        </Suspense>
      </SectionBoundary>

      <nav className="sd-breadcrumb" aria-label="Breadcrumb">
        <a href="/">Home</a>
        <span className="sd-bread-sep" aria-hidden="true">
          /
        </span>
        <a href="/servers">Servers</a>
        <span className="sd-bread-sep" aria-hidden="true">
          /
        </span>
        <span className="sd-bread-current">{dd.server?.name ?? slug}</span>
      </nav>

      <SectionBoundary section="hero" label="Hero">
        <HeroBlock
          serverName={dd.server?.name ?? slug}
          coverage={dd.coverage}
          categories={dd.categories}
          attackChains={dd.attack_chains}
        />
      </SectionBoundary>

      <div className="dd-story-lens">
        <SectionBoundary section="kill-chain-reel" label="Attack stories">
          <KillChainReel
            chains={dd.attack_chains}
            currentServerSlug={dd.server?.slug ?? slug}
          />
        </SectionBoundary>
        <SectionBoundary section="capability-surface" label="Capability surface">
          <CapabilitySurface
            node={dd.capability_node}
            edges={dd.risk_edges}
          />
        </SectionBoundary>
      </div>

      <SectionBoundary section="coverage-ledger" label="Coverage ledger">
        <CoverageLedger
          coverage={dd.coverage}
          categories={dd.categories}
        />
      </SectionBoundary>

      <SectionBoundary section="taxonomy" label="Per-rule taxonomy">
        {hasContent ? (
          <DeepDiveLayout
            sidebar={
              <SectionBoundary section="taxonomy-sidebar" label="Sidebar">
                <Suspense fallback={null}>
                  <DeepDiveSidebar categories={dd.categories} />
                </Suspense>
              </SectionBoundary>
            }
            main={
              <div className="dd-main">
                {dd.categories.map((cat) => (
                  <SectionBoundary
                    key={cat.id}
                    section={`category-${cat.id ?? "unknown"}`}
                    label={cat.title ?? cat.id ?? "Category"}
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

      <SectionBoundary section="provenance" label="Provenance footer">
        <ProvenanceFooter provenance={dd.provenance} />
      </SectionBoundary>
    </div>
  );
}
