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

import React from "react";
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
  const { slug } = await params;
  const dd = await getDeepDive(slug);
  if (!dd) return { title: "Server Not Found" };
  const total = dd.coverage.total_findings;
  return {
    title: `${dd.server.name} Security Deep Dive`,
    description:
      `Deep dive into ${dd.server.name}: ${total} finding${total === 1 ? "" : "s"} ` +
      `across ${dd.coverage.total_rules} detection rules. Sub-categories, rules, ` +
      `methodology, and evidence per rule.`,
  };
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
      {/* Phase 3 verdict bar — sticky one-line verdict at the very top.
          Always present (never honest-gapped); falls back to "Awaiting
          scan data" when sparse. */}
      <VerdictBar
        serverName={dd.server.name}
        coverage={dd.coverage}
        categories={dd.categories}
        attackChains={dd.attack_chains}
      />

      {/* Phase 4 lens + density controls — twin pill rows. Sticky-aligned
          with the verdict bar so the controls stay in view while the
          page scrolls. Writes ?lens= / ?view= and localStorage. */}
      <LensDensityControls lens={lens} density={density} />

      {/* Breadcrumb — kept as the only navigation context. The rest of
          the page chrome (hero, signed pack, posture matrix, risk
          boundary, drift, compliance, footer attestation, honest gaps,
          tools, profile card, attack chains, attack surface strip,
          grade breakdown, evidence summary hero) is intentionally not
          mounted on this route per the user's strip-down call. */}
      <nav className="sd-breadcrumb" aria-label="Breadcrumb">
        <a href="/">Home</a>
        <span className="sd-bread-sep" aria-hidden="true">
          /
        </span>
        <a href="/servers">Servers</a>
        <span className="sd-bread-sep" aria-hidden="true">
          /
        </span>
        <span className="sd-bread-current">{dd.server.name}</span>
      </nav>

      {/* Phase 3 hero — server name + coverage line + auto-narrative
          bullets + severity proportional bar. Always renders the name +
          coverage line; bullets and severity bar render only when their
          inputs support them (honest gap). */}
      <HeroBlock
        serverName={dd.server.name}
        coverage={dd.coverage}
        categories={dd.categories}
        attackChains={dd.attack_chains}
      />

      {/* Story-lens augmentations (Phase 2 redesign). Each component
          renders nothing when its data is absent — honest gaps, no
          synthetic placeholders. The reel and surface mount BEFORE the
          taxonomy stack so a regulator's eye lands on the synthesised
          attack stories first, then drills into the per-rule evidence. */}
      <div className="dd-story-lens">
        <KillChainReel
          chains={dd.attack_chains}
          currentServerSlug={dd.server.slug}
        />
        <CapabilitySurface
          node={dd.capability_node}
          edges={dd.risk_edges}
        />
      </div>

      {/* Phase 3 coverage ledger — a first-class section listing every
          rule we couldn't test this scan, grouped by structured reason.
          Renders nothing when no rules are skipped. */}
      <CoverageLedger
        coverage={dd.coverage}
        categories={dd.categories}
      />

      {hasContent ? (
        <DeepDiveLayout
          sidebar={<DeepDiveSidebar categories={dd.categories} />}
          main={
            <div className="dd-main">
              {dd.categories.map((cat) => (
                <CategorySection key={cat.id} cat={cat} />
              ))}
            </div>
          }
        />
      ) : (
        <section className="dd-empty" aria-labelledby="dd-empty-title">
          <h1 id="dd-empty-title" className="dd-empty-title">
            {dd.server.name}
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

      <ProvenanceFooter provenance={dd.provenance} />
    </div>
  );
}
