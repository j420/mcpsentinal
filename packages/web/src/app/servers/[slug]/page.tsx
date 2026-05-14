/**
 * /servers/[slug] — five-entity cascade.
 *
 * One page, one job: surface findings (and the proofs behind them) as
 * the page's hero. Categories → Sub-categories → Rules → Tests → Evidence.
 * Everything else (audit panels, lens controls, mobile FAB, kill-chain
 * reel, capability surface, coverage ledger, forensic drawer, sidebar)
 * has been removed. The verdict + counts live in a sticky header; the
 * skipped rules live in a single collapsed block at the bottom that
 * doubles as the "give us more context" CTA; the clean categories live
 * in a one-row footer underneath.
 *
 * Rules + evidence chains are the hero. Category and sub-category
 * dividers are typographic — no card chrome.
 *
 * All derivation happens server-side in `buildViewModel`. Client
 * components are pure renderers. `<SectionBoundary/>` wraps each major
 * section so a render exception in one block degrades to a quiet
 * skeleton instead of taking down the whole route.
 */

import React, { Fragment } from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import SectionBoundary from "@/components/SectionBoundary";
import HeaderRail from "./header-rail";
import CategoryRail from "./category-rail";
import SubCategoryRail from "./sub-category-rail";
import RuleCard from "./rule-card";
import SkippedRulesBlock from "./skipped-rules-block";
import CleanCategoriesFooter from "./clean-categories-footer";
import { buildViewModel } from "./view-model";
import type { DeepDiveResponse, DeepDiveData } from "@/lib/deep-dive";
import "./findings-view.css";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

async function getDeepDive(slug: string): Promise<DeepDiveData | null> {
  try {
    const res = await fetch(
      `${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/deep-dive`,
      { signal: AbortSignal.timeout(4000), next: { revalidate: 300 } },
    );
    if (!res.ok) return null;
    const body = (await res.json()) as DeepDiveResponse;
    return body.data ?? null;
  } catch {
    return null;
  }
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  try {
    const { slug } = await params;
    const dd = await getDeepDive(slug);
    if (!dd) return { title: "Server Not Found" };
    const name = dd.server?.name ?? slug;
    const totalFindings = Number(dd.coverage?.total_findings) || 0;
    const totalRules = Number(dd.coverage?.total_rules) || 0;
    return {
      title: `${name} security findings`,
      description: `${totalFindings} finding${
        totalFindings === 1 ? "" : "s"
      } across ${totalRules} detection rules. Sub-categories, rules, tests, and evidence chains for ${name}.`,
    };
  } catch {
    return { title: "Security findings" };
  }
}

export default async function ServerDetailPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const data = await getDeepDive(slug);
  if (!data) return notFound();

  const vm = buildViewModel(data);
  const apiOrigin = API_URL;
  const provenance = data.provenance ?? null;

  return (
    <div className="fv-page">
      <SectionBoundary section="header" label="Header">
        <HeaderRail
          vm={vm}
          server={data.server}
          provenance={provenance}
          apiOrigin={apiOrigin}
        />
      </SectionBoundary>

      <main className="fv-main">
        {vm.findingsByCategory.length === 0 ? (
          <section className="fv-empty" aria-labelledby="fv-empty-h">
            <h2 id="fv-empty-h" className="fv-empty-title">
              No findings on file
            </h2>
            <p>
              {vm.counts.passed > 0
                ? `${vm.counts.passed} rule${vm.counts.passed === 1 ? "" : "s"} tested cleanly.`
                : "Deep-dive data is not yet on file for this server."}
              {vm.counts.skipped > 0 &&
                ` ${vm.counts.skipped} rule${
                  vm.counts.skipped === 1 ? "" : "s"
                } need more context — see below.`}
            </p>
          </section>
        ) : (
          vm.findingsByCategory.map((cat) => (
            <SectionBoundary
              key={cat.id}
              section={`category-${cat.id}`}
              label={cat.title}
            >
              <CategoryRail
                id={cat.id}
                title={cat.title}
                worstSeverity={cat.worstSeverity}
                findingCount={cat.findingCount}
                frameworks={cat.frameworks}
              />
              {cat.subCategories.map((sub) => (
                <Fragment key={sub.id}>
                  <SubCategoryRail
                    id={sub.id}
                    title={sub.title}
                    findingCount={sub.findingCount}
                  />
                  {sub.rules.map((rule) => (
                    <RuleCard key={rule.rule_id} rule={rule} />
                  ))}
                </Fragment>
              ))}
            </SectionBoundary>
          ))
        )}

        {vm.skipped.length > 0 && (
          <SectionBoundary section="skipped" label="Skipped rules">
            <SkippedRulesBlock groups={vm.skipped} />
          </SectionBoundary>
        )}

        {vm.cleanCategories.length > 0 && (
          <SectionBoundary section="clean" label="Clean categories">
            <CleanCategoriesFooter categories={vm.cleanCategories} />
          </SectionBoundary>
        )}
      </main>
    </div>
  );
}
