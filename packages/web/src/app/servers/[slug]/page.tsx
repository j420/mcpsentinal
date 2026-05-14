/**
 * /servers/[slug] — five-entity cascade, complete.
 *
 * One page, one job: render the testing taxonomy in full for every
 * server. Categories → Sub-categories → Rules → Tests → Evidence.
 * Every rule renders regardless of status:
 *   - findings → full hero card with vertical evidence cascade
 *   - passed   → medium card with Tests visible + "Tested cleanly" note
 *   - skipped  → medium card with Tests visible + "Needs X" CTA
 *
 * The page IS the proof of work. A clean server still shows what was
 * tested, how it was tested, and that nothing fired. A finding-heavy
 * server surfaces the structured proof chain for each finding.
 *
 * The verdict + counts live in a sticky header. All derivation happens
 * server-side in `buildViewModel`. Client components are pure
 * renderers. `<SectionBoundary/>` wraps each major section so a render
 * exception in one block degrades to a quiet skeleton instead of
 * taking down the whole route.
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
      title: `${name} — security audit`,
      description: `Full five-entity audit cascade for ${name}: ${totalRules} rules tested, ${totalFindings} finding${
        totalFindings === 1 ? "" : "s"
      }. Categories, sub-categories, rule-by-rule test methodology, and structured evidence chains for every finding.`,
    };
  } catch {
    return { title: "Security audit" };
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
        {/* Coverage-gaps banner — slim CTA near the top when we are
            missing inputs that block tests. Always above the cascade so
            the reader sees the gap-context before they scroll. */}
        {vm.skipped.length > 0 && (
          <SectionBoundary section="coverage-gaps" label="Coverage gaps">
            <SkippedRulesBlock groups={vm.skipped} />
          </SectionBoundary>
        )}

        {/* Page-level explainer so the cascade is self-describing. */}
        <section
          className="fv-cascade-intro"
          aria-labelledby="fv-cascade-intro-h"
        >
          <h2 id="fv-cascade-intro-h" className="fv-cascade-intro-h">
            The five-entity audit cascade
          </h2>
          <p className="fv-cascade-intro-body">
            Every rule in our 164-rule taxonomy is reported below — grouped
            by <strong>category</strong> and <strong>sub-category</strong>,
            with its <strong>test methodology</strong> always visible and a{" "}
            <strong>structured evidence chain</strong> for every finding.
            Rules that tested cleanly say so; rules we could not run say
            what they would need.
          </p>
        </section>

        {vm.cascade.length === 0 ? (
          <section className="fv-empty" aria-labelledby="fv-empty-h">
            <h2 id="fv-empty-h" className="fv-empty-title">
              Deep-dive data not yet on file
            </h2>
            <p>
              We have not yet ingested rule-level results for this server.
              Check back after the next scheduled scan, or contact the
              registry maintainers.
            </p>
          </section>
        ) : (
          vm.cascade.map((cat) => (
            <SectionBoundary
              key={cat.id}
              section={`category-${cat.id}`}
              label={cat.title}
            >
              <CategoryRail
                id={cat.id}
                title={cat.title}
                summary={cat.summary}
                worstSeverity={cat.worstSeverity ?? "informational"}
                findingCount={cat.findingCount}
                ruleCount={cat.ruleCounts.total}
                severity={cat.severity}
                frameworks={cat.frameworks}
              />
              {cat.subCategories.map((sub) => (
                <Fragment key={sub.id}>
                  <SubCategoryRail
                    id={sub.id}
                    title={sub.title}
                    summary={sub.summary}
                    worstSeverity={sub.worstSeverity ?? "informational"}
                    findingCount={sub.findingCount}
                    ruleCount={sub.rules.length}
                    severity={sub.severity}
                  />
                  {sub.rules.map((rule) => (
                    <RuleCard key={rule.rule_id} rule={rule} />
                  ))}
                </Fragment>
              ))}
            </SectionBoundary>
          ))
        )}
      </main>
    </div>
  );
}
