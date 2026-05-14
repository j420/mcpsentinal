/**
 * /servers/[slug] — five-entity cascade with navigable layout.
 *
 * The page shows every rule in our taxonomy, but it's navigable rather
 * than a single 50,000-pixel scroll. Layout:
 *
 *   ┌────────────────────────────────────────────────────────────────┐
 *   │  Sticky HeaderRail                                              │
 *   ├──────────────────┬──────────────────────────────────────────────┤
 *   │  Sticky TocSidebar│ Cascade intro                                │
 *   │  (categories,     │ Coverage-gaps banner (if any skipped)        │
 *   │   severity dots,  │                                              │
 *   │   counts)         │ <details> per category — open when the       │
 *   │                   │   category has findings, closed when clean.  │
 *   │                   │ Inside open category:                        │
 *   │                   │   sub-category rails + rules:                │
 *   │                   │     • findings → full RuleCard               │
 *   │                   │     • passed   → CompactRuleRow (expandable) │
 *   │                   │     • skipped  → CompactRuleRow (expandable) │
 *   └──────────────────┴──────────────────────────────────────────────┘
 *
 * A <HashOpener/> client island ensures clicking a TOC link auto-opens
 * the matching `<details>` block and scrolls into view.
 */

import React, { Fragment } from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import SectionBoundary from "@/components/SectionBoundary";
import HeaderRail from "./header-rail";
import TocSidebar from "./toc-sidebar";
import CategoryRail from "./category-rail";
import SubCategoryRail from "./sub-category-rail";
import RuleCard from "./rule-card";
import CompactRuleRow from "./compact-rule-row";
import SkippedRulesBlock from "./skipped-rules-block";
import HashOpener from "./hash-opener";
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

      <div className="fv-layout">
        <SectionBoundary section="toc" label="Table of contents">
          <TocSidebar cascade={vm.cascade} counts={vm.counts} />
        </SectionBoundary>

        <main className="fv-main">
          <section className="fv-cascade-intro" aria-labelledby="fv-cascade-intro-h">
            <h2 id="fv-cascade-intro-h" className="fv-cascade-intro-h">
              The five-entity audit cascade
            </h2>
            <p className="fv-cascade-intro-body">
              Every rule in our 164-rule taxonomy is reported below — grouped
              by <strong>category</strong> and <strong>sub-category</strong>,
              with its <strong>test methodology</strong> always visible and a{" "}
              <strong>structured evidence chain</strong> for every finding.
              Categories with findings open automatically; clean categories
              stay collapsed so the page is navigable. Click any category to
              expand it, or use the table of contents on the left.
            </p>
          </section>

          {vm.skipped.length > 0 && (
            <SectionBoundary section="coverage-gaps" label="Coverage gaps">
              <SkippedRulesBlock groups={vm.skipped} />
            </SectionBoundary>
          )}

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
            vm.cascade.map((cat) => {
              const hasFindings = cat.findingCount > 0;
              return (
                <SectionBoundary
                  key={cat.id}
                  section={`category-${cat.id}`}
                  label={cat.title}
                >
                  <details className="fv-cat-box" open={hasFindings}>
                    <summary className="fv-cat-summary">
                      <span className="fv-cat-summary-chev" aria-hidden="true">
                        <svg viewBox="0 0 16 16" width="14" height="14" fill="none">
                          <path
                            d="M6 4l4 4-4 4"
                            stroke="currentColor"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        </svg>
                      </span>
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
                    </summary>

                    <div className="fv-cat-body">
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
                          {sub.rules.map((rule) =>
                            rule.status === "findings" ? (
                              <RuleCard key={rule.rule_id} rule={rule} />
                            ) : (
                              <CompactRuleRow key={rule.rule_id} rule={rule} />
                            ),
                          )}
                        </Fragment>
                      ))}
                    </div>
                  </details>
                </SectionBoundary>
              );
            })
          )}
        </main>
      </div>

      <HashOpener />
    </div>
  );
}
