// @vitest-environment jsdom
/**
 * Partial-data resilience tests.
 *
 * Production saw a server-side crash when the deployed api was older
 * than the deployed web (Phase 1 backend additives not yet rolled out).
 * Each new component must therefore tolerate ANY field being absent /
 * malformed and never throw at render. These tests feed deliberately
 * partial / malformed payloads that pass TS but can occur at runtime.
 */

import { describe, expect, it } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import { buildAutoNarrative, buildVerdictHeadline } from "@/lib/auto-narrative";
import HeroBlock from "../components/HeroBlock";
import CoverageLedger from "../components/CoverageLedger";
import KillChainReel from "../components/KillChainReel";
import CapabilitySurface from "../components/CapabilitySurface";

// Cast escape hatch — these inputs deliberately violate the TS contract
// to simulate a runtime mismatch. The tests assert that render survives
// the violation (no throw) and produces sensible (empty / fallback) UI.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const bad = (v: any) => v as any;

describe("AutoNarrative — partial / malformed inputs do not throw", () => {
  it("missing severity_breakdown", () => {
    expect(() =>
      buildAutoNarrative({
        coverage: bad({
          coverage_band: null,
          total_rules: 10,
          rules_executed: 8,
          rules_skipped_no_data: 0,
          rules_with_findings: 1,
          total_findings: 1,
          // severity_breakdown OMITTED
        }),
        categories: [],
        attackChains: [],
      }),
    ).not.toThrow();
  });

  it("category missing sub_categories", () => {
    expect(() =>
      buildAutoNarrative({
        coverage: undefined,
        categories: [
          bad({
            id: "lethal-trifecta",
            title: "Lethal Trifecta",
            // sub_categories OMITTED
            // counts OMITTED
          }),
        ],
        attackChains: [],
      }),
    ).not.toThrow();
  });

  it("kill chain missing exploitability_overall (NaN-trap)", () => {
    expect(() =>
      buildAutoNarrative({
        coverage: undefined,
        categories: [],
        attackChains: [
          bad({
            chain_id: "x",
            kill_chain_id: "KC01",
            // exploitability_overall OMITTED
            // exploitability_rating OMITTED
            // kill_chain_name OMITTED
            // steps OMITTED
          }),
        ],
      }),
    ).not.toThrow();
  });

  it("verdict headline never throws on an empty/null shape", () => {
    expect(() => buildVerdictHeadline({} as never)).not.toThrow();
    expect(() =>
      buildVerdictHeadline({
        coverage: undefined,
        categories: undefined,
        attackChains: undefined,
      }),
    ).not.toThrow();
  });
});

describe("HeroBlock — partial coverage does not throw", () => {
  it("renders without severity_breakdown", () => {
    expect(() =>
      render(
        <HeroBlock
          serverName="demo"
          coverage={bad({
            coverage_band: null,
            total_rules: 10,
            rules_executed: 8,
            rules_skipped_no_data: 0,
            rules_with_findings: 0,
            total_findings: 0,
            // severity_breakdown OMITTED
          })}
          categories={[]}
          attackChains={[]}
        />,
      ),
    ).not.toThrow();
  });

  it("renders without coverage entirely", () => {
    expect(() =>
      render(
        <HeroBlock
          serverName="demo"
          coverage={undefined}
          categories={[]}
          attackChains={[]}
        />,
      ),
    ).not.toThrow();
  });
});

describe("CoverageLedger — malformed taxonomy does not throw", () => {
  it("category with missing sub_categories", () => {
    expect(() =>
      render(
        <CoverageLedger
          coverage={undefined}
          categories={[bad({ id: "x", title: "x" })]}
        />,
      ),
    ).not.toThrow();
  });

  it("sub-category with missing rules array", () => {
    expect(() =>
      render(
        <CoverageLedger
          coverage={undefined}
          categories={[
            bad({
              id: "x",
              title: "x",
              sub_categories: [bad({ id: "y", title: "y" })],
            }),
          ]}
        />,
      ),
    ).not.toThrow();
  });
});

describe("KillChainReel — malformed chains do not throw", () => {
  it("chain missing every optional / nested field", () => {
    expect(() =>
      render(
        <KillChainReel
          chains={[
            bad({}),
            bad({ chain_id: "only-id" }),
            bad({
              chain_id: "no-arrays",
              exploitability_overall: 0.5,
              exploitability_rating: "high",
              // owasp_refs / mitre_refs / steps / mitigations OMITTED
            }),
          ]}
          currentServerSlug="demo"
        />,
      ),
    ).not.toThrow();
  });
});

describe("CapabilitySurface — partial node / edges do not throw", () => {
  it("node missing capabilities array", () => {
    expect(() =>
      render(
        <CapabilitySurface
          node={bad({ server_id: "x", server_slug: "y" })}
          edges={[]}
        />,
      ),
    ).not.toThrow();
  });

  it("edge missing from_server / to_server", () => {
    expect(() =>
      render(
        <CapabilitySurface
          node={bad({
            server_id: "x",
            server_slug: "y",
            capabilities: ["sends-network"],
          })}
          edges={[
            bad({
              pattern_id: "P01",
              edge_type: "data_flow",
              severity: "high",
              description: "x",
              owasp_category: null,
              mitre_technique: null,
              config_id: "c",
              // from_server / to_server OMITTED
            }),
          ]}
        />,
      ),
    ).not.toThrow();
  });
});
