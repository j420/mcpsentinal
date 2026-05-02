// @vitest-environment jsdom
/**
 * data-trace coverage smoke tests.
 *
 * Guards: each component that's part of the Hover-to-Trace cluster
 * actually emits the right data-trace attributes for the entities it
 * renders. If a refactor accidentally drops `data-trace` from a
 * key-bearing element, the page-wide hover linking silently breaks —
 * these assertions surface that regression.
 */

import { afterEach, describe, expect, it } from "vitest";
import React from "react";
import { cleanup, render } from "@testing-library/react";
import KillChainReel from "../components/KillChainReel";
import CapabilitySurface from "../components/CapabilitySurface";
import CoverageLedger from "../components/CoverageLedger";
import type {
  DeepDiveAttackChain,
  DeepDiveCapabilityNode,
  DeepDiveRiskEdge,
} from "../lib/deep-dive";

afterEach(() => cleanup());

describe("KillChainReel — data-trace coverage", () => {
  const chain: DeepDiveAttackChain = {
    chain_id: "x",
    kill_chain_id: "KC01",
    kill_chain_name: "Indirect Injection → Data Exfiltration",
    steps: [
      {
        ordinal: 1,
        server_id: "web-scraper",
        server_name: "web-scraper",
        role: "injection_gateway",
        tools_involved: ["fetch_url", "scrape"],
      },
    ],
    exploitability_overall: 0.5,
    exploitability_rating: "high",
    narrative: "x",
    mitigations: [],
    owasp_refs: [],
    mitre_refs: [],
  };

  it("emits kc:, server:, tool: trace keys on the right elements", () => {
    const { container } = render(<KillChainReel chains={[chain]} />);
    expect(container.querySelector('[data-trace="kc:KC01"]')).not.toBeNull();
    expect(
      container.querySelector('[data-trace="server:web-scraper"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-trace="tool:fetch_url"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-trace="tool:scrape"]'),
    ).not.toBeNull();
  });
});

describe("CapabilitySurface — data-trace coverage", () => {
  const node: DeepDiveCapabilityNode = {
    server_id: "this",
    server_name: "this-server",
    server_slug: "this-server",
    latest_score: 50,
    capabilities: ["executes-code", "sends-network", "reads-data"],
    is_injection_gateway: false,
    is_shared_writer: false,
    category: null,
  };
  const edges: DeepDiveRiskEdge[] = [
    {
      config_id: "c",
      from_server: { id: "this", name: "this-server", slug: "this-server" },
      to_server: { id: "peer", name: "peer-mcp", slug: "peer-mcp" },
      edge_type: "data_flow",
      pattern_id: "P01",
      severity: "critical",
      description: "x",
      owasp_category: null,
      mitre_technique: null,
    },
  ];

  it("emits capability:, pattern:, server: trace keys on the right elements", () => {
    const { container } = render(
      <CapabilitySurface node={node} edges={edges} />,
    );
    expect(
      container.querySelector('[data-trace="capability:executes-code"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-trace="capability:sends-network"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-trace="capability:reads-data"]'),
    ).not.toBeNull();
    expect(container.querySelector('[data-trace="pattern:P01"]')).not.toBeNull();
    expect(
      container.querySelector('[data-trace="server:peer-mcp"]'),
    ).not.toBeNull();
  });
});

describe("CoverageLedger — data-trace coverage", () => {
  it("emits rule: trace keys on each skipped-rule pill", () => {
    const skipped = {
      rule_id: "C1",
      name: "Command Injection",
      severity: "high" as const,
      category: "C",
      owasp: null,
      mitre: null,
      summary: "",
      framework_controls: [],
      methodology: {
        technique: "ast-taint",
        verified_edge_cases: [],
        edge_case_strategies: [],
        confidence_cap: null,
      },
      backing: null,
      remediation: "—",
      status: "skipped" as const,
      findings: [],
      skip_reason: { missing_inputs: ["source_code" as const], summary: "x" },
    };
    const cat = {
      id: "code",
      title: "Code",
      summary: "",
      frameworks: [],
      counts: {
        rules_total: 1,
        rules_passed: 0,
        rules_with_findings: 0,
        rules_skipped: 1,
        finding_count: 0,
        severity_breakdown: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          informational: 0,
        },
      },
      sub_categories: [
        {
          id: "x",
          title: "x",
          summary: "",
          counts: {
            rules_total: 1,
            rules_passed: 0,
            rules_with_findings: 0,
            rules_skipped: 1,
            finding_count: 0,
            severity_breakdown: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              informational: 0,
            },
          },
          rules: [skipped],
        },
      ],
    };
    const { container } = render(
      <CoverageLedger coverage={undefined} categories={[cat]} />,
    );
    expect(container.querySelector('[data-trace="rule:C1"]')).not.toBeNull();
  });
});
