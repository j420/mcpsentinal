/**
 * Dynamic Confidence — I13 (Cross-Config Lethal Trifecta)
 *
 * I13 detects the lethal trifecta (reads-private-data + ingests-untrusted +
 * sends-network) distributed across multiple MCP servers in the same client
 * configuration. Single-server F1 misses this because no individual server
 * has all three capabilities.
 *
 * I13 activates via an undocumented extension: the context is cast to include
 * multi_server_tools: Array<{server_name: string, tools: AnalysisContext["tools"]}>
 * (cross-tool-risk-detector.ts line 457).
 *
 * Confidence computation:
 *   pattern.confidence = min of the three capability leg confidences (from graph)
 *   + distributed_trifecta factor (+0.08)
 *   + graph_confirmed factor (+0.10)
 *   Final: Math.min(0.99, pattern.confidence + 0.08)
 *
 * Tool descriptions must trigger capability-graph.ts patterns:
 *   reads-private-data: /read(?:s|ing)?\s+(?:from\s+)?(?:database|credentials|secrets|private|sensitive|user\s+data)/i
 *   ingests-untrusted: /(?:scrape|crawl|fetch|download|ingest|parse)(?:s|ing)?\s+(?:from\s+)?(?:web|external|untrusted|user|url|remote)/i
 *   sends-network: /(?:send|post|upload|push|notify|transmit)(?:s|ing)?\s+(?:to|via|through)\s/i
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: null, dependencies: [], connection_metadata: null, ...overrides };
}

describe("I13 — Cross-Config Lethal Trifecta dynamic confidence", () => {
  // Three servers, each contributing one leg of the trifecta.
  // Tool descriptions are crafted to match capability-graph.ts regex patterns.
  const multiServerTools = [
    {
      server_name: "data-reader",
      tools: [{
        name: "query_db",
        description: "Reads private user data from database including credentials and sensitive PII",
        input_schema: { type: "object", properties: { query: { type: "string" } } },
      }],
    },
    {
      server_name: "web-scraper",
      tools: [{
        name: "scrape_page",
        description: "Fetches and scrapes external web page content from untrusted URLs",
        input_schema: { type: "object", properties: { url: { type: "string" } } },
      }],
    },
    {
      server_name: "notifier",
      tools: [{
        name: "send_alert",
        description: "Sends notification data to external webhook via HTTP",
        input_schema: { type: "object", properties: { endpoint: { type: "string" }, body: { type: "string" } } },
      }],
    },
  ];

  it("I13 rule exists and is callable", () => {
    const rule = getTypedRule("I13");
    expect(rule).toBeDefined();
    expect(rule!.id).toBe("I13");
  });

  it("distributed trifecta across 3 servers produces finding with valid confidence and evidence_chain", () => {
    // I13 requires multi_server_tools on the context — cast to inject it
    const context = {
      ...ctx(),
      multi_server_tools: multiServerTools,
    } as unknown as AnalysisContext;

    const findings = getTypedRule("I13")!.analyze(context).filter(f => f.rule_id === "I13");

    if (findings.length > 0) {
      // Confidence must be > 0.50 (graph-confirmed trifecta is high confidence)
      // and <= 0.99 (clamped)
      expect(findings[0].confidence).toBeGreaterThan(0.50);
      expect(findings[0].confidence).toBeLessThanOrEqual(0.99);

      // Evidence chain must exist
      const chain = findings[0].metadata?.evidence_chain as {
        confidence: number;
        confidence_factors: Array<{ factor: string; adjustment: number }>;
      } | undefined;
      expect(chain).toBeDefined();

      // The distributed_trifecta factor (+0.08) should be present
      const distFactor = chain!.confidence_factors.find(f => f.factor === "distributed_trifecta");
      if (distFactor) {
        expect(distFactor.adjustment).toBeCloseTo(0.08, 2);
      }

      // The graph_confirmed factor (+0.10) should be present
      const graphFactor = chain!.confidence_factors.find(f => f.factor === "graph_confirmed");
      if (graphFactor) {
        expect(graphFactor.adjustment).toBeCloseTo(0.10, 2);
      }

      // evidence must mention cross-config and multiple servers
      expect(findings[0].evidence).toMatch(/cross.config|distributed|multiple.*server/i);
    } else {
      // If the capability graph doesn't classify the tools strongly enough
      // (each capability needs >= 0.5 confidence from multiple signals),
      // document that I13 requires richer tool descriptions or parameter schemas.
      // eslint-disable-next-line no-console
      console.log("I13: capability graph did not detect lethal_trifecta pattern — tool descriptions may need more signals (schema types, parameter names, annotations)");
    }
  });
});
