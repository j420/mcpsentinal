/**
 * Integration Tests — Cross-cutting engine behaviors
 *
 * Tests multi-template activation, safety caps, deduplication,
 * score boundaries, edge direction handling, and config_id determinism.
 */
import { describe, it, expect } from "vitest";
import { AttackGraphEngine } from "../engine.js";
import type { AttackGraphInput, CapabilityNode } from "../types.js";
import {
  webScraper, emailReader, slackBot,
  fileManager, credentialStore, dbReader,
  codeRunner, shellExec,
  webhookSender, emailSender,
  configWriter, memoryWriter, memoryReader,
  codeGenerator, dbAdmin,
  safeCalculator, safeFormatter,
} from "./fixtures/nodes.js";
import {
  kc01Edges, kc02Edges, kc03Edges, kc04Edges,
  kc05Edges, kc06Edges, kc07Edges, makeEdge,
} from "./fixtures/edges.js";

function makeCustomNode(
  id: string,
  name: string,
  caps: string[],
  overrides: Partial<CapabilityNode> = {}
): CapabilityNode {
  return {
    server_id: id,
    server_name: name,
    server_slug: name,
    latest_score: 50,
    capabilities: caps as any,
    is_injection_gateway: false,
    is_shared_writer: false,
    category: null,
    ...overrides,
  };
}

const engine = new AttackGraphEngine();

// ── Multi-template simultaneous activation ────────────────────────────────────

describe("multi-template simultaneous activation", () => {
  // 8 servers satisfying KC01 + KC03 + KC07 simultaneously
  // KC01: injection_gateway → data_source → exfiltrator
  //   webScraper (injection gateway) → fileManager (data source) → webhookSender (exfiltrator)
  // KC03: data_source (credentials) → exfiltrator
  //   credentialStore → webhookSender
  // KC07: data_source (db) → executor (db admin) → exfiltrator
  //   dbReader → dbAdmin → webhookSender

  function buildMultiTemplateInput(): AttackGraphInput {
    return {
      nodes: [
        webScraper(),
        fileManager(),
        webhookSender(),
        credentialStore(),
        dbReader(),
        dbAdmin(),
      ],
      edges: [
        // KC01 edges
        makeEdge("web-scraper", "file-manager", "injection_path", "critical", "P01"),
        makeEdge("file-manager", "webhook-sender", "exfiltration_chain", "critical", "P01"),
        // KC03 edges
        makeEdge("credential-store", "webhook-sender", "credential_chain", "critical", "P02"),
        // KC07 edges
        makeEdge("db-reader", "db-admin", "privilege_escalation", "critical", "P08"),
        makeEdge("db-admin", "webhook-sender", "exfiltration_chain", "high", "P08"),
      ],
      patterns_detected: ["P01", "P02", "P03", "P08", "P09"],
    };
  }

  it("all 3 templates fire (KC01, KC03, KC07)", () => {
    const report = engine.analyze(buildMultiTemplateInput());

    const templateIds = new Set(report.chains.map((c) => c.kill_chain_id));
    expect(templateIds.has("KC01")).toBe(true);
    expect(templateIds.has("KC03")).toBe(true);
    expect(templateIds.has("KC07")).toBe(true);
  });

  it("chains are sorted by exploitability descending", () => {
    const report = engine.analyze(buildMultiTemplateInput());

    for (let i = 1; i < report.chains.length; i++) {
      expect(report.chains[i - 1].exploitability.overall).toBeGreaterThanOrEqual(
        report.chains[i].exploitability.overall
      );
    }
  });

  it("aggregate_risk is critical when any chain is critical", () => {
    const report = engine.analyze(buildMultiTemplateInput());

    const hasCritical = report.chains.some(
      (c) => c.exploitability.rating === "critical"
    );
    if (hasCritical) {
      expect(report.aggregate_risk).toBe("critical");
    } else {
      // If no individual chain reaches critical, aggregate should be at least high
      expect(["high", "medium", "low"]).toContain(report.aggregate_risk);
    }
  });

  it("chain_count matches chains.length", () => {
    const report = engine.analyze(buildMultiTemplateInput());
    expect(report.chain_count).toBe(report.chains.length);
  });

  it("each chain has distinct chain_id", () => {
    const report = engine.analyze(buildMultiTemplateInput());
    const ids = report.chains.map((c) => c.chain_id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// ── MAX_COMBINATIONS_PER_TEMPLATE cap ─────────────────────────────────────────

describe("MAX_COMBINATIONS_PER_TEMPLATE cap", () => {
  it("produces multiple KC01 chains from 5x5x5 candidates without exceeding cap", () => {
    // 5 gateways x 5 data sources x 5 exfiltrators = 125 combos
    const gateways: CapabilityNode[] = [];
    const sources: CapabilityNode[] = [];
    const exfiltrators: CapabilityNode[] = [];

    for (let i = 0; i < 5; i++) {
      gateways.push(
        makeCustomNode(`gw-${i}`, `gateway-${i}`, ["web-scraping", "reads-data"], {
          is_injection_gateway: true,
          latest_score: 30,
        })
      );
      sources.push(
        makeCustomNode(`src-${i}`, `source-${i}`, ["reads-data", "accesses-filesystem"], {
          latest_score: 55,
        })
      );
      exfiltrators.push(
        makeCustomNode(`exf-${i}`, `exfil-${i}`, ["sends-network"], {
          latest_score: 50,
        })
      );
    }

    const nodes = [...gateways, ...sources, ...exfiltrators];

    // Create edges between all gateways→sources and sources→exfiltrators
    const edges = [];
    for (let g = 0; g < 5; g++) {
      for (let s = 0; s < 5; s++) {
        edges.push({
          from_server_id: `gw-${g}`,
          to_server_id: `src-${s}`,
          edge_type: "injection_path" as const,
          severity: "critical" as const,
          description: `gw-${g} → src-${s}`,
          owasp: "MCP01",
          mitre: "AML.T0054",
          pattern_id: "P01",
        });
      }
      for (let e = 0; e < 5; e++) {
        edges.push({
          from_server_id: `src-${g}`,
          to_server_id: `exf-${e}`,
          edge_type: "exfiltration_chain" as const,
          severity: "critical" as const,
          description: `src-${g} → exf-${e}`,
          owasp: "MCP04",
          mitre: "AML.T0057",
          pattern_id: "P01",
        });
      }
    }

    const report = engine.analyze({
      nodes,
      edges,
      patterns_detected: ["P01", "P03", "P09"],
    });

    // Should produce multiple KC01 chains
    const kc01Chains = report.chains.filter((c) => c.kill_chain_id === "KC01");
    expect(kc01Chains.length).toBeGreaterThan(1);
    // Must not exceed MAX_COMBINATIONS_PER_TEMPLATE (500) — though 125 combos won't hit it
    expect(kc01Chains.length).toBeLessThanOrEqual(500);
  }, 10_000);

  it("engine completes in reasonable time with many candidates", () => {
    // 10 gateways x 10 sources x 10 exfiltrators = 1000 theoretical combos
    // capped at 500 per template
    const nodes: CapabilityNode[] = [];
    const edges: any[] = [];

    for (let i = 0; i < 10; i++) {
      nodes.push(
        makeCustomNode(`gw-${i}`, `gateway-${i}`, ["web-scraping", "reads-data"], {
          is_injection_gateway: true,
          latest_score: 30,
        })
      );
      nodes.push(
        makeCustomNode(`src-${i}`, `source-${i}`, ["reads-data", "accesses-filesystem"], {
          latest_score: 55,
        })
      );
      nodes.push(
        makeCustomNode(`exf-${i}`, `exfil-${i}`, ["sends-network"], {
          latest_score: 50,
        })
      );
    }

    // Create edges between all gateways→sources and sources→exfiltrators
    for (let g = 0; g < 10; g++) {
      for (let s = 0; s < 10; s++) {
        edges.push({
          from_server_id: `gw-${g}`,
          to_server_id: `src-${s}`,
          edge_type: "injection_path" as const,
          severity: "critical" as const,
          description: `gw-${g} → src-${s}`,
          owasp: "MCP01",
          mitre: "AML.T0054",
          pattern_id: "P01",
        });
        edges.push({
          from_server_id: `src-${s}`,
          to_server_id: `exf-${g}`,
          edge_type: "exfiltration_chain" as const,
          severity: "critical" as const,
          description: `src-${s} → exf-${g}`,
          owasp: "MCP04",
          mitre: "AML.T0057",
          pattern_id: "P01",
        });
      }
    }

    const start = Date.now();
    const report = engine.analyze({
      nodes,
      edges,
      patterns_detected: ["P01", "P03", "P09"],
    });
    const elapsed = Date.now() - start;

    // KC01 chains capped at 500
    const kc01Chains = report.chains.filter((c) => c.kill_chain_id === "KC01");
    expect(kc01Chains.length).toBeLessThanOrEqual(500);
    // Should complete quickly (well under 10s)
    expect(elapsed).toBeLessThan(10_000);
  }, 15_000);
});

// ── MAX_CHAINS global cap ─────────────────────────────────────────────────────

describe("MAX_CHAINS global cap", () => {
  it("report.chains.length never exceeds 100", () => {
    // Create enough servers for many valid chains across multiple templates
    const nodes: CapabilityNode[] = [];
    const edges: any[] = [];

    // Create 10 gateways, 10 sources, 10 exfiltrators for KC01
    for (let i = 0; i < 10; i++) {
      nodes.push(
        makeCustomNode(`gw-${i}`, `gateway-${i}`, ["web-scraping", "reads-data"], {
          is_injection_gateway: true,
          latest_score: 30,
        })
      );
      nodes.push(
        makeCustomNode(`src-${i}`, `source-${i}`, ["reads-data", "accesses-filesystem"], {
          latest_score: 55,
        })
      );
      nodes.push(
        makeCustomNode(`exf-${i}`, `exfil-${i}`, ["sends-network"], {
          latest_score: 50,
        })
      );
    }

    for (let g = 0; g < 10; g++) {
      for (let s = 0; s < 10; s++) {
        edges.push({
          from_server_id: `gw-${g}`,
          to_server_id: `src-${s}`,
          edge_type: "injection_path" as const,
          severity: "critical" as const,
          description: `gw-${g} → src-${s}`,
          owasp: "MCP01",
          mitre: "AML.T0054",
          pattern_id: "P01",
        });
        edges.push({
          from_server_id: `src-${s}`,
          to_server_id: `exf-${g}`,
          edge_type: "exfiltration_chain" as const,
          severity: "critical" as const,
          description: `src-${s} → exf-${g}`,
          owasp: "MCP04",
          mitre: "AML.T0057",
          pattern_id: "P01",
        });
      }
    }

    const report = engine.analyze({
      nodes,
      edges,
      patterns_detected: ["P01", "P03", "P09"],
    });

    expect(report.chains.length).toBeLessThanOrEqual(100);
  }, 15_000);

  it("chains are sorted by exploitability descending (highest kept)", () => {
    const nodes: CapabilityNode[] = [];
    const edges: any[] = [];

    for (let i = 0; i < 10; i++) {
      nodes.push(
        makeCustomNode(`gw-${i}`, `gateway-${i}`, ["web-scraping", "reads-data"], {
          is_injection_gateway: true,
          latest_score: 30,
        })
      );
      nodes.push(
        makeCustomNode(`src-${i}`, `source-${i}`, ["reads-data", "accesses-filesystem"], {
          latest_score: 55,
        })
      );
      nodes.push(
        makeCustomNode(`exf-${i}`, `exfil-${i}`, ["sends-network"], {
          latest_score: 50,
        })
      );
    }

    for (let g = 0; g < 10; g++) {
      for (let s = 0; s < 10; s++) {
        edges.push({
          from_server_id: `gw-${g}`,
          to_server_id: `src-${s}`,
          edge_type: "injection_path" as const,
          severity: "critical" as const,
          description: `gw-${g} → src-${s}`,
          owasp: "MCP01",
          mitre: "AML.T0054",
          pattern_id: "P01",
        });
        edges.push({
          from_server_id: `src-${s}`,
          to_server_id: `exf-${g}`,
          edge_type: "exfiltration_chain" as const,
          severity: "critical" as const,
          description: `src-${s} → exf-${g}`,
          owasp: "MCP04",
          mitre: "AML.T0057",
          pattern_id: "P01",
        });
      }
    }

    const report = engine.analyze({
      nodes,
      edges,
      patterns_detected: ["P01", "P03", "P09"],
    });

    for (let i = 1; i < report.chains.length; i++) {
      expect(report.chains[i - 1].exploitability.overall).toBeGreaterThanOrEqual(
        report.chains[i].exploitability.overall
      );
    }
  }, 15_000);
});

// ── All-safe-servers baseline ─────────────────────────────────────────────────

describe("all-safe-servers baseline", () => {
  it("produces 0 chains for safe-only servers", () => {
    const report = engine.analyze({
      nodes: [safeCalculator(), safeFormatter()],
      edges: [],
      patterns_detected: [],
    });

    expect(report.chains).toHaveLength(0);
    expect(report.chain_count).toBe(0);
  });

  it("aggregate_risk is none", () => {
    const report = engine.analyze({
      nodes: [safeCalculator(), safeFormatter()],
      edges: [],
      patterns_detected: [],
    });

    expect(report.aggregate_risk).toBe("none");
  });

  it("summary contains 'No multi-step attack chains detected'", () => {
    const report = engine.analyze({
      nodes: [safeCalculator(), safeFormatter()],
      edges: [],
      patterns_detected: [],
    });

    expect(report.summary).toContain("No multi-step attack chains detected");
  });

  it("report is well-formed with all required fields", () => {
    const report = engine.analyze({
      nodes: [safeCalculator(), safeFormatter()],
      edges: [],
      patterns_detected: [],
    });

    expect(report.generated_at).toBeDefined();
    expect(typeof report.generated_at).toBe("string");
    expect(report.config_id).toBeDefined();
    expect(typeof report.config_id).toBe("string");
    expect(report.server_count).toBe(2);
    expect(report.critical_chains).toBe(0);
    expect(report.high_chains).toBe(0);
  });
});

// ── Score boundary conditions ─────────────────────────────────────────────────

describe("score boundary conditions", () => {
  // Use KC03 (simplest: 2 servers, credential-store + webhook-sender)
  // Vary the credential-store's latest_score and check server_score_weakness factor

  function buildKC03WithScore(score: number | null): AttackGraphInput {
    const cred = makeCustomNode(
      "srv-credential-store",
      "credential-store",
      ["reads-data", "manages-credentials"],
      { latest_score: score }
    );
    const webhook = makeCustomNode(
      "srv-webhook-sender",
      "webhook-sender",
      ["sends-network"],
      { latest_score: 90 } // high score so it doesn't affect the weakest calculation
    );

    return {
      nodes: [cred, webhook],
      edges: [
        {
          from_server_id: "srv-credential-store",
          to_server_id: "srv-webhook-sender",
          edge_type: "credential_chain" as const,
          severity: "critical" as const,
          description: "cred → webhook",
          owasp: "MCP04",
          mitre: "AML.T0057",
          pattern_id: "P02",
        },
      ],
      patterns_detected: ["P02"],
    };
  }

  function getWeaknessFactor(report: ReturnType<AttackGraphEngine["analyze"]>): number | undefined {
    const chain = report.chains.find((c) => c.kill_chain_id === "KC03");
    if (!chain) return undefined;
    const factor = chain.exploitability.factors.find(
      (f) => f.factor === "server_score_weakness"
    );
    return factor?.value;
  }

  it("latest_score = null uses default 0.7 when ALL servers unscored", () => {
    // Both servers must have null score for the "all unscored" default (0.7)
    // to apply. If only one is null, the other's score is used as minScore.
    const cred = makeCustomNode(
      "srv-credential-store",
      "credential-store",
      ["reads-data", "manages-credentials"],
      { latest_score: null }
    );
    const webhook = makeCustomNode(
      "srv-webhook-sender",
      "webhook-sender",
      ["sends-network"],
      { latest_score: null }
    );
    const input: AttackGraphInput = {
      nodes: [cred, webhook],
      edges: [
        {
          from_server_id: "srv-credential-store",
          to_server_id: "srv-webhook-sender",
          edge_type: "credential_chain" as const,
          severity: "critical" as const,
          description: "cred → webhook",
          owasp: "MCP04",
          mitre: "AML.T0057",
          pattern_id: "P02",
        },
      ],
      patterns_detected: ["P02"],
    };
    const report = engine.analyze(input);
    expect(getWeaknessFactor(report)).toBe(0.7);
  });

  it("latest_score = 0 yields factor 1.0 (< 40)", () => {
    const report = engine.analyze(buildKC03WithScore(0));
    expect(getWeaknessFactor(report)).toBe(1.0);
  });

  it("latest_score = 100 yields factor 0.2 (>= 80)", () => {
    const report = engine.analyze(buildKC03WithScore(100));
    expect(getWeaknessFactor(report)).toBe(0.2);
  });

  it("latest_score = 39 yields factor 1.0 (critical boundary, < 40)", () => {
    const report = engine.analyze(buildKC03WithScore(39));
    expect(getWeaknessFactor(report)).toBe(1.0);
  });

  it("latest_score = 40 yields factor 0.8 (poor boundary, 40-59)", () => {
    const report = engine.analyze(buildKC03WithScore(40));
    expect(getWeaknessFactor(report)).toBe(0.8);
  });

  it("latest_score = 59 yields factor 0.8 (poor, 40-59)", () => {
    const report = engine.analyze(buildKC03WithScore(59));
    expect(getWeaknessFactor(report)).toBe(0.8);
  });

  it("latest_score = 60 yields factor 0.5 (moderate, 60-79)", () => {
    const report = engine.analyze(buildKC03WithScore(60));
    expect(getWeaknessFactor(report)).toBe(0.5);
  });

  it("latest_score = 79 yields factor 0.5 (moderate, 60-79)", () => {
    const report = engine.analyze(buildKC03WithScore(79));
    expect(getWeaknessFactor(report)).toBe(0.5);
  });

  it("latest_score = 80 yields factor 0.2 (good, >= 80)", () => {
    const report = engine.analyze(buildKC03WithScore(80));
    expect(getWeaknessFactor(report)).toBe(0.2);
  });
});

// ── Deduplication ─────────────────────────────────────────────────────────────

describe("deduplication", () => {
  function buildKC03Input(): AttackGraphInput {
    return {
      nodes: [credentialStore(), webhookSender()],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    };
  }

  it("chain_id is deterministic across multiple runs", () => {
    const report1 = engine.analyze(buildKC03Input());
    const report2 = engine.analyze(buildKC03Input());

    const ids1 = report1.chains.map((c) => c.chain_id).sort();
    const ids2 = report2.chains.map((c) => c.chain_id).sort();
    expect(ids1).toEqual(ids2);
  });

  it("same 3 servers + same template produces exactly 1 chain", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: kc01Edges(),
      patterns_detected: ["P01"],
    });

    const kc01Chains = report.chains.filter((c) => c.kill_chain_id === "KC01");
    expect(kc01Chains).toHaveLength(1);
  });

  it("2 different server sets filling KC01 produce 2 distinct chains", () => {
    // Set 1: webScraper + fileManager + webhookSender
    // Set 2: emailReader + credentialStore + emailSender
    const report = engine.analyze({
      nodes: [
        webScraper(),
        fileManager(),
        webhookSender(),
        emailReader(),
        credentialStore(),
        emailSender(),
      ],
      edges: [
        // Set 1 edges
        makeEdge("web-scraper", "file-manager", "injection_path", "critical", "P01"),
        makeEdge("file-manager", "webhook-sender", "exfiltration_chain", "critical", "P01"),
        // Set 2 edges
        makeEdge("email-reader", "credential-store", "injection_path", "critical", "P01"),
        makeEdge("credential-store", "email-sender", "exfiltration_chain", "critical", "P01"),
      ],
      patterns_detected: ["P01", "P03", "P09"],
    });

    const kc01Chains = report.chains.filter((c) => c.kill_chain_id === "KC01");
    expect(kc01Chains.length).toBeGreaterThanOrEqual(2);

    const chainIds = kc01Chains.map((c) => c.chain_id);
    expect(new Set(chainIds).size).toBe(chainIds.length);
  });

  it("same servers + different template produce different chain_ids", () => {
    // credentialStore + webhookSender can match KC03
    // dbReader + dbAdmin + webhookSender can match KC07
    // webhookSender is shared but templates differ
    const report = engine.analyze({
      nodes: [credentialStore(), dbReader(), dbAdmin(), webhookSender()],
      edges: [
        ...kc03Edges(),
        ...kc07Edges(),
      ],
      patterns_detected: ["P02", "P08"],
    });

    const kc03 = report.chains.find((c) => c.kill_chain_id === "KC03");
    const kc07 = report.chains.find((c) => c.kill_chain_id === "KC07");

    expect(kc03).toBeDefined();
    expect(kc07).toBeDefined();
    expect(kc03!.chain_id).not.toBe(kc07!.chain_id);
  });
});

// ── server_findings enrichment ────────────────────────────────────────────────

describe("server_findings enrichment", () => {
  function buildKC03WithFindings(
    findings?: Record<string, string[]>
  ): AttackGraphInput {
    return {
      nodes: [credentialStore(), webhookSender()],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
      server_findings: findings,
    };
  }

  it("3+ findings yields supporting_findings factor = 1.0", () => {
    const report = engine.analyze(
      buildKC03WithFindings({
        "srv-credential-store": ["C5", "F1", "G7"],
        "srv-webhook-sender": [],
      })
    );

    const chain = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(chain).toBeDefined();
    const factor = chain!.exploitability.factors.find(
      (f) => f.factor === "supporting_findings"
    );
    expect(factor).toBeDefined();
    expect(factor!.value).toBe(1.0);
  });

  it("1-2 findings yields supporting_findings factor = 0.7", () => {
    const report = engine.analyze(
      buildKC03WithFindings({
        "srv-credential-store": ["C5"],
        "srv-webhook-sender": [],
      })
    );

    const chain = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(chain).toBeDefined();
    const factor = chain!.exploitability.factors.find(
      (f) => f.factor === "supporting_findings"
    );
    expect(factor).toBeDefined();
    expect(factor!.value).toBe(0.7);
  });

  it("no findings (undefined) yields supporting_findings factor = 0.3", () => {
    const report = engine.analyze(buildKC03WithFindings(undefined));

    const chain = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(chain).toBeDefined();
    const factor = chain!.exploitability.factors.find(
      (f) => f.factor === "supporting_findings"
    );
    expect(factor).toBeDefined();
    expect(factor!.value).toBe(0.3);
  });

  it("findings for non-chain servers are ignored", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), webhookSender(), safeCalculator()],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
      server_findings: {
        "srv-calculator": ["A1", "A2", "A3", "C1", "C5"],
        "srv-credential-store": [],
        "srv-webhook-sender": [],
      },
    });

    const chain = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(chain).toBeDefined();
    const factor = chain!.exploitability.factors.find(
      (f) => f.factor === "supporting_findings"
    );
    expect(factor).toBeDefined();
    // calculator is not in the chain, its 5 findings should not count
    expect(factor!.value).toBe(0.3);
  });
});

// ── Edge direction handling ───────────────────────────────────────────────────

describe("edge direction handling", () => {
  it("detects KC03 chain with reversed edge direction (B→A instead of A→B)", () => {
    const report = engine.analyze({
      nodes: [credentialStore(), webhookSender()],
      edges: [
        // Reversed: webhook-sender → credential-store instead of credential-store → webhook-sender
        {
          from_server_id: "srv-webhook-sender",
          to_server_id: "srv-credential-store",
          edge_type: "credential_chain" as const,
          severity: "critical" as const,
          description: "reversed edge",
          owasp: "MCP04",
          mitre: "AML.T0057",
          pattern_id: "P02",
        },
      ],
      patterns_detected: ["P02"],
    });

    const kc03 = report.chains.find((c) => c.kill_chain_id === "KC03");
    expect(kc03).toBeDefined();
    expect(kc03!.steps).toHaveLength(2);
  });

  it("detects KC01 chain with all edges reversed", () => {
    const report = engine.analyze({
      nodes: [webScraper(), fileManager(), webhookSender()],
      edges: [
        // Reversed: file-manager → web-scraper
        makeEdge("file-manager", "web-scraper", "injection_path", "critical", "P01"),
        // Reversed: webhook-sender → file-manager
        makeEdge("webhook-sender", "file-manager", "exfiltration_chain", "critical", "P01"),
      ],
      patterns_detected: ["P01"],
    });

    const kc01 = report.chains.find((c) => c.kill_chain_id === "KC01");
    expect(kc01).toBeDefined();
    expect(kc01!.steps).toHaveLength(3);
  });
});

// ── config_id determinism ─────────────────────────────────────────────────────

describe("config_id determinism", () => {
  it("same nodes produce same config_id", () => {
    const input: AttackGraphInput = {
      nodes: [credentialStore(), webhookSender()],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    };

    const report1 = engine.analyze(input);
    const report2 = engine.analyze(input);
    expect(report1.config_id).toBe(report2.config_id);
  });

  it("different order of nodes produces same config_id (sorted before hashing)", () => {
    const cred = credentialStore();
    const webhook = webhookSender();

    const report1 = engine.analyze({
      nodes: [cred, webhook],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    });

    const report2 = engine.analyze({
      nodes: [webhook, cred],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    });

    expect(report1.config_id).toBe(report2.config_id);
  });

  it("adding one more node changes config_id", () => {
    const cred = credentialStore();
    const webhook = webhookSender();
    const calc = safeCalculator();

    const report1 = engine.analyze({
      nodes: [cred, webhook],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    });

    const report2 = engine.analyze({
      nodes: [cred, webhook, calc],
      edges: kc03Edges(),
      patterns_detected: ["P02"],
    });

    expect(report1.config_id).not.toBe(report2.config_id);
  });
});
