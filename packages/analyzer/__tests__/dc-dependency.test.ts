/**
 * Dynamic Confidence — D1 (Known CVEs) + E1 (No Auth) + D5 (Known Malicious)
 *
 * D1 builds: source (dependency) + sink (vulnerable code) + mitigation (absent)
 *   + impact + cve_confirmed factor (+0.20) + server-specific signals.
 *   Base: 0.45 (source+sink, no propagation) → boosted by +0.20 CVE factor
 *   + absent mitigation (+0.10) + server signals.
 *
 * E1 builds: source (environment) + sink (privilege-grant) + mitigation (absent)
 *   + impact + no_auth_confirmed factor (+0.15) + server signals.
 *   Base: 0.45 (source+sink) → boosted by absent mitigation (+0.10) and
 *   no_auth_confirmed (+0.15).
 *
 * D5 builds a chain for known malicious packages. The evidence_chain must
 *   exist and produce dynamic confidence.
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: null, dependencies: [], connection_metadata: null, ...overrides };
}
function run(id: string, c: AnalysisContext) { return getTypedRule(id)!.analyze(c); }

describe("D1 — Known CVEs dynamic confidence", () => {
  it("CVE-backed dependency produces finding with evidence_chain and dynamic confidence", () => {
    const findings = run("D1", ctx({
      dependencies: [{
        name: "lodash",
        version: "4.17.10",
        has_known_cve: true,
        cve_ids: ["CVE-2020-8203"],
        last_updated: "2019-07-01",
      }],
    }));

    const d1 = findings.filter(f => f.rule_id === "D1");
    expect(d1.length).toBeGreaterThanOrEqual(1);
    expect(d1[0].evidence).toContain("CVE-2020-8203");

    // Confidence must be from chain, not a bare hardcoded value
    const chain = d1[0].metadata?.evidence_chain as {
      confidence: number;
      confidence_factors: Array<{ factor: string; adjustment: number }>;
    } | undefined;
    expect(chain).toBeDefined();

    // Must have the cve_confirmed factor (+0.20)
    const cveFactor = chain!.confidence_factors.find(f => f.factor === "cve_confirmed");
    expect(cveFactor).toBeDefined();
    expect(cveFactor!.adjustment).toBeCloseTo(0.20, 2);

    // chain.confidence must equal finding.confidence
    expect(chain!.confidence).toBe(d1[0].confidence);

    // Base 0.45 (source+sink) + 0.20 (CVE) + mitigation absent (+0.10) = 0.75 minimum
    // Plus server signals. Must be in valid range.
    expect(d1[0].confidence).toBeGreaterThanOrEqual(0.50);
    expect(d1[0].confidence).toBeLessThanOrEqual(0.99);
  });
});

describe("E1 — No Authentication dynamic confidence", () => {
  it("unauthenticated server produces finding with evidence_chain and dynamic confidence", () => {
    const findings = run("E1", ctx({
      connection_metadata: { auth_required: false, transport: "http", response_time_ms: 50 },
    }));

    const e1 = findings.filter(f => f.rule_id === "E1");
    expect(e1.length).toBeGreaterThanOrEqual(1);

    const chain = e1[0].metadata?.evidence_chain as {
      confidence: number;
      confidence_factors: Array<{ factor: string; adjustment: number }>;
    } | undefined;
    expect(chain).toBeDefined();

    // Must have the no_auth_confirmed factor (+0.15)
    const noAuthFactor = chain!.confidence_factors.find(f => f.factor === "no_auth_confirmed");
    expect(noAuthFactor).toBeDefined();
    expect(noAuthFactor!.adjustment).toBeCloseTo(0.15, 2);

    // chain.confidence must equal finding.confidence
    expect(chain!.confidence).toBe(e1[0].confidence);

    // Must be in valid clamped range
    expect(e1[0].confidence).toBeGreaterThanOrEqual(0.05);
    expect(e1[0].confidence).toBeLessThanOrEqual(0.99);
  });
});

describe("D5 — Known Malicious Packages dynamic confidence", () => {
  it("@mcp/sdk typosquat produces finding with evidence_chain", () => {
    const findings = run("D5", ctx({
      dependencies: [{
        name: "@mcp/sdk",
        version: "1.0.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: "2025-01-01",
      }],
    }));

    const d5 = findings.filter(f => f.rule_id === "D5");
    expect(d5.length).toBeGreaterThanOrEqual(1);

    // Confidence must be dynamic and in valid range
    expect(d5[0].confidence).toBeGreaterThan(0.05);
    expect(d5[0].confidence).toBeLessThanOrEqual(0.99);

    // Evidence chain must exist
    const chain = d5[0].metadata?.evidence_chain as { confidence: number } | undefined;
    expect(chain).toBeDefined();
    expect(chain!.confidence).toBe(d5[0].confidence);
  });
});
