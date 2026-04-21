/**
 * N1 — Evidence chain unit tests. Covers each CHARTER lethal edge case and
 * validates the shape of the produced evidence chain (source + sink +
 * mitigation + impact + structured verification targets).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { AnalysisContext } from "../../../../engine.js";
import type { EvidenceChain, EvidenceLink } from "../../../../evidence.js";
import { isLocation } from "../../../location.js";
// Side-effect import registers the rule.
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";

const FIXTURES_DIR = join(__dirname, "..", "__fixtures__");

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

function ctx(source: string): AnalysisContext {
  return {
    server: { id: "t", name: "test", description: null, github_url: null },
    tools: [],
    source_code: source,
    dependencies: [],
    connection_metadata: null,
  };
}

function runN1(source: string) {
  const rule = getTypedRuleV2("N1");
  expect(rule, "N1 rule must be registered").toBeDefined();
  return rule!.analyze(ctx(source));
}

// Locations are narrowed via `isLocation` imported from ../../../location.js —
// every v2 rule's evidence links + verification steps must carry a structured
// Location (not prose). See docs/standards/rule-standard-v2.md §2 + §4.

describe("N1 — JSON-RPC Batch Request Abuse", () => {
  describe("true positives (lethal edge cases)", () => {
    it("flags classic Array.isArray + forEach dispatch without limit", () => {
      const findings = runN1(loadFixture("tp-forEach-without-limit.ts"));
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].rule_id).toBe("N1");
    });

    it("flags batch-named receiver walked with .map() (map-without-guard edge case)", () => {
      const findings = runN1(loadFixture("tp-batch-map-without-guard.ts"));
      expect(findings.length).toBeGreaterThan(0);
    });

    it("flags batch-within-batch nested payload shape", () => {
      const findings = runN1(loadFixture("tp-batch-within-batch.ts"));
      expect(findings.length).toBeGreaterThan(0);
    });

    it("flags notification-storm shape (array of notification objects, no id)", () => {
      const src = `function handleRpc(messages) {
        if (Array.isArray(messages)) {
          messages.forEach((n) => notify(n.method, n.params));
        }
      }`;
      const findings = runN1(src);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe("true negatives", () => {
    it("does NOT flag handler with explicit length guard", () => {
      const findings = runN1(loadFixture("tn-length-guard-present.ts"));
      expect(findings.filter((f) => f.rule_id === "N1")).toHaveLength(0);
    });

    it("does NOT flag handler with throttle wrapper", () => {
      const findings = runN1(loadFixture("tn-throttled-dispatch.ts"));
      expect(findings.filter((f) => f.rule_id === "N1")).toHaveLength(0);
    });

    it("does NOT flag single-request (non-batch) handlers", () => {
      const src = `function handleOne(req) { return processRequest(req); }`;
      const findings = runN1(src);
      expect(findings).toHaveLength(0);
    });

    it("does NOT flag test fixtures (__tests__ marker)", () => {
      const src = `// __tests__ marker\nfunction handleRpc(request) { if (Array.isArray(request.batch)) request.batch.forEach(m => m); }`;
      const findings = runN1(src);
      expect(findings).toHaveLength(0);
    });
  });

  describe("evidence chain shape", () => {
    it("produces a chain with source, sink, mitigation, impact and at least one factor", () => {
      const findings = runN1(loadFixture("tp-forEach-without-limit.ts"));
      expect(findings.length).toBeGreaterThan(0);

      // Chain is carried on the RuleResult
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain).toBeDefined();

      const kinds = new Set(chain.links.map((l: EvidenceLink) => l.type));
      expect(kinds.has("source")).toBe(true);
      expect(kinds.has("sink")).toBe(true);
      expect(kinds.has("mitigation")).toBe(true);
      expect(kinds.has("impact")).toBe(true);

      expect(chain.confidence_factors.length).toBeGreaterThanOrEqual(1);
      const factorNames = chain.confidence_factors.map((f) => f.factor);
      expect(factorNames).toContain("unbounded_batch_iteration");
    });

    it("respects the CHARTER confidence ceiling (≤ 0.90)", () => {
      const findings = runN1(loadFixture("tp-forEach-without-limit.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.confidence).toBeLessThanOrEqual(0.90);
      expect(chain.confidence).toBeGreaterThanOrEqual(0.05);
    });

    it("every evidence link location is a structured Location, not prose", () => {
      const findings = runN1(loadFixture("tp-forEach-without-limit.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      for (const link of chain.links) {
        if ("location" in link) {
          expect(isLocation(link.location), `${link.type} link carries a Location`).toBe(true);
        }
      }
    });

    it("every verification step target is a structured Location, not prose", () => {
      const findings = runN1(loadFixture("tp-forEach-without-limit.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.verification_steps).toBeDefined();
      expect(chain.verification_steps!.length).toBeGreaterThanOrEqual(2);
      for (const step of chain.verification_steps!) {
        expect(isLocation(step.target), "verification step target is a Location").toBe(true);
      }
    });

    it("threat reference points at the JSON-RPC 2.0 batch spec", () => {
      const findings = runN1(loadFixture("tp-forEach-without-limit.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.threat_reference).toBeDefined();
      expect(chain.threat_reference!.id).toContain("JSONRPC");
    });
  });
});
