/**
 * N2 — Notification Flooding: per-rule unit tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { AnalysisContext } from "../../../../engine.js";
import type { EvidenceChain, EvidenceLink } from "../../../../evidence.js";
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

function runN2(src: string) {
  const rule = getTypedRuleV2("N2");
  expect(rule).toBeDefined();
  return rule!.analyze(ctx(src));
}

function isStructuredTarget(t: string): boolean {
  return /^source_code:line \d+(:column \d+)?$/.test(t);
}

describe("N2 — JSON-RPC Notification Flooding", () => {
  describe("true positives", () => {
    it("flags while-forever producer without throttle", () => {
      const findings = runN2(loadFixture("tp-while-forever.ts"));
      expect(findings.length).toBeGreaterThan(0);
    });

    it("flags setInterval-producer (CHARTER edge case)", () => {
      const findings = runN2(loadFixture("tp-setinterval-producer.ts"));
      expect(findings.length).toBeGreaterThan(0);
    });

    it("flags notification-storm-via-batch-reply (CHARTER edge case)", () => {
      const findings = runN2(loadFixture("tp-notification-storm-via-batch.ts"));
      expect(findings.length).toBeGreaterThan(0);
    });

    it("flags emit in classic while loop", () => {
      const findings = runN2(`declare const emit: (e: unknown) => void; declare const running: boolean; while (running) { emit("update"); }`);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe("true negatives", () => {
    it("does NOT flag throttled producer", () => {
      const findings = runN2(loadFixture("tn-throttled-producer.ts"));
      expect(findings).toHaveLength(0);
    });

    it("does NOT flag debounced producer", () => {
      const findings = runN2(loadFixture("tn-debounced-producer.ts"));
      expect(findings).toHaveLength(0);
    });

    it("does NOT flag notification outside any loop", () => {
      const findings = runN2(`declare const notify: (m: unknown) => void; export function once() { notify({ a: 1 }); }`);
      expect(findings).toHaveLength(0);
    });
  });

  describe("evidence chain shape", () => {
    it("produces source + sink + mitigation + impact and required factor", () => {
      const findings = runN2(loadFixture("tp-while-forever.ts"));
      expect(findings.length).toBeGreaterThan(0);
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      const kinds = new Set(chain.links.map((l: EvidenceLink) => l.type));
      expect(kinds.has("source")).toBe(true);
      expect(kinds.has("sink")).toBe(true);
      expect(kinds.has("mitigation")).toBe(true);
      expect(kinds.has("impact")).toBe(true);
      expect(chain.confidence_factors.map((f) => f.factor)).toContain(
        "notification_emission_in_unbounded_loop",
      );
    });

    it("respects CHARTER confidence ceiling (≤ 0.85)", () => {
      const findings = runN2(loadFixture("tp-while-forever.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.confidence).toBeLessThanOrEqual(0.85);
    });

    it("every verification target is a structured Location", () => {
      const findings = runN2(loadFixture("tp-while-forever.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.verification_steps).toBeDefined();
      expect(chain.verification_steps!.length).toBeGreaterThanOrEqual(3);
      for (const step of chain.verification_steps!) {
        expect(isStructuredTarget(step.target)).toBe(true);
      }
    });
  });
});
