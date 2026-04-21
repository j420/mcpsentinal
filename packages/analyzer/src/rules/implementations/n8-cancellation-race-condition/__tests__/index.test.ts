/**
 * N8 — Cancellation Race Condition tests.
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

function ctx(src: string): AnalysisContext {
  return {
    server: { id: "t", name: "test", description: null, github_url: null },
    tools: [],
    source_code: src,
    dependencies: [],
    connection_metadata: null,
  };
}

function runN8(src: string) {
  const rule = getTypedRuleV2("N8");
  expect(rule).toBeDefined();
  return rule!.analyze(ctx(src));
}

function isStructuredTarget(t: string): boolean {
  return /^source_code:line \d+(:column \d+)?$/.test(t);
}

describe("N8 — Cancellation Race Condition", () => {
  describe("true positives (CHARTER lethal edge cases)", () => {
    it("flags named cancel handler that deletes (cancel-after-commit)", () => {
      const f = runN8(loadFixture("tp-cancel-handler-deletes.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags AbortSignal-guarded write path (abortsignal-without-transaction)", () => {
      const f = runN8(loadFixture("tp-abortsignal-write-path.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags catch(AbortError) that deletes (cleanup-in-catch-without-state-check)", () => {
      const f = runN8(loadFixture("tp-catch-abort-error-delete.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags addEventListener('cancel', handler) with a mutation in the handler", () => {
      const f = runN8(`declare const target: { addEventListener(ev: string, fn: (e: unknown) => void): void }; declare const db: { delete(id: string): Promise<void> };
        target.addEventListener("cancel", () => { db.delete("x"); });`);
      expect(f.length).toBeGreaterThan(0);
    });
  });

  describe("true negatives", () => {
    it("does NOT flag transaction-wrapped mutation", () => {
      expect(runN8(loadFixture("tn-transaction-rollback.ts"))).toHaveLength(0);
    });

    it("does NOT flag mutex-guarded mutation", () => {
      expect(runN8(loadFixture("tn-mutex-guarded.ts"))).toHaveLength(0);
    });

    it("does NOT flag cancel handler that only logs", () => {
      const f = runN8(`declare const logger: { info(msg: string): void };
        export function handleCancel(id: string) { logger.info("cancelled: " + id); }`);
      expect(f).toHaveLength(0);
    });
  });

  describe("evidence chain shape", () => {
    it("chain includes source + propagation + sink + mitigation + impact", () => {
      const findings = runN8(loadFixture("tp-cancel-handler-deletes.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      const kinds = new Set(chain.links.map((l: EvidenceLink) => l.type));
      expect(kinds.has("source")).toBe(true);
      expect(kinds.has("propagation")).toBe(true);
      expect(kinds.has("sink")).toBe(true);
      expect(kinds.has("mitigation")).toBe(true);
      expect(kinds.has("impact")).toBe(true);
      expect(chain.confidence_factors.map((f) => f.factor)).toContain(
        "cancellation_without_atomic_guard",
      );
    });

    it("confidence respects CHARTER ceiling (≤ 0.80)", () => {
      const findings = runN8(loadFixture("tp-cancel-handler-deletes.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.confidence).toBeLessThanOrEqual(0.80);
    });

    it("verification step targets are structured Locations", () => {
      const findings = runN8(loadFixture("tp-cancel-handler-deletes.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      for (const step of chain.verification_steps ?? []) {
        expect(isStructuredTarget(step.target)).toBe(true);
      }
    });
  });
});
