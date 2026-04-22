/**
 * N3 — JSON-RPC Request ID Collision unit tests.
 *
 * This rule was bug-misaligned in the legacy jsonrpc-protocol-v2.ts file
 * (that implementation targeted progress tokens, which is N7's concern).
 * The new implementation matches rules/N3-jsonrpc-id-collision.yaml: it
 * detects predictable request-id generators.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { AnalysisContext } from "../../../../engine.js";
import type { EvidenceChain, EvidenceLink } from "../../../../evidence.js";
import { isLocation } from "../../../location.js";
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

function runN3(src: string) {
  const rule = getTypedRuleV2("N3");
  expect(rule).toBeDefined();
  return rule!.analyze(ctx(src));
}

// Locations validated via `isLocation` (Rule Standard v2 §2/§4).

describe("N3 — JSON-RPC Request ID Collision", () => {
  describe("true positives (CHARTER lethal edge cases)", () => {
    it("flags sequential counter increment", () => {
      const f = runN3(loadFixture("tp-counter-increment.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags Date.now as id (date-now-as-id edge case)", () => {
      const f = runN3(loadFixture("tp-date-now-id.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags two-statement `this._request_id += 1; id = this._request_id` form", () => {
      const f = runN3(loadFixture("tp-two-statement-form.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags requestId assigned plain integer literal", () => {
      const f = runN3(`export function send() { const requestId = 42; return { jsonrpc: "2.0", id: requestId, method: "x" }; }`);
      expect(f.length).toBeGreaterThan(0);
    });
  });

  describe("true negatives", () => {
    it("does NOT flag crypto.randomUUID()", () => {
      expect(runN3(loadFixture("tn-crypto-randomuuid.ts"))).toHaveLength(0);
    });

    it("does NOT flag nanoid()", () => {
      expect(runN3(loadFixture("tn-nanoid.ts"))).toHaveLength(0);
    });

    it("does NOT flag non-id variable increments", () => {
      expect(runN3(`let counter = 0; counter++; const total = counter;`)).toHaveLength(0);
    });
  });

  describe("evidence chain shape", () => {
    it("produces source + sink + mitigation + impact", () => {
      const findings = runN3(loadFixture("tp-counter-increment.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      const kinds = new Set(chain.links.map((l: EvidenceLink) => l.type));
      expect(kinds.has("source")).toBe(true);
      expect(kinds.has("sink")).toBe(true);
      expect(kinds.has("mitigation")).toBe(true);
      expect(kinds.has("impact")).toBe(true);
      expect(chain.confidence_factors.map((f) => f.factor)).toContain(
        "predictable_request_id_generator",
      );
    });

    it("sink link carries the CVE-2025-6515 precedent", () => {
      const findings = runN3(loadFixture("tp-counter-increment.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      const sink = chain.links.find((l) => l.type === "sink") as any;
      expect(sink).toBeDefined();
      expect(sink.cve_precedent).toBe("CVE-2025-6515");
    });

    it("confidence respects CHARTER ceiling (≤ 0.85)", () => {
      const findings = runN3(loadFixture("tp-counter-increment.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.confidence).toBeLessThanOrEqual(0.85);
    });

    it("evidence link locations are structured Locations", () => {
      const findings = runN3(loadFixture("tp-counter-increment.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      for (const link of chain.links) {
        if ("location" in link) {
          expect(isLocation(link.location), `${link.type} link Location`).toBe(true);
        }
      }
    });

    it("verification step targets are structured Locations", () => {
      const findings = runN3(loadFixture("tp-counter-increment.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      for (const step of chain.verification_steps ?? []) {
        expect(isLocation(step.target), "verification step target").toBe(true);
      }
    });
  });
});
