/**
 * N10 — Incomplete Handshake DoS tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { AnalysisContext } from "../../../../engine.js";
import type { EvidenceChain, EvidenceLink } from "../../../../evidence.js";
import "../index.js";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation } from "../../../location.js";

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

function runN10(src: string) {
  const rule = getTypedRuleV2("N10");
  expect(rule).toBeDefined();
  return rule!.analyze(ctx(src));
}

// Locations validated via `isLocation` (Rule Standard v2 §2/§4).

describe("N10 — Incomplete Handshake DoS", () => {
  describe("true positives (CHARTER lethal edge cases)", () => {
    it("flags WebSocketServer without handshakeTimeout", () => {
      const f = runN10(loadFixture("tp-websocket-no-deadline.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags http.createServer without maxConnections or requestTimeout", () => {
      const f = runN10(loadFixture("tp-http-no-maxconnections.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags createServer gateway with while-not-initialized loop", () => {
      const f = runN10(loadFixture("tp-initialise-loop-no-deadline.ts"));
      expect(f.length).toBeGreaterThan(0);
    });

    it("flags net.createServer without per-socket timeout", () => {
      const f = runN10(`import * as net from "node:net";
        export function start() { net.createServer((socket) => { socket.on("data", () => {}); }).listen(9000); }`);
      expect(f.length).toBeGreaterThan(0);
    });
  });

  describe("true negatives", () => {
    it("does NOT flag WebSocketServer configured with handshakeTimeout", () => {
      expect(runN10(loadFixture("tn-ws-handshake-timeout.ts"))).toHaveLength(0);
    });

    it("does NOT flag http server with requestTimeout + maxConnections", () => {
      expect(runN10(loadFixture("tn-http-requesttimeout.ts"))).toHaveLength(0);
    });

    it("does NOT flag AbortSignal.timeout-guarded accept", () => {
      const f = runN10(`import * as http from "node:http";
        export function start(): void {
          const server = http.createServer(async (req, res) => {
            const signal = AbortSignal.timeout(30000);
            void signal; res.end("ok");
          });
          server.listen(3000);
        }`);
      expect(f).toHaveLength(0);
    });
  });

  describe("evidence chain shape", () => {
    it("chain includes source + sink + mitigation + impact with required factor", () => {
      const findings = runN10(loadFixture("tp-http-no-maxconnections.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      const kinds = new Set(chain.links.map((l: EvidenceLink) => l.type));
      expect(kinds.has("source")).toBe(true);
      expect(kinds.has("sink")).toBe(true);
      expect(kinds.has("mitigation")).toBe(true);
      expect(kinds.has("impact")).toBe(true);
      expect(chain.confidence_factors.map((f) => f.factor)).toContain(
        "handshake_deadline_absent",
      );
    });

    it("confidence respects CHARTER ceiling (≤ 0.82)", () => {
      const findings = runN10(loadFixture("tp-http-no-maxconnections.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      expect(chain.confidence).toBeLessThanOrEqual(0.82);
    });

    it("evidence link locations are structured Locations", () => {
      const findings = runN10(loadFixture("tp-http-no-maxconnections.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      for (const link of chain.links) {
        if ("location" in link) {
          expect(isLocation(link.location), `${link.type} link Location`).toBe(true);
        }
      }
    });

    it("every verification step target is a structured Location", () => {
      const findings = runN10(loadFixture("tp-http-no-maxconnections.ts"));
      const chain = (findings[0] as unknown as { chain: EvidenceChain }).chain;
      for (const step of chain.verification_steps ?? []) {
        expect(isLocation(step.target), "verification step target").toBe(true);
      }
    });
  });
});
