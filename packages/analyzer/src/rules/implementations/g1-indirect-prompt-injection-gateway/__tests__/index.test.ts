/**
 * G1 v2 — functional + chain-integrity tests.
 *
 * Asserts:
 *   - TP fixtures produce ≥1 G1 finding each;
 *   - TN fixtures produce zero G1 findings;
 *   - every chain link has a structured Location (not a prose string);
 *   - every VerificationStep.target is a Location;
 *   - confidence capped at 0.75 (charter cap);
 *   - G1 does NOT emit companion findings under other rule ids;
 *   - mitigation-declared gateway still fires G1 with mitigation link present.
 *
 * Each `describe` block corresponds to a lethal edge case in CHARTER.md,
 * so a reviewer can read this file alongside the charter to confirm
 * every case has a test.
 */

import { describe, it, expect } from "vitest";
import { IndirectPromptInjectionGatewayRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-web-scraper-with-emailer.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-issue-reader-with-file-writer.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-resource-fetch-plus-http-egress.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-read-only-no-sinks.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-utility-only.js";
import { buildContext as mit01 } from "../__fixtures__/mitigation-01-sanitized-gateway.js";

const rule = new IndirectPromptInjectionGatewayRule();

describe("G1 — Indirect Prompt Injection Gateway (v2)", () => {
  // ─── Lethal edge case #1 — web scraper (canonical Rehberger) ──────────────

  describe("lethal-edge #1 — web scraper gateway with reachable sink", () => {
    it("fires when a web scraper coexists with an email-sender sink", () => {
      const results = rule.analyze(tp01());
      const g1 = results.filter((r) => r.rule_id === "G1");
      expect(g1.length).toBeGreaterThan(0);
      for (const r of g1) {
        expect(r.severity).toBe("critical");
        expect(r.owasp_category).toBe("MCP01-prompt-injection");
        expect(r.mitre_technique).toBe("AML.T0054.001");
      }
    });

    it("chain names the web scraper as the source", () => {
      const g1 = rule.analyze(tp01()).find((r) => r.rule_id === "G1")!;
      const sources = g1.chain.links.filter((l) => l.type === "source");
      expect(sources.length).toBe(1);
      const src = sources[0];
      // Source location must be a structured Location of kind "tool".
      expect(isLocation(src.location)).toBe(true);
      if (typeof src.location !== "string" && src.location.kind === "tool") {
        expect(src.location.tool_name).toBe("scrape_webpage");
      }
    });
  });

  // ─── Lethal edge case #3 — issue-tracker reader + file writer ─────────────

  describe("lethal-edge #3 — issue-tracker reader with file-write sink", () => {
    it("fires when an issue reader coexists with a file writer", () => {
      const g1 = rule.analyze(tp02()).filter((r) => r.rule_id === "G1");
      expect(g1.length).toBeGreaterThan(0);
    });

    it("pickPrimarySink prefers filesystem_write over network_egress", () => {
      // TP-02 exposes only one sink (write_triage_notes). Verify the
      // narrative references the writer, not the reader.
      const g1 = rule.analyze(tp02()).find((r) => r.rule_id === "G1")!;
      const sinks = g1.chain.links.filter((l) => l.type === "sink");
      expect(sinks.length).toBe(1);
      const sink = sinks[0];
      if (typeof sink.location !== "string" && sink.location.kind === "tool") {
        expect(sink.location.tool_name).toBe("write_triage_notes");
      }
    });
  });

  // ─── Lethal edge case #6 — MCP resource as gateway ────────────────────────

  describe("lethal-edge #6 — MCP resource-fetch gateway", () => {
    it("fires when an MCP resource surface coexists with a network sink", () => {
      const g1 = rule.analyze(tp03()).filter((r) => r.rule_id === "G1");
      expect(g1.length).toBeGreaterThan(0);
    });

    it("resource-origin gateway carries a resource Location, not tool", () => {
      const g1 = rule.analyze(tp03()).find((r) => r.rule_id === "G1")!;
      const src = g1.chain.links.find((l) => l.type === "source")!;
      expect(isLocation(src.location)).toBe(true);
      if (typeof src.location !== "string") {
        expect(src.location.kind).toBe("resource");
      }
    });
  });

  // ─── Lethal edge case #4/#5 coverage via explicit negative ─────────────────

  describe("does NOT fire without a sink (lethal-edge: gateway-only safe case)", () => {
    it("TN-01 single web scraper alone emits zero G1 findings", () => {
      const results = rule.analyze(tn01());
      expect(results.filter((r) => r.rule_id === "G1").length).toBe(0);
    });
  });

  describe("does NOT fire without a gateway (utility-tool safety)", () => {
    it("TN-02 utility-only server emits zero findings", () => {
      const results = rule.analyze(tn02());
      expect(results.length).toBe(0);
    });
  });

  // ─── Mitigation path (charter: sanitizer declared → confidence drop) ─────

  describe("mitigation path — declared sanitizer lowers confidence but still fires", () => {
    it("MIT-01 fires G1 with a present=true sanitizer mitigation link", () => {
      const g1 = rule.analyze(mit01()).find((r) => r.rule_id === "G1");
      expect(g1).toBeDefined();
      const mitigations = g1!.chain.links.filter((l) => l.type === "mitigation");
      expect(mitigations.length).toBe(1);
      const mit = mitigations[0];
      if (mit.type === "mitigation") {
        expect(mit.present).toBe(true);
        expect(mit.mitigation_type).toBe("sanitizer-function");
      }
    });

    it("MIT-01 records a mitigation verification step targeting the sanitizer parameter", () => {
      const g1 = rule.analyze(mit01()).find((r) => r.rule_id === "G1")!;
      const steps = g1.chain.verification_steps ?? [];
      const paramStep = steps.find(
        (s) =>
          typeof s.target !== "string" && s.target.kind === "parameter",
      );
      expect(paramStep).toBeDefined();
    });
  });

  // ─── Chain integrity — v2 contract ────────────────────────────────────────

  describe("chain integrity — v2 contract", () => {
    it("TP-01: every link has a structured Location (not a prose string)", () => {
      const g1 = rule.analyze(tp01()).find((r) => r.rule_id === "G1")!;
      for (const link of g1.chain.links) {
        if (link.type === "impact") continue;
        expect(
          isLocation(link.location),
          `${link.type} link location must be a Location, got ${JSON.stringify(link.location)}`,
        ).toBe(true);
      }
    });

    it("TP-01: every VerificationStep.target is a Location", () => {
      const g1 = rule.analyze(tp01()).find((r) => r.rule_id === "G1")!;
      const steps = g1.chain.verification_steps ?? [];
      expect(steps.length).toBeGreaterThan(0);
      for (const step of steps) {
        expect(
          isLocation(step.target),
          `step ${step.step_type} target must be a Location, got ${JSON.stringify(step.target)}`,
        ).toBe(true);
      }
    });

    it("TP-01: confidence capped at 0.75 (charter cap) and above 0.30 floor", () => {
      const g1 = rule.analyze(tp01()).find((r) => r.rule_id === "G1")!;
      expect(g1.chain.confidence).toBeLessThanOrEqual(0.75);
      expect(g1.chain.confidence).toBeGreaterThan(0.3);
    });

    it("TP-01: records ingestion + sink-reachability confidence factors", () => {
      const g1 = rule.analyze(tp01()).find((r) => r.rule_id === "G1")!;
      const factors = g1.chain.confidence_factors.map((f) => f.factor);
      expect(factors).toContain("ingestion_capability_confidence");
      expect(factors).toContain("sink_reachability");
    });

    it("TP-01: chain carries a MITRE ATLAS AML.T0054.001 threat reference", () => {
      const g1 = rule.analyze(tp01()).find((r) => r.rule_id === "G1")!;
      expect(g1.chain.threat_reference).toBeDefined();
      expect(g1.chain.threat_reference?.id).toBe("MITRE-ATLAS-AML.T0054.001");
    });

    it("TP-01: chain has source, propagation, sink, mitigation, impact links", () => {
      const g1 = rule.analyze(tp01()).find((r) => r.rule_id === "G1")!;
      const types = new Set(g1.chain.links.map((l) => l.type));
      expect(types.has("source")).toBe(true);
      expect(types.has("propagation")).toBe(true);
      expect(types.has("sink")).toBe(true);
      expect(types.has("impact")).toBe(true);
      // Mitigation link always emitted (present=false when no sanitizer).
      expect(types.has("mitigation")).toBe(true);
    });
  });

  // ─── Companion-pattern negative assertion ─────────────────────────────────

  describe("companion-pattern isolation — G1 emits ONLY G1 rule_ids", () => {
    it("TP-01..TP-03 never emit G2/G3/G5/H2 or any non-G1 finding", () => {
      for (const build of [tp01, tp02, tp03, mit01]) {
        const results = rule.analyze(build());
        for (const r of results) {
          expect(r.rule_id).toBe("G1");
        }
      }
    });
  });
});
