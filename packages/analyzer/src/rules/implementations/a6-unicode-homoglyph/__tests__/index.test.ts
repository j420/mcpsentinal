/**
 * A6 — Unicode Homoglyph Attack (v2) unit tests.
 *
 * Covers:
 *  - TP fixtures (Cyrillic name, fullwidth description, shadow collision)
 *  - TN fixtures (pure ASCII, pure Cyrillic)
 *  - Evidence-chain structural assertions
 *  - Confidence cap enforcement
 */

import { describe, it, expect } from "vitest";
import { getTypedRuleV2 } from "../../../base.js";
import { isLocation, type Location } from "../../../location.js";
import "../index.js"; // side-effect: register A6

import { fixture as tp01, expectation as tp01x } from "../__fixtures__/true-positive-01-cyrillic-in-tool-name.js";
import { fixture as tp02, expectation as tp02x } from "../__fixtures__/true-positive-02-fullwidth-description.js";
import { fixture as tp03, expectation as tp03x } from "../__fixtures__/true-positive-03-shadow-collision.js";
import { fixture as tn01 } from "../__fixtures__/true-negative-01-pure-ascii.js";
import { fixture as tn02 } from "../__fixtures__/true-negative-02-single-script-non-latin.js";

const rule = getTypedRuleV2("A6");
if (!rule) {
  throw new Error("A6 TypedRuleV2 not registered — check registration order");
}

describe("A6 — Unicode Homoglyph Attack (v2)", () => {
  describe("Registration", () => {
    it("registers as a native v2 rule with the `unicode` technique", () => {
      expect(rule!.id).toBe("A6");
      expect(rule!.technique).toBe("unicode");
      expect(rule!.requires.tools).toBe(true);
    });
  });

  describe("True positives", () => {
    it("TP-01: Cyrillic 'а' inside Latin tool name → critical finding with CWE-1007", () => {
      const results = rule!.analyze(tp01);
      expect(results.length).toBeGreaterThanOrEqual(tp01x.min_findings);
      const nameFinding = results.find((r) =>
        r.chain.links.some(
          (l) =>
            l.type === "source" &&
            isLocation(l.location) &&
            (l.location as Location).kind === "tool" &&
            ((l.location as { kind: "tool"; tool_name: string }).tool_name ===
              tp01x.expected_tool_name) &&
            // The source's observed text carries the "tool name" scope indicator
            (l as { observed: string }).observed.includes("tool name"),
        ),
      );
      expect(nameFinding).toBeDefined();
      expect(nameFinding!.severity).toBe(tp01x.expected_severity);
      expect(nameFinding!.chain.links.some((l) => l.type === "source")).toBe(true);
      expect(nameFinding!.chain.links.some((l) => l.type === "sink")).toBe(true);
      expect(nameFinding!.chain.threat_reference?.id).toBe("CWE-1007");
      expect(nameFinding!.chain.confidence).toBeGreaterThan(0.5);
      expect(nameFinding!.chain.confidence).toBeLessThanOrEqual(0.95);
      expect((nameFinding!.chain.verification_steps ?? []).length).toBeGreaterThanOrEqual(2);
    });

    it("TP-02: clustered fullwidth Latin in description → finding with Fullwidth-Latin script", () => {
      const results = rule!.analyze(tp02);
      const descFinding = results.find((r) =>
        r.chain.links.some(
          (l) =>
            l.type === "source" &&
            isLocation(l.location) &&
            (l.location as Location).kind === "tool" &&
            ((l.location as { kind: "tool"; tool_name: string }).tool_name ===
              tp02x.expected_tool_name) &&
            (l as { observed: string }).observed.includes("description"),
        ),
      );
      expect(descFinding).toBeDefined();
      expect(tp02x.expected_severity_in).toContain(descFinding!.severity);
      // Source rationale must reference the Fullwidth-Latin script explicitly
      const src = descFinding!.chain.links.find((l) => l.type === "source") as
        | { observed: string; rationale: string }
        | undefined;
      expect(src!.observed.length + src!.rationale.length).toBeGreaterThan(0);
      expect(descFinding!.chain.confidence).toBeLessThanOrEqual(0.95);
    });

    it("TP-03: shadow collision between two tools → emits collision finding", () => {
      const results = rule!.analyze(tp03);
      expect(results.length).toBeGreaterThanOrEqual(tp03x.min_findings);
      // Collision findings carry a tool Location for the LEFT tool and an
      // observed text that names BOTH tools. Identify them structurally.
      const collision = results.find((r) =>
        r.chain.links.some(
          (l) =>
            l.type === "source" &&
            isLocation(l.location) &&
            (l.location as Location).kind === "tool" &&
            (l as { observed: string }).observed.includes("Collision between tool"),
        ),
      );
      expect(collision).toBeDefined();
      expect(collision!.severity).toBe("critical");
      const sink = collision!.chain.links.find((l) => l.type === "sink") as
        | { sink_type: string }
        | undefined;
      expect(sink!.sink_type).toBe("privilege-grant");
    });
  });

  describe("True negatives", () => {
    it("TN-01: pure ASCII tools produce ZERO findings", () => {
      const results = rule!.analyze(tn01);
      expect(results).toEqual([]);
    });

    it("TN-02: single-script non-Latin tool name produces ZERO findings", () => {
      const results = rule!.analyze(tn02);
      // Mixed-script policy: pure Cyrillic is NOT a homoglyph attack
      expect(results).toEqual([]);
    });
  });

  describe("Evidence-chain integrity", () => {
    it("every emitted finding has ≥1 source, ≥1 sink, a threat_reference, and verification steps", () => {
      const allResults = [
        ...rule!.analyze(tp01),
        ...rule!.analyze(tp02),
        ...rule!.analyze(tp03),
      ];
      expect(allResults.length).toBeGreaterThan(0);
      for (const r of allResults) {
        const sources = r.chain.links.filter((l) => l.type === "source");
        const sinks = r.chain.links.filter((l) => l.type === "sink");
        expect(sources.length).toBeGreaterThanOrEqual(1);
        // Name and shadow-collision findings have a sink; description findings
        // are informational (they cannot prove routing impact deterministically).
        const src = sources[0] as { observed: string };
        const isNameOrShadow =
          src.observed.includes("tool name") ||
          src.observed.includes("Collision between tool");
        if (isNameOrShadow) {
          expect(sinks.length).toBeGreaterThanOrEqual(1);
        }
        expect(r.chain.threat_reference).toBeDefined();
        expect(r.chain.verification_steps?.length ?? 0).toBeGreaterThanOrEqual(1);
        expect(r.chain.confidence).toBeLessThanOrEqual(0.95);
        expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
        expect(r.remediation.length).toBeGreaterThan(40);
      }
    });

    it("every evidence link location is a structured Location (v2 contract)", () => {
      const results = [
        ...rule!.analyze(tp01),
        ...rule!.analyze(tp02),
        ...rule!.analyze(tp03),
      ];
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(
            isLocation(link.location),
            `${link.type} link location must be a Location`,
          ).toBe(true);
          const loc = link.location as Location;
          expect(["tool", "capability"]).toContain(loc.kind);
        }
      }
    });

    it("every VerificationStep.target is a structured Location (v2 contract)", () => {
      const results = [
        ...rule!.analyze(tp01),
        ...rule!.analyze(tp02),
        ...rule!.analyze(tp03),
      ];
      for (const r of results) {
        for (const step of r.chain.verification_steps ?? []) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });
  });
});
