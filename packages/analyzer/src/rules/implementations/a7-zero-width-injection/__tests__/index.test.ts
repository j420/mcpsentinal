/**
 * A7 — Zero-Width / Invisible Character Injection (v2) unit tests.
 *
 * Covers:
 *  - TP fixtures (ZWSP in name, tag-decoded hidden message, bidi override)
 *  - TN fixtures (plain ASCII, legitimate emoji ZWJ sequence)
 *  - Evidence-chain structural assertions
 *  - Confidence cap enforcement
 *  - Location structure: `tool:<name>:<field>` or `tool:<name>:parameter:<p>:description`
 */

import { describe, it, expect } from "vitest";
import { getTypedRuleV2 } from "../../../base.js";
import "../index.js";

import { fixture as tp01, expectation as tp01x } from "../__fixtures__/true-positive-01-zwsp-in-tool-name.js";
import { fixture as tp02, expectation as tp02x } from "../__fixtures__/true-positive-02-tag-hidden-message.js";
import { fixture as tp03, expectation as tp03x } from "../__fixtures__/true-positive-03-bidi-override.js";
import { fixture as tn01 } from "../__fixtures__/true-negative-01-plain-ascii.js";
import { fixture as tn02 } from "../__fixtures__/true-negative-02-emoji-zwj-sequence.js";

const rule = getTypedRuleV2("A7");
if (!rule) {
  throw new Error("A7 TypedRuleV2 not registered — check registration order");
}

describe("A7 — Zero-Width / Invisible Character Injection (v2)", () => {
  describe("Registration", () => {
    it("registers as a native v2 rule with the `unicode` technique", () => {
      expect(rule!.id).toBe("A7");
      expect(rule!.technique).toBe("unicode");
      expect(rule!.requires.tools).toBe(true);
    });
  });

  describe("True positives", () => {
    it("TP-01: ZWSP in tool name → critical finding at tool:<name>:name location", () => {
      const results = rule!.analyze(tp01);
      expect(results.length).toBeGreaterThanOrEqual(tp01x.min_findings);
      const nameFinding = results.find((r) => {
        const src = r.chain.links.find((l) => l.type === "source") as any;
        return src && typeof src.location === "string" && src.location.endsWith(":name");
      });
      expect(nameFinding).toBeDefined();
      expect(nameFinding!.severity).toBe(tp01x.expected_severity);
      // ZWSP is class zero-width — the source observed field should mention ZWSP or U+200B
      const src = nameFinding!.chain.links.find((l) => l.type === "source") as any;
      expect(String(src.observed)).toContain("U+200B");
    });

    it("TP-02: tag-character hidden ASCII message → severity=critical + hidden_tag factor", () => {
      const results = rule!.analyze(tp02);
      expect(results.length).toBeGreaterThanOrEqual(tp02x.min_findings);
      const descFinding = results.find((r) => {
        const src = r.chain.links.find((l) => l.type === "source") as any;
        return src && typeof src.location === "string" && src.location.endsWith(":description");
      });
      expect(descFinding).toBeDefined();
      expect(descFinding!.severity).toBe("critical");
      const src = descFinding!.chain.links.find((l) => l.type === "source") as any;
      expect(String(src.rationale)).toContain(tp02x.expected_hidden_message);
      const hasHiddenFactor = descFinding!.chain.confidence_factors.some(
        (f) => f.factor === "hidden_tag_message_decoded",
      );
      expect(hasHiddenFactor).toBe(true);
    });

    it("TP-03: bidi override → dedicated finding citing CVE-2021-42574", () => {
      const results = rule!.analyze(tp03);
      const bidiFinding = results.find(
        (r) =>
          (r.chain.threat_reference?.id ?? "").includes(tp03x.expected_reference_contains),
      );
      expect(bidiFinding).toBeDefined();
      expect(bidiFinding!.severity).toBe(tp03x.expected_severity);
      const sink = bidiFinding!.chain.links.find((l) => l.type === "sink") as any;
      expect(sink.sink_type).toBe("code-evaluation");
    });
  });

  describe("True negatives", () => {
    it("TN-01: plain ASCII produces ZERO findings", () => {
      const results = rule!.analyze(tn01);
      expect(results).toEqual([]);
    });

    it("TN-02: ZWJ between emoji codepoints is suppressed — ZERO findings", () => {
      const results = rule!.analyze(tn02);
      expect(results).toEqual([]);
    });
  });

  describe("Evidence-chain integrity", () => {
    it("every emitted finding has ≥1 source, ≥1 sink, a threat_reference, and verification steps", () => {
      const all = [
        ...rule!.analyze(tp01),
        ...rule!.analyze(tp02),
        ...rule!.analyze(tp03),
      ];
      expect(all.length).toBeGreaterThan(0);
      for (const r of all) {
        const sources = r.chain.links.filter((l) => l.type === "source");
        const sinks = r.chain.links.filter((l) => l.type === "sink");
        expect(sources.length).toBeGreaterThanOrEqual(1);
        expect(sinks.length).toBeGreaterThanOrEqual(1);
        expect(r.chain.threat_reference).toBeDefined();
        expect(r.chain.verification_steps?.length ?? 0).toBeGreaterThanOrEqual(1);
        expect(r.chain.confidence).toBeLessThanOrEqual(0.95);
        expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
        expect(r.remediation.length).toBeGreaterThan(40);
      }
    });

    it("source Locations use the `tool:<name>:(name|description)` or parameter pattern", () => {
      const all = [...rule!.analyze(tp01), ...rule!.analyze(tp02), ...rule!.analyze(tp03)];
      for (const r of all) {
        const src = r.chain.links.find((l) => l.type === "source") as any;
        expect(typeof src.location).toBe("string");
        const ok =
          /^tool:[^:]+:(name|description)$/.test(src.location) ||
          /^tool:[^:]+:parameter:[^:]+:description$/.test(src.location);
        expect(ok).toBe(true);
      }
    });
  });
});
