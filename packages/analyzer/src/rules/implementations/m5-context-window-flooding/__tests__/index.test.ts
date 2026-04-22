/** M5 v2 — context window flooding tests. */
import { describe, it, expect } from "vitest";
import { M5ContextWindowFloodingRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import { gatherM5, tokenise, matchSignals, detectPagination } from "../gather.js";

import { fixture as tp01 } from "../__fixtures__/true-positive-01-unbounded-all.js";
import { fixture as tp02 } from "../__fixtures__/true-positive-02-schema-unbounded.js";
import { fixture as tp03 } from "../__fixtures__/true-positive-03-recursive-deep.js";
import { fixture as tn01 } from "../__fixtures__/true-negative-01-pagination.js";
import { fixture as tn02 } from "../__fixtures__/true-negative-02-bounded-lookup.js";
import { fixture as tn03 } from "../__fixtures__/true-negative-03-error-diagnostic.js";

function ctx(tool: { name: string; description: string; input_schema: unknown }): AnalysisContext {
  return {
    server: { id: "srv", name: "t", description: null, github_url: null },
    tools: [{ name: tool.name, description: tool.description, input_schema: tool.input_schema as Record<string, unknown> | null }],
    source_code: null,
    source_files: null,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new M5ContextWindowFloodingRule();

describe("M5 — Context Window Flooding (v2)", () => {
  describe("true positives", () => {
    it("fires on 'returns all records ... no pagination' (TP-01)", () => {
      const findings = rule.analyze(ctx(tp01));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].rule_id).toBe("M5");
    });

    it("fires on schema with include_all unbounded flag (TP-02)", () => {
      const findings = rule.analyze(ctx(tp02));
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("fires on deep recursive + complete output (TP-03)", () => {
      const findings = rule.analyze(ctx(tp03));
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("true negatives", () => {
    it("does NOT fire when pagination mitigates (TN-01)", () => {
      const findings = rule.analyze(ctx(tn01));
      expect(findings).toHaveLength(0);
    });

    it("does NOT fire on bounded lookup (TN-02)", () => {
      const findings = rule.analyze(ctx(tn02));
      expect(findings).toHaveLength(0);
    });

    it("does NOT fire on diagnostic 'detailed error messages' only (TN-03)", () => {
      const findings = rule.analyze(ctx(tn03));
      expect(findings).toHaveLength(0);
    });
  });

  describe("evidence chain shape", () => {
    it("every non-impact link has a structured Location", () => {
      const findings = rule.analyze(ctx(tp01));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      for (const link of findings[0].chain.links) {
        if (link.type === "impact") continue;
        expect(isLocation(link.location)).toBe(true);
      }
    });

    it("every verification step target is a structured Location", () => {
      const findings = rule.analyze(ctx(tp02));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      const steps = findings[0].chain.verification_steps ?? [];
      expect(steps.length).toBeGreaterThanOrEqual(3);
      for (const step of steps) expect(isLocation(step.target)).toBe(true);
    });

    it("respects the 0.80 confidence cap", () => {
      const findings = rule.analyze(ctx(tp01));
      for (const f of findings) expect(f.chain.confidence).toBeLessThanOrEqual(0.80);
    });

    it("threat reference is CoSAI MCP-T10", () => {
      const findings = rule.analyze(ctx(tp01));
      expect(findings[0].chain.threat_reference?.id).toBe("CoSAI-MCP-T10");
    });

    it("impact link uses denial-of-service impact type", () => {
      const findings = rule.analyze(ctx(tp01));
      const impact = findings[0].chain.links.find((l) => l.type === "impact");
      expect(impact && impact.type === "impact" && impact.impact_type).toBe("denial-of-service");
    });

    it("mitigation link records pagination state", () => {
      const findings = rule.analyze(ctx(tp01));
      const mit = findings[0].chain.links.find((l) => l.type === "mitigation");
      expect(mit).toBeDefined();
    });
  });

  describe("no-pagination-is-aggravation edge case", () => {
    it("'no pagination' in description is treated as aggravation, not mitigation", () => {
      const toks = tokenise("no pagination supported, returns all records");
      const { present, noPaginationClaim } = detectPagination(toks, null);
      expect(present).toBe(false);
      expect(noPaginationClaim).toBe(true);
    });
  });

  describe("gather boundaries", () => {
    it("gatherM5 returns empty for tool with no signals", () => {
      const sites = gatherM5(ctx({ name: "x", description: "a simple getter", input_schema: null }));
      expect(sites).toHaveLength(0);
    });

    it("matchSignals finds multiple flood signal classes", () => {
      const toks = tokenise("returns all records with detailed output and full export");
      const matches = matchSignals(toks);
      const classes = new Set(matches.map((m) => m.cls));
      expect(classes.size).toBeGreaterThanOrEqual(2);
    });
  });
});
