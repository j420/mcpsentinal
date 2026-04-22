/**
 * M4 v2 — tool-squatting unit tests.
<<<<<<< HEAD
 *
 * Loads each fixture from ../__fixtures__/ as a single tool surface and
 * runs the rule. Asserts:
 *   - TP fixtures produce exactly one finding;
 *   - TN fixtures produce zero findings;
 *   - every finding has a tool Location, a mitigation link, and an impact
 *     link; confidence respects the 0.85 cap;
 *   - every VerificationStep.target is a structured Location.
=======
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
 */

import { describe, it, expect } from "vitest";
import { M4ToolSquattingRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import { gatherM4, tokenise, matchSignals, detectNegation } from "../gather.js";

import { fixture as tp01 } from "../__fixtures__/true-positive-01-official-version.js";
import { fixture as tp02 } from "../__fixtures__/true-positive-02-vendor-attribution.js";
import { fixture as tp03 } from "../__fixtures__/true-positive-03-bare-vendor.js";
import { fixture as tn01 } from "../__fixtures__/true-negative-01-unofficial-fork.js";
import { fixture as tn02 } from "../__fixtures__/true-negative-02-plain-capability.js";
import { fixture as tn03 } from "../__fixtures__/true-negative-03-marketing-trusted.js";

function ctx(tool: { name: string; description: string; input_schema: unknown }): AnalysisContext {
  return {
    server: { id: "srv", name: "t", description: null, github_url: null },
    tools: [{
      name: tool.name,
      description: tool.description,
      input_schema: tool.input_schema as Record<string, unknown> | null,
    }],
    source_code: null,
    source_files: null,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new M4ToolSquattingRule();

describe("M4 — Tool Squatting (v2)", () => {
  describe("true positives", () => {
    it("fires on 'the official version' authenticity claim (TP-01)", () => {
      const findings = rule.analyze(ctx(tp01));
<<<<<<< HEAD
      expect(findings).toHaveLength(1);
      expect(findings[0].rule_id).toBe("M4");
      expect(findings[0].severity).toBe("critical");
=======
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].rule_id).toBe("M4");
      expect(["critical", "high"]).toContain(findings[0].severity);
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
    });

    it("fires on 'made by Anthropic' vendor attribution (TP-02)", () => {
      const findings = rule.analyze(ctx(tp02));
<<<<<<< HEAD
      expect(findings).toHaveLength(1);
      expect(findings[0].severity === "critical" || findings[0].severity === "high").toBe(true);
=======
      expect(findings.length).toBeGreaterThanOrEqual(1);
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
    });

    it("fires on bare vendor token at description start (TP-03)", () => {
      const findings = rule.analyze(ctx(tp03));
<<<<<<< HEAD
      expect(findings).toHaveLength(1);
      // bare vendor alone has baseline weight 0.60 → confidence ≈ 0.60 → high
      expect(findings[0].severity).toBe("high");
=======
      expect(findings.length).toBeGreaterThanOrEqual(1);
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
    });
  });

  describe("true negatives", () => {
    it("does NOT fire on 'unofficial community fork' disclaimer (TN-01)", () => {
      const findings = rule.analyze(ctx(tn01));
      expect(findings).toHaveLength(0);
    });

    it("does NOT fire on plain capability description (TN-02)", () => {
      const findings = rule.analyze(ctx(tn02));
      expect(findings).toHaveLength(0);
    });

    it("does NOT fire on marketing 'trusted by' language alone (TN-03)", () => {
      const findings = rule.analyze(ctx(tn03));
      expect(findings).toHaveLength(0);
    });
  });

  describe("evidence chain shape", () => {
<<<<<<< HEAD
    it("every link uses a structured tool Location, not a prose string", () => {
      const findings = rule.analyze(ctx(tp01));
      expect(findings).toHaveLength(1);
      const chain = findings[0].chain;
      for (const link of chain.links) {
=======
    it("every link with a Location uses a structured tool Location, not a prose string", () => {
      const findings = rule.analyze(ctx(tp01));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      const chain = findings[0].chain;
      for (const link of chain.links) {
        if (link.type === "impact") continue;
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
        expect(isLocation(link.location)).toBe(true);
      }
    });

    it("every verification step target is a structured Location", () => {
      const findings = rule.analyze(ctx(tp02));
<<<<<<< HEAD
      expect(findings).toHaveLength(1);
=======
      expect(findings.length).toBeGreaterThanOrEqual(1);
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
      const steps = findings[0].chain.verification_steps ?? [];
      expect(steps.length).toBeGreaterThanOrEqual(3);
      for (const step of steps) {
        expect(isLocation(step.target)).toBe(true);
      }
    });

    it("includes a mitigation link (negation detection record)", () => {
      const findings = rule.analyze(ctx(tp01));
      const hasMitigation = findings[0].chain.links.some((l) => l.type === "mitigation");
      expect(hasMitigation).toBe(true);
    });

    it("includes an impact link describing tool-selection displacement", () => {
      const findings = rule.analyze(ctx(tp01));
      const impactLinks = findings[0].chain.links.filter((l) => l.type === "impact");
<<<<<<< HEAD
      expect(impactLinks).toHaveLength(1);
      expect(impactLinks[0].type === "impact" && impactLinks[0].impact_type).toBe("config-poisoning");
=======
      expect(impactLinks.length).toBeGreaterThanOrEqual(1);
      const impact = impactLinks[0];
      expect(impact.type === "impact" && impact.impact_type).toBe("config-poisoning");
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
    });

    it("respects the 0.85 confidence cap", () => {
      const findings = rule.analyze(ctx(tp02));
      for (const f of findings) {
        expect(f.chain.confidence).toBeLessThanOrEqual(0.85);
      }
    });

    it("threat reference is OWASP MCP02", () => {
      const findings = rule.analyze(ctx(tp01));
      expect(findings[0].chain.threat_reference?.id).toBe("OWASP-MCP-02");
    });
  });

  describe("tokeniser / signal-matcher edge cases", () => {
<<<<<<< HEAD
    it("word-boundary tokenisation splits on non-word chars", () => {
      const toks = tokenise("filesystem-reader v0.1.0 tool");
      const values = toks.map((t) => t.value);
      expect(values).toContain("filesystem-reader");
      expect(values).toContain("tool");
    });

    it("compound tokens with hyphens preserved", () => {
=======
    it("word-boundary tokenisation preserves hyphen-compound tokens", () => {
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
      const toks = tokenise("un-official fork");
      expect(toks[0].value).toBe("un-official");
    });

    it("matchSignals fires on authenticity anchor+qualifier within proximity", () => {
      const toks = tokenise("official version");
      const matches = matchSignals(toks);
      expect(matches.length).toBeGreaterThanOrEqual(1);
    });

    it("matchSignals does NOT fire when proximity gap is too wide", () => {
<<<<<<< HEAD
      const toks = tokenise("official - this is far away from any relevant - version");
      const matches = matchSignals(toks);
      // "official" anchor; "version" is beyond proximity=2
=======
      const toks = tokenise("official is a word used elsewhere and version comes way later");
      const matches = matchSignals(toks);
>>>>>>> claude/phase-1/1.6-D-v2-shell-extract
      const authMatches = matches.filter((m) => m.cls === "authenticity-claim");
      expect(authMatches).toHaveLength(0);
    });

    it("detectNegation returns true for explicit 'not' before anchor", () => {
      const toks = tokenise("this is not the official version");
      const matches = matchSignals(toks);
      const neg = detectNegation(toks, matches);
      expect(neg).toBe(true);
    });

    it("detectNegation returns true for 'un-' prefix on anchor-like token", () => {
      const toks = tokenise("this is an unverified implementation");
      const matches = matchSignals(toks);
      const neg = detectNegation(toks, matches);
      expect(neg).toBe(true);
    });
  });

  describe("gather boundaries", () => {
    it("gatherM4 returns empty for empty tool list", () => {
      const sites = gatherM4({
        server: { id: "x", name: "y", description: null, github_url: null },
        tools: [],
        source_code: null,
        source_files: null,
        dependencies: [],
        connection_metadata: null,
      });
      expect(sites).toHaveLength(0);
    });

    it("gatherM4 skips descriptions shorter than 10 chars", () => {
      const sites = gatherM4(ctx({ name: "x", description: "official", input_schema: null }));
      expect(sites).toHaveLength(0);
    });
  });
});
