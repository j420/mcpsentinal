import { describe, it, expect } from "vitest";
import { Q10Rule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import { gatherQ10, tokenise, matchSignals, detectMitigation } from "../gather.js";

import { fixture as tp01 } from "../__fixtures__/true-positive-01-store-instructions.js";
import { fixture as tp02 } from "../__fixtures__/true-positive-02-system-context-write.js";
import { fixture as tp03 } from "../__fixtures__/true-positive-03-priority-override.js";
import { fixture as tn01 } from "../__fixtures__/true-negative-01-readonly-facts.js";
import { fixture as tn02 } from "../__fixtures__/true-negative-02-plain-fact.js";
import { fixture as tn03 } from "../__fixtures__/true-negative-03-single-weak-signal.js";

function ctx(tool: { name: string; description: string; input_schema: unknown }): AnalysisContext {
  return {
    server: { id: "s", name: "n", description: null, github_url: null },
    tools: [{ name: tool.name, description: tool.description, input_schema: tool.input_schema as Record<string, unknown> | null }],
    source_code: null,
    source_files: null,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new Q10Rule();

describe("Q10 — Agent Memory Poisoning (v2)", () => {
  it("fires on 'stores behavioral instructions' (TP-01)", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs.length).toBeGreaterThanOrEqual(1);
    expect(fs[0].rule_id).toBe("Q10");
  });

  it("fires on system-personality-write (TP-02)", () => {
    const fs = rule.analyze(ctx(tp02));
    expect(fs.length).toBeGreaterThanOrEqual(1);
    expect(["critical", "high"]).toContain(fs[0].severity);
  });

  it("fires on override + must-follow directive (TP-03)", () => {
    const fs = rule.analyze(ctx(tp03));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire on read-only facts-only memory (TN-01)", () => {
    const fs = rule.analyze(ctx(tn01));
    expect(fs).toHaveLength(0);
  });

  it("does NOT fire on plain name-remembering (TN-02)", () => {
    const fs = rule.analyze(ctx(tn02));
    expect(fs).toHaveLength(0);
  });

  it("does NOT fire on single-class weak signal (TN-03)", () => {
    const fs = rule.analyze(ctx(tn03));
    expect(fs).toHaveLength(0);
  });

  it("every non-impact link has a structured Location", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const link of fs[0].chain.links) {
      if (link.type === "impact") continue;
      expect(isLocation(link.location)).toBe(true);
    }
  });

  it("verification steps carry structured Locations", () => {
    const fs = rule.analyze(ctx(tp02));
    const steps = fs[0].chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThanOrEqual(3);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("respects the 0.80 confidence cap", () => {
    const fs = rule.analyze(ctx(tp02));
    for (const f of fs) expect(f.chain.confidence).toBeLessThanOrEqual(0.80);
  });

  it("threat reference is AML.T0058", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs[0].chain.threat_reference?.id).toBe("MITRE-AML-T0058");
  });

  describe("helpers", () => {
    it("matchSignals fires on 'memory ... instruction' forward order", () => {
      const toks = tokenise("stores instructions in memory permanently");
      const m = matchSignals(toks);
      expect(m.length).toBeGreaterThanOrEqual(1);
    });

    it("detectMitigation detects 'read-only'", () => {
      const toks = tokenise("read-only memory for facts only");
      expect(detectMitigation(toks)).toBe(true);
    });

    it("detectMitigation detects 'no instructions'", () => {
      const toks = tokenise("accepts user feedback; no instructions are stored");
      expect(detectMitigation(toks)).toBe(true);
    });

    it("gatherQ10 skips tools with description < 15 chars", () => {
      const sites = gatherQ10(ctx({ name: "x", description: "tiny desc", input_schema: null }));
      expect(sites).toHaveLength(0);
    });
  });
});
