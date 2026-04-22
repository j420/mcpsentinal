import { describe, it, expect } from "vitest";
import { L8Rule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import { looksOld, isMcpCritical, parseInstallString } from "../gather.js";

import { source as tp01 } from "../__fixtures__/true-positive-01-overrides-mcp.js";
import { source as tp02 } from "../__fixtures__/true-positive-02-install-command.js";
import { source as tp03 } from "../__fixtures__/true-positive-03-pnpm-overrides.js";
import { source as tn01 } from "../__fixtures__/true-negative-01-latest-pin.js";
import { source as tn02 } from "../__fixtures__/true-negative-02-plain-code.js";

function ctx(src: string, file = "package.json"): AnalysisContext {
  return {
    server: { id: "s", name: "n", description: null, github_url: null },
    tools: [],
    source_code: src,
    source_files: new Map([[file, src]]),
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new L8Rule();

describe("L8 — Version Rollback Attack (v2)", () => {
  it("fires on overrides.mcp-sdk=0.1.0 (TP-01) with CRITICAL severity", () => {
    const fs = rule.analyze(ctx(tp01));
    expect(fs.length).toBeGreaterThanOrEqual(1);
    expect(fs[0].severity).toBe("critical");
  });

  it("fires on npm install @anthropic/sdk@0.2.3 (TP-02)", () => {
    const fs = rule.analyze(ctx(tp02, "setup.ts"));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("fires on pnpm.overrides nested block (TP-03)", () => {
    const fs = rule.analyze(ctx(tp03));
    expect(fs.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire on modern ^5.4.2 pin (TN-01)", () => {
    const fs = rule.analyze(ctx(tn01));
    expect(fs).toHaveLength(0);
  });

  it("does NOT fire on plain code (TN-02)", () => {
    const fs = rule.analyze(ctx(tn02, "util.ts"));
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
    const fs = rule.analyze(ctx(tp01));
    const steps = fs[0].chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThanOrEqual(3);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("respects the 0.85 confidence cap", () => {
    const fs = rule.analyze(ctx(tp01));
    for (const f of fs) expect(f.chain.confidence).toBeLessThanOrEqual(0.85);
  });

  describe("helpers", () => {
    it("looksOld recognises 0.x versions", () => {
      expect(looksOld("0.1.0")).toBe(true);
      expect(looksOld("^0.2.0")).toBe(true);
    });
    it("looksOld recognises < and <= comparators", () => {
      expect(looksOld("<1.0.0")).toBe(true);
      expect(looksOld("<=2.0.0")).toBe(true);
    });
    it("looksOld rejects modern versions", () => {
      expect(looksOld("5.4.2")).toBe(false);
      expect(looksOld("^2.1.0")).toBe(false);
    });
    it("isMcpCritical accepts scoped packages", () => {
      expect(isMcpCritical("@anthropic/sdk")).toBe(true);
      expect(isMcpCritical("mcp-sdk")).toBe(true);
      expect(isMcpCritical("lodash")).toBe(false);
    });
    it("parseInstallString returns {pkg, version} for pip==", () => {
      const r = parseInstallString("pip install foo==0.1.0");
      expect(r).toEqual({ pkg: "foo", version: "0.1.0" });
    });
    it("parseInstallString returns null for modern version", () => {
      const r = parseInstallString("npm install foo@5.4.2");
      expect(r).toBeNull();
    });
  });
});
