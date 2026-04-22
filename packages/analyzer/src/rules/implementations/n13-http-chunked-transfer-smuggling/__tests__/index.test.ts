import { describe, it, expect } from "vitest";
import { ChunkedTransferSmugglingRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-dual-headers.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-raw-chunked.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-chunk-extension.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-no-transport.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-express-no-manip.js";

const rule = new ChunkedTransferSmugglingRule();

describe("N13 — HTTP Chunked Transfer Smuggling (v2)", () => {
  it("fires on dual Transfer-Encoding + Content-Length headers", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N13");
    expect(f[0].severity).toBe("critical");
  });

  it("fires on raw chunked terminator construction", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires on chunk-extension abuse", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("honest refusal: no finding when no HTTP/SSE transport present", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("does not fire when using express without framing manipulation", () => {
    expect(rule.analyze(tn02()).length).toBe(0);
  });

  it("every link has Location", () => {
    const f = rule.analyze(tp01())[0];
    for (const l of f.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });

  it("verification targets are Locations", () => {
    const f = rule.analyze(tp01())[0];
    const steps = f.chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("confidence capped at 0.82", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.82);
  });

  it("references CVE-2025-6515", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.threat_reference?.id).toBe("CVE-2025-6515");
  });

  it("records chunked_framing_manipulated factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("chunked_framing_manipulated");
  });
});
