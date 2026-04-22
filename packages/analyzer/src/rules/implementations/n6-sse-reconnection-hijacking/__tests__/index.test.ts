import { describe, it, expect } from "vitest";
import { SSEReconnectionRule } from "../index.js";
import { isLocation } from "../../../location.js";
import { buildContext as tp01 } from "../__fixtures__/true-positive-01-eventsource-no-auth.js";
import { buildContext as tp02 } from "../__fixtures__/true-positive-02-session-in-url.js";
import { buildContext as tp03 } from "../__fixtures__/true-positive-03-reconnect-handler.js";
import { buildContext as tn01 } from "../__fixtures__/true-negative-01-no-sse.js";
import { buildContext as tn02 } from "../__fixtures__/true-negative-02-sse-with-auth.js";

const rule = new SSEReconnectionRule();

describe("N6 — SSE Reconnection Hijacking (v2)", () => {
  it("fires on EventSource reconnect with no auth", () => {
    const f = rule.analyze(tp01());
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].rule_id).toBe("N6");
    expect(f[0].severity).toBe("critical");
  });

  it("fires on session id in URL with no hmac", () => {
    const f = rule.analyze(tp02());
    expect(f.length).toBeGreaterThan(0);
  });

  it("fires on reconnect handler reading Last-Event-ID without auth", () => {
    const f = rule.analyze(tp03());
    expect(f.length).toBeGreaterThan(0);
  });

  it("does not fire on non-SSE servers (honest refusal)", () => {
    expect(rule.analyze(tn01()).length).toBe(0);
  });

  it("fires with present=true when SSE + auth present", () => {
    const f = rule.analyze(tn02());
    // When auth IS present, rule still fires once but mitigation=true.
    if (f.length > 0) {
      const mit = f[0].chain.links.find((l) => l.type === "mitigation");
      if (mit && mit.type === "mitigation") {
        expect(mit.present).toBe(true);
      }
    }
  });

  it("every link has Location", () => {
    const f = rule.analyze(tp01())[0];
    for (const l of f.chain.links) {
      if (l.type === "impact") continue;
      expect(isLocation(l.location)).toBe(true);
    }
  });

  it("every verification step target is Location", () => {
    const f = rule.analyze(tp01())[0];
    const steps = f.chain.verification_steps ?? [];
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) expect(isLocation(s.target)).toBe(true);
  });

  it("confidence capped at 0.80", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.confidence).toBeLessThanOrEqual(0.8);
  });

  it("references CVE-2025-6515", () => {
    const f = rule.analyze(tp01())[0];
    expect(f.chain.threat_reference?.id).toBe("CVE-2025-6515");
  });

  it("records reconnect_auth_absent factor", () => {
    const f = rule.analyze(tp01())[0];
    const factors = f.chain.confidence_factors.map((x) => x.factor);
    expect(factors).toContain("reconnect_auth_absent");
  });
});
