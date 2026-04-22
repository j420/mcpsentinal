/**
 * O10 v2 unit tests.
 *
 * Edge cases covered (mirroring CHARTER.md lethal_edge_cases):
 *   - TP-01 OS/arch/hostname/NIC enumeration → fetch POST
 *   - TP-02 installed-software (process.versions) enumeration → axios POST
 *   - TP-03 tracking-pixel URL with analytics host fragment in response
 *   - TP-04 device-identifier (/etc/machine-id, hwid, mac) transmission
 *   - TN-01 honest-refusal: os.platform() read with no network sink
 *   - TN-02 network sink but no enumeration surface (user-text translator)
 *
 * Chain-integrity assertions:
 *   - every non-impact link carries a structured Location
 *   - every VerificationStep.target is a Location
 *   - confidence capped at 0.80 (CHARTER)
 *   - chain cites MITRE-ATLAS-AML-T0057
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { O10Rule } from "../index.js";
import { gatherO10 } from "../gather.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "__fixtures__");

function loadFixture(name: string): AnalysisContext {
  const file = join(FIXTURES_DIR, name);
  const text = readFileSync(file, "utf8");
  return {
    server: { id: "o10-test", name: "o10-test", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new O10Rule();

describe("O10 — True Positives", () => {
  it("TP-01 OS/arch/hostname/NIC + fetch POST fires", () => {
    const ctx = loadFixture("true-positive-01-host-fingerprint-post.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].severity).toBe("high");
    const sites = gatherO10(ctx).sites;
    expect(sites.some((s) => s.surfaces.some((h) => h.kind === "os"))).toBe(true);
    expect(sites.some((s) => s.surfaces.some((h) => h.kind === "network"))).toBe(true);
  });

  it("TP-02 process.versions enumeration + axios POST fires", () => {
    const ctx = loadFixture("true-positive-02-software-enumeration.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO10(ctx).sites;
    expect(sites.some((s) => s.surfaces.some((h) => h.kind === "software"))).toBe(true);
  });

  it("TP-03 tracking-pixel URL with analytics host fragment fires", () => {
    const ctx = loadFixture("true-positive-03-tracking-pixel.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO10(ctx).sites;
    expect(sites.some((s) => s.pixelHint !== null)).toBe(true);
  });

  it("TP-04 device-identifier (machine-id / hwid) transmission fires", () => {
    const ctx = loadFixture("true-positive-04-device-id.ts");
    const results = rule.analyze(ctx);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const sites = gatherO10(ctx).sites;
    expect(sites.some((s) => s.surfaces.some((h) => h.kind === "device"))).toBe(true);
  });
});

describe("O10 — True Negatives", () => {
  it("TN-01 honest-refusal: os.platform() with no network primitive → 0 findings", () => {
    const ctx = loadFixture("true-negative-01-os-platform-path-sep.ts");
    const gathered = gatherO10(ctx);
    expect(gathered.hasNetworkPrimitive).toBe(false);
    expect(rule.analyze(ctx).length).toBe(0);
  });

  it("TN-02 network send without surface enumeration → 0 findings", () => {
    expect(rule.analyze(loadFixture("true-negative-02-no-enumeration.ts")).length).toBe(0);
  });

  it("returns [] when source_code is null", () => {
    expect(
      rule.analyze({
        server: { id: "e", name: "e", description: null, github_url: null },
        tools: [],
        source_code: null,
        dependencies: [],
        connection_metadata: null,
      }).length,
    ).toBe(0);
  });
});

describe("O10 — Chain integrity", () => {
  const TP_NAMES = [
    "true-positive-01-host-fingerprint-post.ts",
    "true-positive-02-software-enumeration.ts",
    "true-positive-03-tracking-pixel.ts",
    "true-positive-04-device-id.ts",
  ];

  for (const name of TP_NAMES) {
    it(`${name} → every non-impact link has a structured Location`, () => {
      const results = rule.analyze(loadFixture(name));
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        for (const link of r.chain.links) {
          if (link.type === "impact") continue;
          expect(isLocation(link.location)).toBe(true);
        }
      }
    });

    it(`${name} → every VerificationStep.target is a Location`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        const steps = r.chain.verification_steps ?? [];
        expect(steps.length).toBeGreaterThan(0);
        for (const step of steps) {
          expect(isLocation(step.target)).toBe(true);
        }
      }
    });

    it(`${name} → confidence capped at 0.80`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.confidence).toBeLessThanOrEqual(0.80);
        expect(r.chain.confidence).toBeGreaterThan(0.1);
      }
    });

    it(`${name} → cites MITRE-ATLAS-AML-T0057`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        expect(r.chain.threat_reference?.id).toBe("MITRE-ATLAS-AML-T0057");
      }
    });

    it(`${name} → chain contains source + propagation + sink + impact`, () => {
      const results = rule.analyze(loadFixture(name));
      for (const r of results) {
        const types = new Set(r.chain.links.map((l) => l.type));
        expect(types.has("source")).toBe(true);
        expect(types.has("propagation")).toBe(true);
        expect(types.has("sink")).toBe(true);
        expect(types.has("impact")).toBe(true);
      }
    });
  }
});
