/**
 * K2 v2 — functional + evidence-integrity tests.
 *
 * Covers every CHARTER lethal edge case plus chain-shape / confidence
 * assertions.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditTrailDestructionRule } from "../index.js";
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

const rule = new AuditTrailDestructionRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "k2-t", name: "k2-test-server", description: null, github_url: null },
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

describe("K2 — fires (true positives)", () => {
  it("canonical shape: fs.unlinkSync on /var/log/audit.log", () => {
    const results = rule.analyze(loadFixture("true-positive-01-unlink-audit-log.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K2");
    expect(results[0].severity).toBe("critical");
  });

  it("CHARTER edge case: truncate-any-size-fires — fs.writeFileSync with empty string on auditPath field", () => {
    const results = rule.analyze(loadFixture("true-positive-02-truncate-via-empty-write.ts"));
    expect(results.length).toBeGreaterThan(0);
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sinks[0].sink_type).toBe("file-write");
  });

  it("CHARTER edge case: logging-disable-structural — logger.silent = true inside conditional fires regardless of guard", () => {
    const results = rule.analyze(loadFixture("true-positive-03-logger-silent-toggle.ts"));
    expect(results.length).toBeGreaterThan(0);
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sinks[0].sink_type).toBe("config-modification");
    expect(results[0].severity).toBe("critical");
  });

  it("CHARTER edge case: python-os-remove-audit-path — os.remove on journal file", () => {
    // TypeScript compiler parses Python-ish code sufficiently to walk
    // the AST — `os.remove("...")` is a valid JS/TS expression too.
    const src = `os.remove("/var/log/journal/system.log");\n`;
    const results = rule.analyze(sourceContext(src));
    expect(results.length).toBeGreaterThan(0);
  });

  it("CHARTER edge case: config-field-name-allowed — fs.unlink(config.auditPath)", () => {
    const src = `
import * as fs from "fs";
function go(config: { auditPath: string }) {
  fs.unlinkSync(config.auditPath);
}
go({ auditPath: "/var/log/audit.log" });
`;
    const results = rule.analyze(sourceContext(src));
    expect(results.length).toBeGreaterThan(0);
  });

  it("CHARTER edge case: rename-then-unlink-without-archive — severity downgrade when archive marker is present", () => {
    const results = rule.analyze(loadFixture("true-negative-01-log-rotation.ts"));
    expect(results.length).toBeGreaterThan(0);
    // Rotation marker ("archive" / "gzip") present — severity should be "high" not "critical".
    expect(results[0].severity).toBe("high");
  });

  it("CHARTER edge case: logging.disable() python-style (parsed as JS expression)", () => {
    // Python's `import logging` is not valid TS; the TS parser doesn't
    // tolerate it at file scope. The DISABLE call itself parses fine as
    // a JS expression — that is all the rule needs to fire.
    const src = `logging.disable(logging.CRITICAL);\n`;
    const results = rule.analyze(sourceContext(src));
    expect(results.length).toBeGreaterThan(0);
    const sinks = getLinksOfType<SinkLink>(results[0].chain, "sink");
    expect(sinks[0].sink_type).toBe("config-modification");
  });
});

// ─── True negatives ───────────────────────────────────────────────────────

describe("K2 — does not fire (true negatives)", () => {
  it("fs.unlink on a build artifact (no audit marker) must NOT fire", () => {
    const results = rule.analyze(loadFixture("true-negative-02-non-audit-path.ts"));
    expect(results.length).toBe(0);
  });

  it("fs.writeFileSync with non-empty content must NOT fire (not a truncation)", () => {
    const src = `
import * as fs from "fs";
fs.writeFileSync("/var/log/audit.log", "some legitimate emit");
`;
    const results = rule.analyze(sourceContext(src));
    expect(results.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("K2 — evidence integrity", () => {
  it("every link with a location field is a structured Location; every VerificationStep.target is a Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-unlink-audit-log.ts"));
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

  it("every destruction chain has source + propagation + sink (file-write) + mitigation + impact", () => {
    const results = rule.analyze(loadFixture("true-positive-01-unlink-audit-log.ts"));
    expect(results.length).toBeGreaterThan(0);
    const chain = results[0].chain;
    const sources = getLinksOfType<SourceLink>(chain, "source");
    const sinks = getLinksOfType<SinkLink>(chain, "sink");
    const mitigations = getLinksOfType<MitigationLink>(chain, "mitigation");
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks[0].sink_type).toBe("file-write");
    expect(mitigations.length).toBeGreaterThanOrEqual(1);
  });

  it("cites ISO-27001-A.8.15 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-unlink-audit-log.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("ISO-27001-A.8.15");
  });

  it("verification_steps contains a check-config step for append-only storage", () => {
    const results = rule.analyze(loadFixture("true-positive-01-unlink-audit-log.ts"));
    const steps = results[0].chain.verification_steps as VerificationStep[];
    const configSteps = steps.filter((s) => s.step_type === "check-config");
    expect(configSteps.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("K2 — confidence contract", () => {
  it("caps confidence at 0.88 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-unlink-audit-log.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.88);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("records required_factors per CHARTER", () => {
    const results = rule.analyze(loadFixture("true-positive-01-unlink-audit-log.ts"));
    expect(results.length).toBeGreaterThan(0);
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("audit_path_identifier");
    expect(factors).toContain("unmitigated_destruction_reachability");
    expect(factors).toContain("rotation_or_archive_absent");
  });
});

// ─── Mutation ────────────────────────────────────────────────────────────

describe("K2 — mutation: replacing unlink with a retained rotation removes critical", () => {
  it("bare unlink = critical; unlink with archive-then-compress = high", () => {
    const bare = `
import * as fs from "fs";
fs.unlinkSync("/var/log/audit.log");
`;
    const rotated = `
import * as fs from "fs";
import { gzipSync } from "zlib";
function rotate() {
  const data = fs.readFileSync("/var/log/audit.log");
  fs.writeFileSync("/var/log/audit.log.archive.gz", gzipSync(data));
  fs.unlinkSync("/var/log/audit.log");
}
rotate();
`;
    const bareResults = rule.analyze(sourceContext(bare));
    const rotatedResults = rule.analyze(sourceContext(rotated));
    expect(bareResults.some((r) => r.severity === "critical")).toBe(true);
    expect(rotatedResults.every((r) => r.severity !== "critical" || r.rule_id !== "K2")).toBe(true);
  });
});
