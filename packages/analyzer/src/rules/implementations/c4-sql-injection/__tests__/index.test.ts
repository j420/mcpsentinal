/**
 * C4 v2 — functional + evidence-integrity tests.
 *
 * Every finding is checked against the v2 contract:
 *   - Location-kinded source / sink / every propagation step
 *   - Every VerificationStep.target is a Location (isLocation passes)
 *   - Chain has ≥1 source link and ≥1 sink link
 *   - Confidence ∈ [0.05, 0.92] — the charter cap
 *   - Mitigation link always present
 *   - Threat reference present and names CWE-89
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SqlInjectionRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import type {
  EvidenceChain,
  SourceLink,
  SinkLink,
  PropagationLink,
  MitigationLink,
  VerificationStep,
} from "../../../../evidence.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "__fixtures__");

const rule = new SqlInjectionRule();

function sourceContext(text: string): AnalysisContext {
  return {
    server: { id: "c4-t", name: "c4-test-server", description: null, github_url: null },
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

// ─── True positives ────────────────────────────────────────────────────────

describe("C4 — fires (true positives)", () => {
  it("flags a template-literal SQL query with a req.body source", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C4");
    expect(results[0].severity).toBe("critical");
  });

  it("flags a multi-hop string-concatenation flow", () => {
    const results = rule.analyze(loadFixture("true-positive-02-string-concat.ts"));
    expect(results.length).toBeGreaterThan(0);
    // The AST analyser may report multiple flows for the same source — at
    // least one of them should include a propagation link (multi-hop).
    const someHaveProp = results.some(
      (r) => getLinksOfType<PropagationLink>(r.chain, "propagation").length >= 1,
    );
    expect(someHaveProp).toBe(true);
  });

  it("flags a Python f-string SQL via the lightweight fallback", () => {
    const results = rule.analyze(loadFixture("true-positive-03-python-fstring.py"));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("C4");
    // Python flows come from the lightweight analyser — severity stays critical.
    expect(["critical", "informational"]).toContain(results[0].severity);
  });
});

// ─── True negatives ────────────────────────────────────────────────────────

describe("C4 — does not fire (true negatives)", () => {
  it("does NOT flag a parameterised .query with a $1 placeholder", () => {
    const results = rule.analyze(loadFixture("true-negative-01-parameterised.ts"));
    // Either no findings at all, or findings that are NOT critical.
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });

  it("drops severity to informational when numeric coercion is on the path", () => {
    const results = rule.analyze(loadFixture("true-negative-02-numeric-coercion.ts"));
    // A Number() coercion is on C4's charter list of known sanitisers —
    // any finding must not be critical.
    const critical = results.filter((r) => r.severity === "critical");
    expect(critical.length).toBe(0);
  });
});

// ─── Evidence integrity ───────────────────────────────────────────────────

describe("C4 — evidence integrity", () => {
  it("every link that carries a location and every VerificationStep.target is a structured Location", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      for (const link of r.chain.links) {
        // Impact links don't carry a location field — only source / propagation /
        // sink / mitigation do. Everything that DOES carry a location must be a
        // structured Location, never a prose string.
        if (link.type === "impact") continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const loc = (link as any).location;
        expect(isLocation(loc)).toBe(true);
      }
      for (const step of r.chain.verification_steps ?? []) {
        expect(isLocation(step.target)).toBe(true);
      }
    }
  });

  it("every chain carries both a source link and a sink link", () => {
    const results = rule.analyze(loadFixture("true-positive-02-string-concat.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const sources = getLinksOfType<SourceLink>(r.chain, "source");
      const sinks = getLinksOfType<SinkLink>(r.chain, "sink");
      expect(sources.length).toBeGreaterThanOrEqual(1);
      expect(sinks.length).toBeGreaterThanOrEqual(1);
      expect(sources[0].source_type).toBe("user-parameter");
      expect(sinks[0].sink_type).toBe("sql-execution");
    }
  });

  it("every chain records a mitigation link (present or absent)", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const mitigations = getLinksOfType<MitigationLink>(r.chain, "mitigation");
      expect(mitigations.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("cites CWE-89 on the threat reference", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    expect(results[0].chain.threat_reference?.id).toBe("CWE-89");
  });
});

// ─── Confidence contract ─────────────────────────────────────────────────

describe("C4 — confidence contract", () => {
  it("caps confidence at 0.92 per charter", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.92);
      expect(r.chain.confidence).toBeGreaterThanOrEqual(0.05);
    }
  });

  it("confidence factors correctly record the hop count per fixture", () => {
    const direct = rule.analyze(loadFixture("true-positive-01-template-literal.ts"));
    const multihop = rule.analyze(loadFixture("true-positive-02-string-concat.ts"));
    expect(direct.length).toBeGreaterThan(0);
    expect(multihop.length).toBeGreaterThan(0);
    // Both fixtures must carry the `ast_confirmed` factor with a positive
    // adjustment — the strongest confidence signal C4 can emit.
    const directFactors = direct[0].chain.confidence_factors.map((f) => f.factor);
    const multiFactors = multihop[0].chain.confidence_factors.map((f) => f.factor);
    expect(directFactors).toContain("ast_confirmed");
    expect(multiFactors).toContain("ast_confirmed");
    expect(directFactors).toContain("interprocedural_hops");
    expect(multiFactors).toContain("interprocedural_hops");
  });
});

// ─── Mutation: adding a sanitiser drops severity ─────────────────────────

describe("C4 — mutation (adding a sanitiser removes the critical finding)", () => {
  it("adding a parameterised call suppresses the critical finding", () => {
    const vulnerable = `
import { createPool } from "mysql2";
const pool = createPool({ host: "db" });
export async function go(req) {
  const name = req.body.name;
  return pool.query(\`SELECT * FROM users WHERE name = '\${name}'\`);
}
`;
    const sanitised = `
import { createPool } from "mysql2";
const pool = createPool({ host: "db" });
export async function go(req) {
  const name = req.body.name;
  return pool.query("SELECT * FROM users WHERE name = $1", [name]);
}
`;
    const vulnerableCritical = rule
      .analyze(sourceContext(vulnerable))
      .filter((r) => r.severity === "critical");
    const sanitisedCritical = rule
      .analyze(sourceContext(sanitised))
      .filter((r) => r.severity === "critical");
    expect(vulnerableCritical.length).toBeGreaterThan(0);
    expect(sanitisedCritical.length).toBe(0);
  });
});

// ─── Verification-steps contract ─────────────────────────────────────────

describe("C4 — verification steps", () => {
  it("emits at least three steps on every unsanitised finding", () => {
    const results = rule.analyze(loadFixture("true-positive-01-template-literal.ts")).filter(
      (r) => r.severity === "critical",
    );
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const steps = r.chain.verification_steps as VerificationStep[];
      expect(steps.length).toBeGreaterThanOrEqual(3);
      for (const s of steps) {
        expect(isLocation(s.target)).toBe(true);
        expect(s.instruction.length).toBeGreaterThan(20);
      }
    }
  });
});
