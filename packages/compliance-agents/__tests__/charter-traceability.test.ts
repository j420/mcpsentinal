/**
 * Charter Traceability Guard
 *
 * Every ComplianceRule under src/rules/<...>/ MUST have a sibling
 * CHARTER.md authored by the Senior MCP Threat Researcher persona. The
 * charter declares the rule id, threat references, and edge-case strategies
 * the engineer must implement. This test parses every CHARTER.md and asserts
 * that the corresponding TypeScript file agrees on:
 *
 *   1. The rule id
 *   2. At least one shared threat reference id
 *   3. At least one shared edge-case strategy
 *
 * Drift between charter and implementation fails CI — that's the whole point
 * of the dual-persona protocol.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";

const PACKAGE_ROOT = new URL("..", import.meta.url).pathname;
const RULES_ROOT = join(PACKAGE_ROOT, "src", "rules");

interface CharterFacts {
  charterPath: string;
  ruleId: string | null;
  threatRefIds: Set<string>;
  strategies: Set<string>;
}

function listCharters(dir: string): string[] {
  const out: string[] = [];
  const entries = readdirSync(dir);
  for (const name of entries) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...listCharters(full));
    } else if (name === "CHARTER.md") {
      out.push(full);
    }
  }
  return out;
}

function parseCharter(path: string): CharterFacts {
  const text = readFileSync(path, "utf8");
  const facts: CharterFacts = {
    charterPath: path,
    ruleId: null,
    threatRefIds: new Set(),
    strategies: new Set(),
  };

  // Charter format (loose): YAML-ish front matter section + markdown.
  // We extract by line scanning so we don't depend on a YAML parser.
  let inThreatRefs = false;
  let inStrategies = false;
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("rule_id:")) {
      facts.ruleId = line.slice("rule_id:".length).trim().replace(/[`'"]/g, "");
    } else if (/^threat_refs\s*:/i.test(line)) {
      inThreatRefs = true;
      inStrategies = false;
      continue;
    } else if (/^strategies\s*:/i.test(line)) {
      inThreatRefs = false;
      inStrategies = true;
      continue;
    } else if (line.length > 0 && !line.startsWith("-") && !line.startsWith("#") && line.includes(":")) {
      inThreatRefs = false;
      inStrategies = false;
    }

    if (inThreatRefs && line.startsWith("-")) {
      const v = line.slice(1).trim().replace(/[`'"]/g, "");
      if (v) facts.threatRefIds.add(v);
    }
    if (inStrategies && line.startsWith("-")) {
      const v = line.slice(1).trim().replace(/[`'"]/g, "");
      if (v) facts.strategies.add(v);
    }
  }
  return facts;
}

interface ImplFacts {
  implPath: string;
  ruleId: string | null;
  threatRefIds: Set<string>;
  strategies: Set<string>;
}

function parseImpl(path: string): ImplFacts {
  const text = readFileSync(path, "utf8");
  const facts: ImplFacts = {
    implPath: path,
    ruleId: null,
    threatRefIds: new Set(),
    strategies: new Set(),
  };

  // Extract id field — string-literal scan, intentionally simple.
  const idLine = text.split("\n").find((l) => /^\s*id:\s*["']/.test(l));
  if (idLine) {
    const m = idLine.match(/["']([^"']+)["']/);
    if (m) facts.ruleId = m[1];
  }

  // Walk the file collecting any "id:" inside threat_refs and any string in strategies arrays.
  // This is intentionally tolerant — the no-static-patterns guard already prevents
  // regex/string-list cheating; we just want a presence check here.
  const threatIdMatches = text.matchAll(/id:\s*["']([A-Z][A-Z0-9\-_.]+)["']/g);
  for (const m of threatIdMatches) {
    facts.threatRefIds.add(m[1]);
  }

  const stratMatches = text.matchAll(/["'](unicode-evasion|encoding-bypass|privilege-chain|auth-bypass-window|consent-bypass|audit-erasure|boundary-leak|cross-tool-flow|trust-inversion|shadow-state|race-condition|config-drift|supply-chain-pivot|credential-laundering|human-oversight-bypass)["']/g);
  for (const m of stratMatches) {
    facts.strategies.add(m[1]);
  }

  return facts;
}

describe("charter-traceability guard", () => {
  const charters = listCharters(RULES_ROOT);

  it("finds at least one CHARTER.md", () => {
    expect(charters.length).toBeGreaterThan(0);
  });

  for (const charterPath of charters) {
    const ruleDir = dirname(charterPath);
    const implPath = join(ruleDir, "index.ts");
    const rel = relative(PACKAGE_ROOT, charterPath);

    it(`${rel} agrees with sibling index.ts`, () => {
      const impl = parseImpl(implPath);
      const charter = parseCharter(charterPath);

      // 1. Rule id must agree (charter must declare it).
      expect(charter.ruleId, `${rel} missing rule_id`).toBeTruthy();
      expect(
        impl.ruleId,
        `${relative(PACKAGE_ROOT, implPath)} has no string id field`,
      ).toBeTruthy();
      expect(impl.ruleId).toBe(charter.ruleId);

      // 2. At least one threat reference must overlap.
      const sharedRefs = [...charter.threatRefIds].filter((r) =>
        impl.threatRefIds.has(r),
      );
      expect(
        sharedRefs.length,
        `${rel} threat_refs do not overlap with implementation. ` +
          `charter=${[...charter.threatRefIds].join(",")} ` +
          `impl=${[...impl.threatRefIds].join(",")}`,
      ).toBeGreaterThan(0);

      // 3. At least one strategy must overlap.
      const sharedStrats = [...charter.strategies].filter((s) =>
        impl.strategies.has(s),
      );
      expect(
        sharedStrats.length,
        `${rel} strategies do not overlap with implementation. ` +
          `charter=${[...charter.strategies].join(",")} ` +
          `impl=${[...impl.strategies].join(",")}`,
      ).toBeGreaterThan(0);
    });
  }
});
