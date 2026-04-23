import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { FRAMEWORKS, FRAMEWORK_IDS, getAllFrameworks, getFramework } from "../index.js";

const RULES_DIR = fileURLToPath(new URL("../../../../rules/", import.meta.url));

/**
 * Load the set of rule ids declared in `rules/*.yaml`. Only active rules
 * participate in assessor membership validation — retired rules
 * (`enabled: false`) are intentionally not covered by any framework.
 */
function loadActiveRuleIds(): Set<string> {
  const files = readdirSync(RULES_DIR).filter((f) => f.endsWith(".yaml"));
  const ids = new Set<string>();
  for (const f of files) {
    if (f === "framework-registry.yaml" || f === "accuracy-targets.yaml") continue;
    const raw = readFileSync(join(RULES_DIR, f), "utf8");
    const parsed = YAML.parse(raw) as { id?: string; enabled?: boolean };
    if (!parsed || typeof parsed.id !== "string") continue;
    if (parsed.enabled === false) continue;
    ids.add(parsed.id);
  }
  return ids;
}

describe("framework registry", () => {
  it("exposes all 7 frameworks", () => {
    expect(FRAMEWORK_IDS.length).toBe(7);
    expect(getAllFrameworks().length).toBe(7);
    for (const id of FRAMEWORK_IDS) {
      expect(FRAMEWORKS[id].id).toBe(id);
    }
  });

  it("getFramework returns the same object as FRAMEWORKS[id]", () => {
    for (const id of FRAMEWORK_IDS) {
      expect(getFramework(id)).toBe(FRAMEWORKS[id]);
    }
  });

  it("every control has required fields populated", () => {
    for (const f of getAllFrameworks()) {
      for (const c of f.controls) {
        expect(c.control_id, `${f.id}:${c.control_id}`).toMatch(/\S/);
        expect(c.control_name, `${f.id}:${c.control_id}`).toMatch(/\S/);
        expect(c.control_description.length, `${f.id}:${c.control_id}`).toBeLessThanOrEqual(500);
        expect(c.control_description, `${f.id}:${c.control_id}`).toMatch(/\S/);
        expect(c.source_url, `${f.id}:${c.control_id}`).toMatch(/^https?:\/\//);
        expect(Array.isArray(c.assessor_rule_ids), `${f.id}:${c.control_id}`).toBe(true);
        expect(c.unmet_threshold, `${f.id}:${c.control_id}`).toMatch(
          /^(critical|high|medium|low|informational)$/,
        );
      }
    }
  });

  it("control ids are unique within each framework", () => {
    for (const f of getAllFrameworks()) {
      const seen = new Set<string>();
      for (const c of f.controls) {
        expect(seen.has(c.control_id), `duplicate control id ${f.id}:${c.control_id}`).toBe(false);
        seen.add(c.control_id);
      }
    }
  });

  it("every assessor_rule_id references an active YAML rule in rules/", () => {
    const activeIds = loadActiveRuleIds();
    // Sanity: we should have at least 150 active rules — catches rules
    // directory drift before any framework assertion starts flapping.
    expect(activeIds.size).toBeGreaterThan(150);

    const orphans: string[] = [];
    for (const f of getAllFrameworks()) {
      for (const c of f.controls) {
        for (const ruleId of c.assessor_rule_ids) {
          if (!activeIds.has(ruleId)) {
            orphans.push(`${f.id}:${c.control_id} → ${ruleId}`);
          }
        }
      }
    }
    expect(orphans, `unknown / retired rule ids cited as assessors:\n${orphans.join("\n")}`).toEqual([]);
  });

  it("documents at least one explicit gap (no assessor) so coverage transparency is real", () => {
    // We intentionally ship with at least one control that has no assessor
    // rule (e.g. OWASP ASI10 — agentic data poisoning). If every control
    // suddenly has coverage, that probably means someone fabricated a
    // mapping rather than honestly declaring the gap.
    const gaps: string[] = [];
    for (const f of getAllFrameworks()) {
      for (const c of f.controls) {
        if (c.assessor_rule_ids.length === 0) {
          gaps.push(`${f.id}:${c.control_id}`);
        }
      }
    }
    expect(gaps.length, "at least one control should honestly declare zero assessors").toBeGreaterThan(0);
  });

  it("last_updated is a parseable ISO date", () => {
    for (const f of getAllFrameworks()) {
      expect(Number.isNaN(new Date(f.last_updated).getTime())).toBe(false);
    }
  });
});
