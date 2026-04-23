/**
 * Cross-phase wiring integration test.
 *
 * Loads the REAL attack-graph kill-chain templates (Phase 2) and the REAL
 * Phase 4 CVE corpus, and asserts that the Phase 5 KC → CVE mapping is
 * consistent with both.
 *
 * These assertions are what make the compliance report auditable: a
 * regulator can re-run this test locally to verify every cited CVE is
 * actually present in the corpus and that every attack-graph template
 * has a mapped narrative pattern.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { ALL_KILL_CHAINS } from "@mcp-sentinel/attack-graph";
import { getRegisteredCases, loadCases } from "@mcp-sentinel/red-team";
import type { CVEReplayCase } from "@mcp-sentinel/red-team";
import { KILL_CHAIN_TO_CVE_PATTERNS } from "../data/kc-cve-mapping.js";
import { ALL_KC_IDS } from "../types.js";

describe("Phase 5 kill-chain → Phase 4 corpus integration", () => {
  let corpusIds: Set<string>;
  let cases: CVEReplayCase[];

  beforeAll(async () => {
    // Trigger side-effect registration of every production-registered case.
    const result = await loadCases();
    cases = result.cases.length > 0 ? result.cases : getRegisteredCases();
    corpusIds = new Set(cases.map((c) => c.id));
  });

  it("corpus loads with ≥1 case (otherwise cross-phase wiring is broken)", () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it("ALL_KC_IDS matches the attack-graph template id set exactly", () => {
    const templateIds = ALL_KILL_CHAINS.map((t) => t.id).sort();
    const mappingIds = [...ALL_KC_IDS].sort();
    expect(mappingIds).toEqual(templateIds);
  });

  it("KILL_CHAIN_TO_CVE_PATTERNS covers every attack-graph template id (no missing, no extra)", () => {
    const mapKeys = Object.keys(KILL_CHAIN_TO_CVE_PATTERNS).sort();
    const templateIds = ALL_KILL_CHAINS.map((t) => t.id).sort();
    expect(mapKeys).toEqual(templateIds);
  });

  it("every cited cve_evidence_id is present in the Phase 4 corpus", () => {
    const missing: Array<{ kc: string; id: string }> = [];
    for (const pattern of Object.values(KILL_CHAIN_TO_CVE_PATTERNS)) {
      for (const id of pattern.cve_evidence_ids) {
        if (!corpusIds.has(id)) {
          missing.push({ kc: pattern.kc_id, id });
        }
      }
    }
    expect(missing, `Missing corpus entries: ${JSON.stringify(missing)}`).toEqual([]);
  });

  it("pattern names match the attack-graph template names", () => {
    const templateById = new Map(ALL_KILL_CHAINS.map((t) => [t.id, t]));
    for (const pattern of Object.values(KILL_CHAIN_TO_CVE_PATTERNS)) {
      const template = templateById.get(pattern.kc_id);
      expect(template, `No template for ${pattern.kc_id}`).toBeDefined();
      expect(pattern.name).toBe(template!.name);
    }
  });
});
