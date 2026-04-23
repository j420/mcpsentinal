import { describe, it, expect } from "vitest";
import { KILL_CHAIN_TO_CVE_PATTERNS } from "../data/kc-cve-mapping.js";
import { ALL_KC_IDS } from "../types.js";

// Mirror of the registry regex patterns (packages/red-team/src/cve-corpus/registry.ts).
// Defined inline so the test asserts on the exact same shape without reaching
// into red-team's internals.
const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const RESEARCH_ID_PATTERN = /^research-[a-z0-9-]+$/;

describe("KC → CVE mapping — structural invariants", () => {
  it("has an entry for every KC in ALL_KC_IDS (no missing, no extra)", () => {
    const mappedKcs = Object.keys(KILL_CHAIN_TO_CVE_PATTERNS).sort();
    const expected = [...ALL_KC_IDS].sort();
    expect(mappedKcs).toEqual(expected);
  });

  it("every pattern's kc_id matches its map key", () => {
    for (const [key, pattern] of Object.entries(KILL_CHAIN_TO_CVE_PATTERNS)) {
      expect(pattern.kc_id).toBe(key);
    }
  });

  it("every pattern has a non-empty name and description", () => {
    for (const pattern of Object.values(KILL_CHAIN_TO_CVE_PATTERNS)) {
      expect(pattern.name.length).toBeGreaterThan(5);
      expect(pattern.description.length).toBeGreaterThan(50);
    }
  });

  it("every pattern declares ≥3 default_mitigations", () => {
    for (const pattern of Object.values(KILL_CHAIN_TO_CVE_PATTERNS)) {
      expect(pattern.default_mitigations.length).toBeGreaterThanOrEqual(3);
      // Every mitigation must be a non-trivial sentence.
      for (const m of pattern.default_mitigations) {
        expect(m.length).toBeGreaterThan(20);
      }
    }
  });

  it("every cited cve_evidence_id matches CVE-YYYY-NNNN or research-<kebab-case>", () => {
    for (const pattern of Object.values(KILL_CHAIN_TO_CVE_PATTERNS)) {
      for (const id of pattern.cve_evidence_ids) {
        const isCVE = CVE_ID_PATTERN.test(id);
        const isResearch = RESEARCH_ID_PATTERN.test(id);
        expect(
          isCVE || isResearch,
          `Pattern ${pattern.kc_id} cites malformed id "${id}"`
        ).toBe(true);
      }
    }
  });

  it("cve_evidence_ids are unique within each pattern", () => {
    for (const pattern of Object.values(KILL_CHAIN_TO_CVE_PATTERNS)) {
      const unique = new Set(pattern.cve_evidence_ids);
      expect(unique.size).toBe(pattern.cve_evidence_ids.length);
    }
  });

  it("permits empty cve_evidence_ids arrays (honest gaps)", () => {
    // At least one KC may legitimately have no Phase 4 evidence. Assert the
    // overall structure supports this — do NOT fail when the array is empty.
    const gapKcs = Object.values(KILL_CHAIN_TO_CVE_PATTERNS).filter(
      (p) => p.cve_evidence_ids.length === 0
    );
    // This list is allowed to be empty or non-empty; the test just asserts
    // that the data model supports the empty case (no throw from mapping load).
    expect(Array.isArray(gapKcs)).toBe(true);
  });
});
