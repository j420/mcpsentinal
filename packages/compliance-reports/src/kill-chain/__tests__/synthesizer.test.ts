import { describe, it, expect } from "vitest";
import type { CVEReplayCase } from "@mcp-sentinel/red-team";
import { synthesizeKillChains } from "../synthesizer.js";
import type { AttackChainRow } from "../types.js";

function cveCase(id: string, kind: "cve" | "research" = "cve"): CVEReplayCase {
  return {
    id,
    kind,
    title: `synthetic ${id}`,
    disclosed: "2026-01-01",
    source_url: "https://example.test/",
    affected_software: "synthetic",
    rationale:
      "Synthetic rationale for unit test — three sentences so shape-check passes. " +
      "This object is never run through the CVECorpusRunner. " +
      "It only exists to let the synthesizer test the corpus-membership filter.",
    expected_rules: [
      { rule_id: "X1", min_severity: "low", rationale: "synthetic rationale" },
    ],
    unpatched_fixture: {
      server: {
        id: `${id}-srv`,
        name: `srv-${id}`,
        description: null,
        github_url: null,
      },
    },
  };
}

function chainRow(
  template_id: AttackChainRow["template_id"],
  severity: number,
  overrides: Partial<AttackChainRow> = {}
): AttackChainRow {
  return {
    id: `row-${template_id}`,
    template_id,
    scan_id: "scan-under-test",
    severity_score: severity,
    contributing_rule_ids: ["A1"],
    edge_path: [`${template_id} step 1`, `${template_id} step 2`, `${template_id} step 3`],
    mitigations: [`${template_id} specific mitigation`],
    synthesized_at: "2026-04-23T12:00:00.000Z",
    ...overrides,
  };
}

describe("synthesizeKillChains — end-to-end with synthetic corpus", () => {
  it("produces one narrative per chain row", () => {
    const out = synthesizeKillChains({
      chains: [chainRow("KC01", 0.8), chainRow("KC02", 0.6), chainRow("KC07", 0.4)],
      cve_corpus: [
        cveCase("research-embrace-the-red-indirect-injection-2024", "research"),
        cveCase("CVE-2025-53773"),
        cveCase("CVE-2025-54135"),
      ],
    });
    expect(out).toHaveLength(3);
  });

  it("orders narratives by severity descending, then kc_id ascending", () => {
    const out = synthesizeKillChains({
      chains: [
        chainRow("KC03", 0.5),
        chainRow("KC01", 0.9),
        chainRow("KC02", 0.9),  // tie — KC01 should still come before KC02
        chainRow("KC05", 0.7),
      ],
      cve_corpus: [],
    });
    expect(out.map((n) => n.kc_id)).toEqual(["KC01", "KC02", "KC05", "KC03"]);
  });

  it("populates cve_evidence_ids only from ids actually present in the corpus", () => {
    // KC01's mapping cites 3 research ids. Provide only one in the corpus.
    const out = synthesizeKillChains({
      chains: [chainRow("KC01", 0.8)],
      cve_corpus: [
        cveCase("research-embrace-the-red-indirect-injection-2024", "research"),
        cveCase("CVE-9999-0001"), // unrelated — must not appear
      ],
    });
    expect(out[0].cve_evidence_ids).toEqual([
      "research-embrace-the-red-indirect-injection-2024",
    ]);
  });

  it("silently drops orphan cve_evidence_ids (those not in the corpus)", () => {
    // Provide NO KC02 exemplars in the corpus → KC02 emits empty list.
    const out = synthesizeKillChains({
      chains: [chainRow("KC02", 0.7)],
      cve_corpus: [cveCase("CVE-9999-0002")],
    });
    expect(out[0].cve_evidence_ids).toEqual([]);
    // Narrative should fall back to the honest-gap sentence.
    expect(out[0].narrative).toContain(
      "No published CVE replays in Phase 4 directly exemplify this chain class yet"
    );
  });

  it("merges contributing_rule_ids deduplicated and sorted", () => {
    const out = synthesizeKillChains({
      chains: [
        chainRow("KC01", 0.7, {
          contributing_rule_ids: ["G1", "A1", "G1", "F1"], // dup
        }),
      ],
      cve_corpus: [],
    });
    expect(out[0].contributing_rule_ids).toEqual(["A1", "F1", "G1"]);
  });

  it("merges mitigations from the chain row AND the pattern defaults (deduped + sorted)", () => {
    const out = synthesizeKillChains({
      chains: [
        chainRow("KC01", 0.7, {
          mitigations: [
            "Custom row-specific action",
            "Isolate untrusted-content ingestion servers into their own agent session with no filesystem or network sinks.",
          ],
        }),
      ],
      cve_corpus: [],
    });
    const mits = out[0].mitigations;
    // Must contain both the row mitigation and all 3 pattern defaults.
    expect(mits).toContain("Custom row-specific action");
    expect(
      mits.some((m) =>
        m.includes("Isolate untrusted-content ingestion servers")
      )
    ).toBe(true);
    // Dedup: the row-level and pattern-level dup should appear only once.
    const isolateCount = mits.filter((m) =>
      m.startsWith("Isolate untrusted-content ingestion servers")
    ).length;
    expect(isolateCount).toBe(1);
    // Sorted.
    const sorted = [...mits].sort();
    expect(mits).toEqual(sorted);
  });

  it("preserves the chain's severity_score on the narrative output", () => {
    const out = synthesizeKillChains({
      chains: [chainRow("KC04", 0.42)],
      cve_corpus: [],
    });
    expect(out[0].severity_score).toBeCloseTo(0.42, 10);
  });

  it("embeds the rendered narrative string on each output record", () => {
    const out = synthesizeKillChains({
      chains: [chainRow("KC05", 0.77)],
      cve_corpus: [],
    });
    expect(out[0].narrative).toContain(
      'This server matched kill chain KC05 ("Code Generation → Execution")'
    );
    expect(out[0].narrative).toContain("KC05 step 1");
  });

  it("returns [] for an empty chains input", () => {
    const out = synthesizeKillChains({ chains: [], cve_corpus: [] });
    expect(out).toEqual([]);
  });
});
