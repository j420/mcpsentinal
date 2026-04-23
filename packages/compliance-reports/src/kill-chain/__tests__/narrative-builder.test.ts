import { describe, it, expect } from "vitest";
import { buildNarrative, uniqSorted } from "../narrative-builder.js";
import type { AttackChainRow, KillChainPattern } from "../types.js";

function makePattern(overrides: Partial<KillChainPattern> = {}): KillChainPattern {
  return {
    kc_id: "KC01",
    name: "Indirect Injection → Data Exfiltration",
    description:
      "An attacker hides instructions inside content that an AI agent " +
      "fetches through one MCP server.",
    cve_evidence_ids: [
      "research-embrace-the-red-indirect-injection-2024",
      "CVE-2025-30066",
    ],
    default_mitigations: [
      "Isolate untrusted-content ingestion servers into their own agent session.",
      "Require explicit human approval for outbound send actions.",
    ],
    ...overrides,
  };
}

function makeChain(overrides: Partial<AttackChainRow> = {}): AttackChainRow {
  return {
    id: "row-1",
    template_id: "KC01",
    scan_id: "scan-1",
    severity_score: 0.83,
    contributing_rule_ids: ["G1", "F1", "A1"],
    edge_path: [
      "web-scraping MCP fetches untrusted content",
      "filesystem MCP reads ~/.ssh/id_rsa",
      "Slack MCP posts content to attacker webhook",
    ],
    mitigations: [
      "Remove the web-scraping server from this agent session.",
    ],
    synthesized_at: "2026-04-23T12:00:00.000Z",
    ...overrides,
  };
}

describe("uniqSorted", () => {
  it("dedupes and sorts a string array", () => {
    expect(uniqSorted(["b", "a", "a", "c", "b"])).toEqual(["a", "b", "c"]);
  });

  it("returns [] for empty input", () => {
    expect(uniqSorted([])).toEqual([]);
  });
});

describe("buildNarrative", () => {
  it("produces a header line with KC id, name, and formatted severity", () => {
    const out = buildNarrative(makeChain(), makePattern());
    expect(out).toMatch(/^This server matched kill chain KC01 \(/);
    expect(out).toContain('"Indirect Injection → Data Exfiltration"');
    expect(out).toContain("severity 0.83");
  });

  it("always renders severity to two decimals, including zero-padding", () => {
    const out = buildNarrative(makeChain({ severity_score: 0.5 }), makePattern());
    expect(out).toContain("severity 0.50");
  });

  it("clamps severity to [0, 1] (no out-of-range scores leak into the text)", () => {
    const high = buildNarrative(makeChain({ severity_score: 1.7 }), makePattern());
    const low = buildNarrative(makeChain({ severity_score: -0.3 }), makePattern());
    expect(high).toContain("severity 1.00");
    expect(low).toContain("severity 0.00");
  });

  it("includes the pattern description paragraph verbatim", () => {
    const pattern = makePattern({ description: "A unique regulator sentence." });
    const out = buildNarrative(makeChain(), pattern);
    expect(out).toContain("A unique regulator sentence.");
  });

  it("renders edge_path as a numbered list", () => {
    const out = buildNarrative(makeChain(), makePattern());
    expect(out).toContain("The chain proceeds as follows:");
    expect(out).toContain("1. web-scraping MCP fetches untrusted content");
    expect(out).toContain("2. filesystem MCP reads ~/.ssh/id_rsa");
    expect(out).toContain("3. Slack MCP posts content to attacker webhook");
  });

  it("handles an empty edge_path with a graceful sentence", () => {
    const out = buildNarrative(makeChain({ edge_path: [] }), makePattern());
    expect(out).toContain("No ordered step sequence was recorded for this chain.");
  });

  it("renders contributing rules sentence sorted alphabetically", () => {
    const out = buildNarrative(
      makeChain({ contributing_rule_ids: ["G1", "A1", "F1"] }),
      makePattern()
    );
    // Alphabetic sort: A1, F1, G1
    expect(out).toContain(
      "Detection rules that fired contributing to this chain: A1, F1, G1."
    );
  });

  it("handles empty contributing_rule_ids with a graceful sentence", () => {
    const out = buildNarrative(
      makeChain({ contributing_rule_ids: [] }),
      makePattern()
    );
    expect(out).toContain("No single-server detection rules contributed to this chain.");
  });

  it("renders the CVE-evidence sentence with sorted ids and correct count", () => {
    const out = buildNarrative(makeChain(), makePattern());
    expect(out).toContain(
      "demonstrated in the wild by 2 CVE/research replays in MCP Sentinel's Phase 4 corpus:"
    );
    // Sorted alphabetically.
    expect(out).toContain(
      "CVE-2025-30066, research-embrace-the-red-indirect-injection-2024"
    );
  });

  it("uses singular 'replay' for exactly one CVE citation", () => {
    const pattern = makePattern({ cve_evidence_ids: ["CVE-2025-6514"] });
    const out = buildNarrative(makeChain(), pattern);
    expect(out).toContain("by 1 CVE/research replay in MCP Sentinel's Phase 4 corpus:");
  });

  it("renders the honest-gap sentence when cve_evidence_ids is empty", () => {
    const pattern = makePattern({ cve_evidence_ids: [] });
    const out = buildNarrative(makeChain(), pattern);
    expect(out).toContain(
      "No published CVE replays in Phase 4 directly exemplify this chain class yet"
    );
    expect(out).toContain("gap tracked for Phase 6 corpus expansion");
  });

  it("merges chain.mitigations and pattern.default_mitigations (deduped + sorted)", () => {
    const pattern = makePattern({
      default_mitigations: [
        "M default 1",
        "M default 2",
      ],
    });
    const chain = makeChain({
      mitigations: ["M chain a", "M default 1"], // dup with pattern
    });
    const out = buildNarrative(chain, pattern);
    expect(out).toContain("Recommended mitigations:");
    // M default 1 must appear only ONCE.
    const occurrences = (out.match(/M default 1/g) ?? []).length;
    expect(occurrences).toBe(1);
    // All three should be present as bullets.
    expect(out).toContain("- M chain a");
    expect(out).toContain("- M default 1");
    expect(out).toContain("- M default 2");
  });

  it("handles empty mitigations with a graceful sentence", () => {
    const pattern = makePattern({ default_mitigations: [] });
    const chain = makeChain({ mitigations: [] });
    const out = buildNarrative(chain, pattern);
    expect(out).toContain("No mitigations were recorded for this chain.");
  });

  it("preserves the fixed section order for renderer predictability", () => {
    const out = buildNarrative(makeChain(), makePattern());
    const headerIdx = out.indexOf("This server matched kill chain");
    const descIdx = out.indexOf(makePattern().description);
    const stepsIdx = out.indexOf("The chain proceeds as follows:");
    const rulesIdx = out.indexOf("Detection rules that fired");
    const cveIdx = out.indexOf("demonstrated in the wild");
    const mitIdx = out.indexOf("Recommended mitigations:");

    expect(headerIdx).toBeGreaterThanOrEqual(0);
    expect(descIdx).toBeGreaterThan(headerIdx);
    expect(stepsIdx).toBeGreaterThan(descIdx);
    expect(rulesIdx).toBeGreaterThan(stepsIdx);
    expect(cveIdx).toBeGreaterThan(rulesIdx);
    expect(mitIdx).toBeGreaterThan(cveIdx);
  });
});
