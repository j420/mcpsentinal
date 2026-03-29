/**
 * Narrative & Mitigation Tests — Deterministic Output Verification
 *
 * Tests verify:
 *   1. Narrative contains objective, precedent, and per-step fragments
 *   2. Mitigations are ordered (chain-breakers first)
 *   3. Each role produces expected mitigation actions
 *   4. Deterministic output (same inputs → same output)
 */
import { describe, it, expect } from "vitest";
import { generateNarrative, generateMitigations } from "../narrative.js";
import { KC01, KC02, KC04, KC05, KC07 } from "../kill-chains.js";

import type { AttackStep, CapabilityNode } from "../types.js";

function makeStep(
  ordinal: number,
  serverName: string,
  role: AttackStep["role"],
  serverId?: string
): AttackStep {
  return {
    ordinal,
    server_id: serverId ?? `srv-${serverName}`,
    server_name: serverName,
    role,
    capabilities_used: [],
    tools_involved: [],
    edge_to_next: null,
    narrative: "",
  };
}

describe("generateNarrative", () => {
  it("KC01: includes objective, precedent, and all 3 steps", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
      makeStep(3, "webhook-sender", "exfiltrator"),
    ];
    const narrative = generateNarrative(KC01, steps);

    expect(narrative).toContain("steal sensitive data");
    expect(narrative).toContain("Claude Desktop 2024-Q4");
    expect(narrative).toContain("web-scraper");
    expect(narrative).toContain("file-manager");
    expect(narrative).toContain("webhook-sender");
    expect(narrative).toContain("1.");
    expect(narrative).toContain("2.");
    expect(narrative).toContain("3.");
  });

  it("KC02: mentions config poisoning and RCE", () => {
    const steps = [
      makeStep(1, "config-writer", "config_writer"),
      makeStep(2, "code-runner", "executor"),
    ];
    const narrative = generateNarrative(KC02, steps);

    expect(narrative).toContain("arbitrary code");
    expect(narrative).toContain("config-writer");
    expect(narrative).toContain("CVE-2025-54135");
  });

  it("KC04: mentions persistence and memory poisoning", () => {
    const steps = [
      makeStep(1, "email-reader", "injection_gateway"),
      makeStep(2, "memory-writer", "memory_writer"),
      makeStep(3, "memory-reader", "data_source"),
    ];
    const narrative = generateNarrative(KC04, steps);

    expect(narrative).toContain("persistent");
    expect(narrative).toContain("memory-writer");
  });

  it("narrative is deterministic (same inputs → same output)", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
      makeStep(3, "webhook-sender", "exfiltrator"),
    ];
    const n1 = generateNarrative(KC01, steps);
    const n2 = generateNarrative(KC01, steps);
    expect(n1).toBe(n2);
  });

  it("narrative includes server count", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
      makeStep(3, "webhook-sender", "exfiltrator"),
    ];
    const narrative = generateNarrative(KC01, steps);
    expect(narrative).toContain("3-step chain");
    expect(narrative).toContain("3 server(s)");
  });

  it("narrative mentions that combination is the danger, not individual servers", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
    ];
    const narrative = generateNarrative(KC01, steps);
    expect(narrative).toContain("combination");
  });
});

describe("generateMitigations", () => {
  it("chain-breakers come before risk-reducers in order", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
      makeStep(3, "webhook-sender", "exfiltrator"),
    ];
    const mitigations = generateMitigations(KC01, steps);

    const breakerIdx = mitigations.findIndex((m) => m.effect === "breaks_chain");
    const reducerIdx = mitigations.findIndex((m) => m.effect === "reduces_risk");

    if (breakerIdx >= 0 && reducerIdx >= 0) {
      expect(breakerIdx).toBeLessThan(reducerIdx);
    }
  });

  it("injection_gateway produces remove_server mitigation", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
    ];
    const mitigations = generateMitigations(KC01, steps);

    const removeMitigation = mitigations.find(
      (m) => m.action === "remove_server" && m.target_server_name === "web-scraper"
    );
    expect(removeMitigation).toBeDefined();
    expect(removeMitigation!.effect).toBe("breaks_chain");
    // Removing gateway should break all steps
    expect(removeMitigation!.breaks_steps).toHaveLength(steps.length);
  });

  it("executor produces add_confirmation mitigation", () => {
    const steps = [
      makeStep(1, "config-writer", "config_writer"),
      makeStep(2, "code-runner", "executor"),
    ];
    const mitigations = generateMitigations(KC02, steps);

    const confirmMitigation = mitigations.find(
      (m) => m.action === "add_confirmation" && m.target_server_name === "code-runner"
    );
    expect(confirmMitigation).toBeDefined();
  });

  it("exfiltrator produces restrict_capability mitigation", () => {
    const steps = [
      makeStep(1, "file-manager", "data_source"),
      makeStep(2, "webhook-sender", "exfiltrator"),
    ];
    const mitigations = generateMitigations(KC01, steps);

    const restrictMitigation = mitigations.find(
      (m) => m.action === "restrict_capability" && m.target_server_name === "webhook-sender"
    );
    expect(restrictMitigation).toBeDefined();
    expect(restrictMitigation!.effect).toBe("breaks_chain");
  });

  it("no duplicate mitigations for same server+role", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
      makeStep(3, "webhook-sender", "exfiltrator"),
    ];
    const mitigations = generateMitigations(KC01, steps);

    // Check no exact duplicates (same server + action)
    const keys = mitigations.map((m) => `${m.target_server_id}:${m.action}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("every mitigation references a valid server from the chain", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
      makeStep(3, "webhook-sender", "exfiltrator"),
    ];
    const serverIds = new Set(steps.map((s) => s.server_id));
    const mitigations = generateMitigations(KC01, steps);

    for (const m of mitigations) {
      expect(serverIds.has(m.target_server_id)).toBe(true);
    }
  });

  it("breaks_steps contains valid ordinals", () => {
    const steps = [
      makeStep(1, "web-scraper", "injection_gateway"),
      makeStep(2, "file-manager", "data_source"),
      makeStep(3, "webhook-sender", "exfiltrator"),
    ];
    const mitigations = generateMitigations(KC01, steps);

    const maxOrdinal = Math.max(...steps.map((s) => s.ordinal));
    for (const m of mitigations) {
      for (const o of m.breaks_steps) {
        expect(o).toBeGreaterThanOrEqual(1);
        expect(o).toBeLessThanOrEqual(maxOrdinal);
      }
    }
  });
});
