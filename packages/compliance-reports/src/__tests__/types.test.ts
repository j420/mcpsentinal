import { describe, expect, it } from "vitest";

import type {
  ComplianceReport,
  ControlResult,
  ControlStatus,
  FrameworkId,
  OverallStatus,
  SignedComplianceReport,
} from "../types.js";
import { FRAMEWORK_IDS } from "../types.js";

/**
 * Type-level assertions. Most of the value of this file is in
 * compile-time TypeScript — vitest runtime assertions are duplicative
 * sanity checks on top.
 */
describe("type-level assertions", () => {
  it("FRAMEWORK_IDS contains exactly the seven declared framework ids", () => {
    const expected: readonly FrameworkId[] = [
      "eu_ai_act",
      "iso_27001",
      "owasp_mcp",
      "owasp_asi",
      "cosai_mcp",
      "maestro",
      "mitre_atlas",
    ];
    expect(new Set(FRAMEWORK_IDS)).toEqual(new Set(expected));
    expect(FRAMEWORK_IDS.length).toBe(7);
  });

  it("ControlStatus and OverallStatus unions are exhaustive as expected", () => {
    const statuses: ControlStatus[] = ["met", "unmet", "partial", "not_applicable"];
    expect(statuses.length).toBe(4);
    const overall: OverallStatus[] = [
      "compliant",
      "non_compliant",
      "partially_compliant",
      "insufficient_evidence",
    ];
    expect(overall.length).toBe(4);
  });

  it("rejects malformed report objects at the type level", () => {
    // @ts-expect-error missing required fields
    const bad: ComplianceReport = { version: "1.0" };
    expect(bad).toBeDefined();

    const bad2: ComplianceReport = {
      // @ts-expect-error version must be literal "1.0"
      version: "2.0",
      server: { slug: "", name: "", github_url: null, scan_id: "" },
      framework: { id: "eu_ai_act", name: "", version: "", last_updated: "", source_url: "" },
      assessment: {
        assessed_at: "",
        rules_version: "",
        sentinel_version: "",
        coverage_band: "high",
        coverage_ratio: 0,
        techniques_run: [],
      },
      controls: [],
      summary: {
        total_controls: 0,
        met: 0,
        unmet: 0,
        partial: 0,
        not_applicable: 0,
        overall_status: "compliant",
      },
      kill_chains: [],
      executive_summary: "",
    };
    expect(bad2).toBeDefined();

    const badControl: ControlResult = {
      control_id: "x",
      control_name: "x",
      control_description: "x",
      source_url: "https://x",
      // @ts-expect-error status must be one of the four ControlStatus values
      status: "banana",
      evidence: [],
      rationale: "",
      required_mitigations: [],
      assessor_rule_ids: [],
    };
    expect(badControl).toBeDefined();

    const badSigned: SignedComplianceReport = {
      report: {} as ComplianceReport,
      attestation: {
        // @ts-expect-error algorithm literal must be HMAC-SHA256
        algorithm: "HMAC-SHA512",
        signature: "",
        key_id: "",
        signed_at: "",
        signer: "",
        canonicalization: "RFC8785",
      },
    };
    expect(badSigned).toBeDefined();
  });
});
