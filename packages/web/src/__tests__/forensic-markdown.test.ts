import { describe, expect, it } from "vitest";
import { buildAuditPackMarkdown } from "@/lib/forensic-markdown";
import type {
  DeepDiveFinding,
  DeepDiveProvenance,
  DeepDiveRule,
} from "@/lib/deep-dive";

function rule(overrides: Partial<DeepDiveRule> = {}): DeepDiveRule {
  return {
    rule_id: "C1",
    name: "Command Injection",
    severity: "critical",
    category: "C",
    owasp: "MCP03-command-injection",
    mitre: "AML.T0054",
    summary: "",
    framework_controls: [
      {
        framework_id: "owasp_mcp",
        control_id: "MCP03",
        control_title: "Command Injection",
      },
    ],
    methodology: {
      technique: "ast-taint",
      verified_edge_cases: [],
      edge_case_strategies: [],
      confidence_cap: 0.99,
    },
    backing: null,
    remediation: "Use execFile() with array args.",
    status: "findings",
    findings: [],
    ...overrides,
  };
}

function finding(overrides: Partial<DeepDiveFinding> = {}): DeepDiveFinding {
  return {
    id: "11111111-2222-3333-4444-555555555555",
    severity: "critical",
    confidence: 0.92,
    evidence: "exec(req.body.cmd) at server.ts:42",
    evidence_chain: {
      verification_steps: [
        {
          step_type: "code-inspection",
          target: "server.ts:42",
          instruction: "Locate the exec() call and confirm req.body.cmd is user-controlled",
        },
        {
          step_type: "input-test",
          instruction: "Send a payload like `; whoami` and observe response",
        },
      ],
      confidence_factors: [
        { factor: "complete_taint_path", adjustment: 0.4, rationale: "source→sink path complete" },
        { factor: "no_mitigation", adjustment: 0.25, rationale: "no allowlist or sanitiser" },
        { factor: "try_catch_wrap", adjustment: -0.1, rationale: "exec wrapped in try/catch" },
      ],
      impact_scenario: "Remote code execution on the server host.",
    },
    remediation: "Replace exec() with execFile() and validate inputs against an allowlist.",
    ...overrides,
  };
}

function provenance(): DeepDiveProvenance {
  return {
    scan_id: "00000000-0000-0000-0000-000000000111",
    scan_completed_at: "2026-04-30T08:00:00.000Z",
    rules_version: "2026-04-23",
    sentinel_version: "0.4.0",
    signing_key_id: "mcp-sentinel-prod-v1",
  };
}

const baseInput = () => ({
  serverSlug: "demo-server",
  serverName: "Demo Server",
  rule: rule(),
  finding: finding(),
  provenance: provenance(),
  apiOrigin: "https://api.mcp-sentinel.com",
});

describe("buildAuditPackMarkdown", () => {
  it("produces a header with rule id, name, server identity, severity, confidence", () => {
    const md = buildAuditPackMarkdown(baseInput());
    expect(md).toMatch(/^# Finding C1 — Command Injection/);
    expect(md).toContain("**Server:** Demo Server (`demo-server`)");
    expect(md).toContain("**Severity:** Critical");
    expect(md).toContain("**Confidence:** 92%");
    expect(md).toContain("**OWASP:** MCP03-command-injection");
    expect(md).toContain("**MITRE ATLAS:** AML.T0054");
  });

  it("renders the evidence prose verbatim under '## Evidence'", () => {
    const md = buildAuditPackMarkdown(baseInput());
    expect(md).toContain("## Evidence");
    expect(md).toContain("exec(req.body.cmd) at server.ts:42");
  });

  it("emits a checkbox-style verification checklist when steps are present", () => {
    const md = buildAuditPackMarkdown(baseInput());
    expect(md).toContain("## How to verify");
    expect(md).toContain(
      "- [ ] Locate the exec() call and confirm req.body.cmd is user-controlled",
    );
    expect(md).toContain("- [ ] Send a payload like `; whoami`");
  });

  it("falls back to a generic checklist when no verification_steps[] are on file", () => {
    const md = buildAuditPackMarkdown({
      ...baseInput(),
      finding: finding({ evidence_chain: null }),
    });
    expect(md).toContain("## How to verify");
    expect(md).toMatch(/- \[ \] Locate the evidence in source: exec/);
    expect(md).toContain(
      "- [ ] Confirm the sink is reachable from user-controllable input",
    );
  });

  it("renders the confidence ledger as a markdown table with signed adjustments", () => {
    const md = buildAuditPackMarkdown(baseInput());
    expect(md).toContain("## Confidence ledger");
    expect(md).toContain("| Factor | Adjustment | Rationale |");
    expect(md).toContain("| complete taint path | +0.40 | source→sink path complete |");
    expect(md).toContain("| try catch wrap | -0.10 | exec wrapped in try/catch |");
    expect(md).toContain("| **Final** | **92%** | |");
  });

  it("escapes pipe characters inside rationale text so the markdown table stays valid", () => {
    const md = buildAuditPackMarkdown({
      ...baseInput(),
      finding: finding({
        evidence_chain: {
          confidence_factors: [
            { factor: "x", adjustment: 0.5, rationale: "a | b" },
          ],
        },
      }),
    });
    expect(md).toContain("| x | +0.50 | a \\| b |");
  });

  it("includes the per-finding remediation when present", () => {
    const md = buildAuditPackMarkdown(baseInput());
    expect(md).toContain("## Remediation");
    expect(md).toContain(
      "Replace exec() with execFile() and validate inputs against an allowlist.",
    );
  });

  it("falls back to rule-level remediation when the finding has none", () => {
    const md = buildAuditPackMarkdown({
      ...baseInput(),
      finding: finding({ remediation: "" }),
    });
    expect(md).toContain("## Remediation (rule-level)");
    expect(md).toContain("Use execFile() with array args.");
  });

  it("includes CVE replay validations when present", () => {
    const md = buildAuditPackMarkdown({
      ...baseInput(),
      rule: rule({
        validated_by_cve: [
          {
            id: "CVE-2025-6514",
            kind: "cve",
            title: "mcp-remote OS command injection",
            source_url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
            disclosed: "2025-07-02",
            cvss_v3: 9.6,
            min_severity: "critical",
          },
        ],
      }),
    });
    expect(md).toContain("## CVE replay validation");
    expect(md).toContain(
      "[CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)",
    );
    expect(md).toContain("CVSS 9.6");
  });

  it("emits the framework cross-walk", () => {
    const md = buildAuditPackMarkdown(baseInput());
    expect(md).toContain("## Framework cross-walk");
    expect(md).toContain("- owasp_mcp: **MCP03** — Command Injection");
  });

  it("includes provenance + signed receipt URL with the finding id", () => {
    const md = buildAuditPackMarkdown(baseInput());
    expect(md).toContain("## Provenance & attestation");
    expect(md).toContain("- **Scan:** `00000000-0000-0000-0000-000000000111`");
    expect(md).toContain("- **Rules version:** `2026-04-23`");
    expect(md).toContain("- **Signing key id:** `mcp-sentinel-prod-v1`");
    expect(md).toContain(
      "**Signed receipt:** https://api.mcp-sentinel.com/api/v1/findings/11111111-2222-3333-4444-555555555555/receipt",
    );
  });

  it("renders an honest gap when provenance is missing", () => {
    const md = buildAuditPackMarkdown({
      ...baseInput(),
      provenance: undefined,
    });
    expect(md).toContain("_Provenance metadata not on file for this scan._");
    // Receipt URL still emitted even without provenance — the audit
    // pack always points the auditor at the verifiable artefact.
    expect(md).toContain("**Signed receipt:**");
  });

  it("is byte-equal across runs for identical input (determinism contract)", () => {
    const a = buildAuditPackMarkdown(baseInput());
    const b = buildAuditPackMarkdown(baseInput());
    expect(a).toBe(b);
  });

  it("URL-encodes the finding id in the receipt URL", () => {
    const md = buildAuditPackMarkdown({
      ...baseInput(),
      finding: finding({ id: "id with spaces & symbols" }),
    });
    expect(md).toContain(
      "/api/v1/findings/id%20with%20spaces%20%26%20symbols/receipt",
    );
  });
});
