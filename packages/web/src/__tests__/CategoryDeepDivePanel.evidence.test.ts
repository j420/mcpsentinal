import { describe, it, expect } from "vitest";
import { buildLiveEvidenceChain, buildLiveRuleTests } from "../components/CategoryDeepDivePanel";
import type { FullFinding } from "../components/cdd-data";

describe("buildLiveEvidenceChain", () => {
  it("builds server-specific evidence text from structured evidence_chain payload", () => {
    const finding: FullFinding = {
      id: "f-1",
      rule_id: "A1",
      severity: "critical",
      evidence: "fallback-evidence",
      remediation: "sanitize",
      owasp_category: "MCP01",
      mitre_technique: "AML.T0000",
      confidence: 0.92,
      evidence_chain: {
        links: [
          {
            type: "source",
            source_type: "user-parameter",
            location: "tool:search.query",
            observed: "source-value",
            rationale: "untrusted",
          },
          {
            type: "sink",
            sink_type: "network-send",
            location: "tool:http.post",
            observed: "POST https://attacker.example",
          },
        ],
        verification_steps: [
          {
            step_type: "inspect-description",
            instruction: "Inspect tool description for override tokens",
            target: "tool:search",
          },
        ],
      },
    };

    const chain = buildLiveEvidenceChain(finding);
    expect(chain.source).toContain("tool:search.query");
    expect(chain.source).toContain("source-value");
    expect(chain.detection).toContain("tool:http.post");
    expect(chain.confidence_basis).toContain("92%");
    expect(chain.verification).toContain("Inspect tool description for override tokens");
  });

  it("falls back gracefully when evidence_chain is absent", () => {
    const finding: FullFinding = {
      id: "f-2",
      rule_id: "C1",
      severity: "high",
      evidence: "exec(userInput) found in handler",
      remediation: "switch to execFile",
      owasp_category: null,
      mitre_technique: null,
      confidence: undefined,
      evidence_chain: null,
    };

    const chain = buildLiveEvidenceChain(finding);
    expect(chain.source).toContain("exec(userInput) found in handler");
    expect(chain.detection).toContain("C1");
    expect(chain.confidence_basis).toContain("unavailable");
    expect(chain.verification).toContain("C1");
  });
});

describe("buildLiveRuleTests", () => {
  it("creates dynamic, scan-derived test cases from live finding payloads", () => {
    const finding: FullFinding = {
      id: "f-3",
      rule_id: "N13",
      severity: "critical",
      evidence: "chunked smuggling pattern found",
      remediation: "normalize transfer parsing",
      owasp_category: "MCP04",
      mitre_technique: "AML.T0001",
      confidence: 0.84,
      evidence_chain: {
        links: [{ type: "source", source_type: "external-content", location: "transport", observed: "chunked", rationale: "untrusted" }],
        verification_steps: [
          { step_type: "check-config", instruction: "Inspect transfer parsing guards", target: "server/http.ts" },
        ],
      },
    };

    const tests = buildLiveRuleTests(finding, []);
    expect(tests[0]?.label).toContain("Live scan triggered N13");
    expect(tests[1]?.label).toContain("Evidence links captured");
    expect(tests.some((t) => t.label.includes("Inspect transfer parsing guards"))).toBe(true);
  });
});
