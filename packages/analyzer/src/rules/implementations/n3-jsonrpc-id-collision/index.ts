/**
 * N3 — JSON-RPC Request ID Collision (Rule Standard v2).
 *
 * The legacy jsonrpc-protocol-v2.ts implementation shipped under id "N3" but
 * targeted PROGRESS TOKEN generation — an N7 concern. This migration aligns
 * the rule with its YAML (`rules/N3-jsonrpc-id-collision.yaml`): predictable
 * JSON-RPC request id generators (counter, Date.now, integer literal) that
 * enable response spoofing per CVE-2025-6515's class.
 *
 * See CHARTER.md for the full threat narrative and audit contract.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import type { Location } from "../../location.js";
import { gather, type IdAssignment } from "./gather.js";
import {
  verifyRhsIsPredictable,
  verifyNoCryptoGenerator,
  verifyTransportAllowsSpoofing,
  toLocation,
} from "./verification.js";

const RULE_ID = "N3";
const RULE_NAME = "JSON-RPC Request ID Collision";
const OWASP = "MCP07-insecure-config";
const SEVERITY = "high" as const;
const CONFIDENCE_CEILING = 0.85;

const REMEDIATION =
  "Generate JSON-RPC request ids with crypto.randomUUID() (or equivalent: " +
  "nanoid/cuid/ulid/crypto.randomBytes). Never use a sequential integer counter, " +
  "Date.now(), or any timestamp-monotonic source. Validate that every response id " +
  "matches a pending request id before dispatching its payload — the id MUST NOT be " +
  "used as a dispatch key without prior registration. JSON-RPC 2.0 Section 4.1 " +
  "requires uniqueness; response-spoofing defence requires unpredictability.";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

export class N3JsonRpcIdCollision implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const { facts } = gather(context.source_code);
    if (facts.length === 0) return [];

    return [this.buildFinding(facts[0])];
  }

  private buildFinding(fact: IdAssignment): RuleResult {
    const b = new EvidenceChainBuilder();
    const loc: Location = toLocation(fact.location);

    b.source({
      source_type: "file-content",
      location: loc,
      observed: fact.location.snippet,
      rationale:
        `Request id assignment uses a ${fact.generator_kind} source ` +
        `(${fact.rhs_expression}). JSON-RPC 2.0 Section 4.1 requires uniqueness but ` +
        `not unpredictability; predictable ids enable response spoofing.`,
    });

    b.sink({
      sink_type: "network-send",
      location: loc,
      observed:
        `Predictable id "${fact.target_identifier}" reaches the wire as the response-` +
        `correlation key. Any concurrent producer on the transport can forge a reply.`,
      cve_precedent: "CVE-2025-6515",
    });

    b.mitigation({
      mitigation_type: "sanitizer-function",
      present: false,
      location: loc,
      detail:
        `No crypto.randomUUID/randomBytes/getRandomValues/uuid/nanoid/cuid call in ` +
        `the id-assignment path` +
        (fact.location.enclosing_function
          ? ` (${fact.location.enclosing_function})`
          : "") +
        `. The attacker can enumerate the next id.`,
    });

    b.impact({
      impact_type: "session-hijack",
      scope: "connected-services",
      exploitability: "moderate",
      scenario:
        `An adversary with any injection capability on the transport (shared proxy, ` +
        `compromised intermediary, multi-writer SSE) races a forged JSON-RPC response ` +
        `whose id matches the client's next pending request. The client honours the ` +
        `forged payload as a legitimate reply. Same primitive as CVE-2025-6515.`,
    });

    b.factor(
      "predictable_request_id_generator",
      0.14,
      `AST-confirmed: ${fact.target_identifier} assigned from ${fact.generator_kind} ` +
        `(${fact.rhs_expression}); enclosing scope has no cryptographic generator.`,
    );

    b.reference({
      id: "CVE-2025-6515",
      title: "oatpp-mcp Session ID Prediction",
      relevance:
        "Documents the defect class when a request/response correlation identifier is predictable. JSON-RPC request ids inherit the same attack primitive.",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6515",
    });

    b.verification(verifyRhsIsPredictable(fact));
    b.verification(verifyNoCryptoGenerator(fact));
    b.verification(verifyTransportAllowsSpoofing(fact));

    const raw = b.build();
    const chain = { ...raw, confidence: Math.min(raw.confidence, CONFIDENCE_CEILING) };

    return {
      rule_id: RULE_ID,
      severity: SEVERITY,
      owasp_category: OWASP,
      mitre_technique: "AML.T0054",
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new N3JsonRpcIdCollision());
