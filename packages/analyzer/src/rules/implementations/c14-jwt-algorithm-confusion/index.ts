/**
 * C14 — JWT Algorithm Confusion / None Algorithm Attack, Rule Standard v2.
 *
 * REPLACES the C14 definition in
 * `packages/analyzer/src/rules/implementations/code-security-deep-detector.ts`.
 *
 * Custom AST walker (not the shared taint-rule-kit) because the sink is
 * a library call whose semantics depend on its OPTIONS argument shape
 * rather than on a tainted argument reaching it. All detection data
 * lives in `./data/config.ts` (guard-skipped).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import {
  EvidenceChainBuilder,
  type EvidenceChain,
} from "../../../evidence.js";
import { gatherC14, type JwtHit } from "./gather.js";
import {
  ANTI_PATTERNS,
  type AntiPatternId,
} from "./data/config.js";
import {
  stepInspectJwtCall,
  stepInspectOptions,
  stepCheckSiblingSafeCall,
  stepConfirmImpact,
} from "./verification.js";

const RULE_ID = "C14";
const RULE_NAME = "JWT Algorithm Confusion / None Algorithm Attack";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Pin the JWT algorithm explicitly on every verify call: " +
  "`jwt.verify(token, publicKey, { algorithms: ['RS256'] });`. " +
  "Never list 'none' in an algorithms array. Never use HS256 with an RSA " +
  "public key — the library will treat the public key as the HMAC secret " +
  "and accept an attacker-forged HS256 token. Use `verify=True` (default) " +
  "in PyJWT; never set `verify=False` or `verify_signature: False` outside " +
  "unit tests. Prefer asymmetric algorithms (RS256, ES256, EdDSA) for " +
  "tokens that cross trust boundaries. Validate `exp`, `iat`, `iss`, and " +
  "`aud` claims in addition to signature — a valid signature on a 3-year-" +
  "old token is still a replay. Use `ignoreExpiration: false` (default).";

const INFO_REMEDIATION =
  "A sibling verify call in the same file pins algorithms correctly. " +
  "Replicate that call's options block on this call. If the inconsistency " +
  "is intentional, document the rationale in a code comment so the rule " +
  "can be overridden with context for reviewers.";

class JwtAlgorithmConfusionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC14(context);
    if (gathered.mode !== "facts") return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: JwtHit): RuleResult {
    const spec = ANTI_PATTERNS[hit.pattern];
    const severity: "critical" | "high" | "informational" = hit.siblingSafeCallPresent
      ? "informational"
      : spec.severity;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.callLocation,
        observed: hit.callExpression,
        rationale:
          `A ${hit.identity.kind === "py-decode" ? "PyJWT" : "JWT"} library call matches the ` +
          `"${hit.pattern}" anti-pattern. The call's configuration disables or fails ` +
          `to pin signature verification, which means an attacker who controls the ` +
          `token can forge a valid-looking claim set with no cryptographic signature.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: hit.callLocation,
        observed: hit.detail,
        cve_precedent: anchorCveForPattern(hit.pattern),
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: hit.siblingSafeCallPresent,
        location: hit.callLocation,
        detail: hit.siblingSafeCallPresent
          ? "A sibling jwt.verify call in the same file pins algorithms correctly — the " +
            "inconsistency is the bug; the developer knows the secure shape."
          : "No sibling correctly-configured jwt.verify call found in this file. No " +
            "evidence the developer has applied the charter-mandated algorithm pin " +
            "elsewhere in this module.",
      })
      .impact({
        impact_type: "session-hijack",
        scope: "connected-services",
        exploitability: severity === "critical" ? "trivial" : "moderate",
        scenario:
          `Attacker forges a token with ${impactScenarioForPattern(hit.pattern)}. The ` +
          `vulnerable call accepts the token, the server returns the attacker's ` +
          `choice of sub/role/aud claims, and any authorisation decision downstream ` +
          `treats the request as authenticated. Canonical real-world precedent: ` +
          `RFC 8725 §3.1 (alg=none bypass) and CVE-2022-21449 (ECDSA psychic ` +
          `signature bypass).`,
      })
      .factor(
        "jwt_call_identity",
        0.1,
        `Library call identified as ${hit.identity.receivers.join(", ") || "<any>"}.${hit.identity.name} ` +
          `(kind=${hit.identity.kind}). Identity match comes from the AST property-access shape, ` +
          `not a string scan — a local shadow function with the same name would not match.`,
      )
      .factor(
        "algorithms_option_inspection",
        0.12,
        `Structural inspection of the options argument matched anti-pattern ` +
          `"${hit.pattern}". ${spec.description}`,
      )
      .factor(
        hit.siblingSafeCallPresent ? "sibling_safe_call_present" : "no_sibling_safe_call",
        hit.siblingSafeCallPresent ? -0.25 : 0.05,
        hit.siblingSafeCallPresent
          ? "A sibling verify call in the same file pins algorithms correctly — the " +
            "file-level baseline knows the secure shape, so this call is likely an " +
            "implementation inconsistency."
          : "No sibling verify call in the file pins algorithms correctly — the file- " +
            "level baseline does not demonstrate knowledge of the secure shape.",
      )
      .reference({
        id: "CVE-2022-21449",
        title: "ECDSA Psychic Signatures — JWT signature bypass via all-zero (r,s)",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2022-21449",
        relevance:
          "2022 CVE demonstrating algorithm-confusion-class bypass at the library " +
          "level. Same class of vulnerability: verification accepts a malformed / " +
          "unpinned signature because the algorithm check was weak.",
      })
      .verification(stepInspectJwtCall(hit))
      .verification(stepInspectOptions(hit))
      .verification(stepCheckSiblingSafeCall(hit))
      .verification(stepConfirmImpact(hit));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: hit.siblingSafeCallPresent ? INFO_REMEDIATION : REMEDIATION,
      chain,
    };
  }
}

function anchorCveForPattern(pattern: AntiPatternId): string {
  switch (pattern) {
    case "algorithms-contains-none":
    case "verify-without-options":
      return "RFC-8725-section-3.1";
    case "pyjwt-verify-false":
      return "CVE-2022-21449";
    case "decode-used-as-verify":
      return "CWE-347";
    case "ignore-expiration-true":
      return "CWE-613";
    case "algorithms-reference-not-literal":
      return "RFC-8725-section-3.1";
  }
}

function impactScenarioForPattern(pattern: AntiPatternId): string {
  switch (pattern) {
    case "algorithms-contains-none":
    case "verify-without-options":
      return 'header alg="none" and no signature';
    case "pyjwt-verify-false":
      return "arbitrary payload; the library never inspects the signature";
    case "decode-used-as-verify":
      return "any payload; the code calls decode() which does not verify";
    case "ignore-expiration-true":
      return "a valid signature but an exp claim 3 years in the past";
    case "algorithms-reference-not-literal":
      return "a payload whose alg claim targets whatever algorithm the unseen binding allows";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C14 charter caps confidence at ${cap}. The 0.08 gap accounts for ` +
      `middleware-based algorithm pinning (express-jwt, fastify-jwt, NestJS ` +
      `AuthGuard) that wraps the library call in configuration the static ` +
      `analyser cannot see from this file alone.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new JwtAlgorithmConfusionRule());

export { JwtAlgorithmConfusionRule };
