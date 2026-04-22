/**
 * C7 — Wildcard CORS Configuration (v2).
 *
 * REPLACES the C7 definition in
 * `packages/analyzer/src/rules/implementations/code-remaining-detector.ts`.
 *
 * Pure structural AST detection. Zero regex literals. Detection logic
 * lives in `./gather.ts`; configuration tables live in `./data/config.ts`.
 *
 * Confidence cap: 0.90 — gap reserved for downstream proxies that strip
 * Access-Control-* headers and feature flags that disable the cors
 * middleware in production.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherC7, type CorsLeakFact, type CorsLeakKind } from "./gather.js";
import {
  stepInspectCorsConfig,
  stepInspectCredentialsFlag,
  stepCheckPerRouteOverride,
} from "./verification.js";

const RULE_ID = "C7";
const RULE_NAME = "Wildcard CORS Configuration";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Replace wildcard / reflected CORS with an explicit allowlist of " +
  "permitted origins. In express's cors module: " +
  "`cors({ origin: ['https://app.example.com', 'https://admin.example.com'] })`. " +
  "Never set `origin: '*'`, `origin: true`, or call `cors()` with no " +
  "arguments — all three default to wildcard. Never combine wildcard " +
  "with `credentials: true` — most browsers reject it but server-side " +
  "fetch and older browsers do not. For Python flask_cors / FastAPI " +
  "CORSMiddleware, set `origins=[\"https://...\"]` explicitly and never " +
  "rely on the default. If your MCP server is workstation-local " +
  "(stdio / loopback transport), CORS does not apply at all — remove " +
  "the cors middleware entirely instead of permitting wildcard.";

class WildcardCorsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC7(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: CorsLeakFact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale:
          `CORS is configured to permit any origin: ${describeKindLong(fact.kind)}. ` +
          `For an MCP server reachable from a browser, this lets any web origin ` +
          `trigger MCP tool calls in the user's session. The default destructive ` +
          `posture of MCP tools turns a single click into an exfiltration / write.`,
      })
      .sink({
        sink_type: "network-send",
        location: fact.location,
        observed:
          `\`Access-Control-Allow-Origin\` will be \`*\` / reflected at runtime ` +
          `for every cross-origin request that hits this configuration.`,
        cve_precedent: "CWE-942",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: fact.location,
        detail:
          `No explicit allowlist on this configuration. The wildcard / reflected ` +
          `origin permits cross-origin requests from any web page the user is ` +
          `logged in to.`,
      })
      .impact({
        impact_type: fact.credentialsFlag ? "session-hijack" : "data-exfiltration",
        scope: "connected-services",
        exploitability: fact.credentialsFlag ? "trivial" : "moderate",
        scenario:
          fact.credentialsFlag
            ? `\`credentials: true\` is paired with the wildcard origin. An ` +
              `attacker page in the user's browser issues an \`fetch(target, ` +
              `{ credentials: 'include' })\` to the MCP server endpoint. The ` +
              `browser ships the user's session cookie and Authorization ` +
              `header along with the request. The MCP server processes the ` +
              `tool invocation as if the user initiated it, exfiltrating data ` +
              `back to the attacker page via the wildcard CORS response.`
            : `An attacker page triggers a no-credentials request to the MCP ` +
              `server endpoint. For unauthenticated MCP tools (or tools that ` +
              `accept tokens via query string), the page can read the ` +
              `response. For destructive write tools, the page does not need ` +
              `to read the response — the side effect IS the exploit.`,
      })
      .factor(
        "ast_cors_pattern",
        kindAdjustment(fact.kind),
        `CORS leak shape: ${fact.kind}. ${describeKindLong(fact.kind)}.`,
      )
      .factor(
        "cors_credentials_flag",
        fact.credentialsFlag ? 0.2 : 0.02,
        fact.credentialsFlag
          ? "`credentials: true` paired with permissive origin — escalation from data exfiltration to full session abuse."
          : "Credentials flag not set in this configuration. Still high severity, but no session ride-along.",
      )
      .factor(
        "structural_test_file_guard",
        0.02,
        "AST-shape check ruled out a vitest/jest/pytest test fixture.",
      )
      .reference({
        id: "CWE-942",
        title: "CWE-942 Permissive Cross-domain Policy with Untrusted Domains",
        url: "https://cwe.mitre.org/data/definitions/942.html",
        relevance:
          "Wildcard / reflected `Access-Control-Allow-Origin` with no allowlist " +
          "matches CWE-942 directly. Combined with `Allow-Credentials: true`, " +
          "the configuration enables cross-origin session abuse from any web " +
          "origin the user is logged in to.",
      })
      .verification(stepInspectCorsConfig(fact))
      .verification(stepInspectCredentialsFlag(fact))
      .verification(stepCheckPerRouteOverride(fact));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function kindAdjustment(kind: CorsLeakKind): number {
  switch (kind) {
    case "cors-options-wildcard":
      return 0.15;
    case "cors-options-reflected":
      return 0.15;
    case "set-header-wildcard":
      return 0.15;
    case "python-cors-wildcard":
      return 0.12;
    case "cors-no-arguments":
      return 0.05;
  }
}

function describeKindLong(kind: CorsLeakKind): string {
  switch (kind) {
    case "cors-options-wildcard":
      return "explicit `origin: \"*\"` setting on a CORS middleware";
    case "cors-options-reflected":
      return "reflected origin (`origin: true` / function returning true unconditionally)";
    case "cors-no-arguments":
      return "bare `cors()` call with no arguments — defaults to wildcard origin";
    case "set-header-wildcard":
      return "manual `setHeader('Access-Control-Allow-Origin', '*')` call";
    case "python-cors-wildcard":
      return "Python `CORS(...)` configured with `origins=\"*\"` or default-wildcard";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C7 charter caps confidence at ${cap}. The remaining gap to 1.0 is ` +
      `reserved for downstream proxies that strip Access-Control-* headers ` +
      `and feature flags that disable the cors middleware in production.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new WildcardCorsRule());

export { WildcardCorsRule };
