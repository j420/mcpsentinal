/**
 * C8 — No Authentication on Network-Exposed Server (v2).
 *
 * REPLACES the C8 definition in
 * `packages/analyzer/src/rules/implementations/code-remaining-detector.ts`.
 *
 * Pure structural AST detection. Zero regex literals. Detection logic
 * lives in `./gather.ts`; configuration tables live in `./data/config.ts`.
 *
 * Confidence cap: 0.85 — gap reserved for network-level isolation
 * (Docker network, service-mesh mTLS, sidecar reverse proxy with auth)
 * the static analyser cannot observe.
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
import { gatherC8, type NetworkBindFact, type C8LeakKind } from "./gather.js";
import {
  stepInspectListenCall,
  stepCheckAuthMiddleware,
  stepCheckDeploymentScope,
} from "./verification.js";

const RULE_ID = "C8";
const RULE_NAME = "No Authentication on Network-Exposed Server";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Register an authentication middleware before exposing the server on a " +
  "network interface. For express: `app.use(authMiddleware)` BEFORE any " +
  "route registration; for fastify: `fastify.addHook('preHandler', " +
  "authHook)`; for FastAPI: `Depends(get_current_user)` on every router. " +
  "Acceptable auth strategies: JWT bearer (validated against an issuer + " +
  "audience), OAuth 2.1, API key (rotated, expirable, validated with " +
  "constant-time comparison), or mutual TLS. NEVER rely on a query-string " +
  "token alone — query strings leak via reverse-proxy logs and browser " +
  "history. If the MCP server is meant to be workstation-local, bind to " +
  "127.0.0.1 / localhost instead of 0.0.0.0 — most listen() / " +
  "uvicorn.run() calls default to 0.0.0.0 if the host argument is omitted, " +
  "so set the host EXPLICITLY.";

class NoAuthOnNetworkRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC8(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: NetworkBindFact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale:
          `${describeKindLong(fact.kind)} with no authentication middleware ` +
          `wired in the source. Any caller on the network can invoke the MCP ` +
          `tools — and MCP tools are destructive by default.`,
      })
      .sink({
        sink_type: "network-send",
        location: fact.location,
        observed:
          `Network listener active on a wildcard / default host without ` +
          `application-level auth.`,
        cve_precedent: "CWE-306",
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: fact.location,
        detail:
          fact.authMiddlewarePresent
            ? `An auth middleware was detected in the file but the network ` +
              `bind still fired the rule. Verify the middleware covers the ` +
              `tool-invocation routes, not only health or metrics endpoints.`
            : `No \`<app>.use(<auth>)\` call found in the source. The ` +
              `network listener accepts requests without authentication.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "connected-services",
        exploitability: "trivial",
        scenario:
          `An attacker scans the network for the open port (or pulls the ` +
          `MCP server's listed endpoint from a public discovery surface) and ` +
          `issues an MCP \`tools/list\` request. The server returns the full ` +
          `tool catalogue without authentication. The attacker then issues ` +
          `\`tools/call\` for the most destructive tool (delete / write / ` +
          `exec / fetch) and the server executes on their behalf. The MCP ` +
          `host's privileges — file system, cloud credentials, internal ` +
          `network — become the attacker's privileges.`,
      })
      .factor(
        "ast_network_bind",
        kindAdjustment(fact.kind),
        `Bind shape: ${fact.kind}. ${describeKindLong(fact.kind)}.`,
      )
      .factor(
        "auth_middleware_search",
        fact.authMiddlewarePresent ? -0.05 : 0.1,
        fact.authMiddlewarePresent
          ? "An auth middleware was detected somewhere in the source but the bind still triggered — partial coverage."
          : "No auth middleware call was discovered anywhere in the source — complete absence.",
      )
      .factor(
        "structural_test_file_guard",
        0.02,
        "AST-shape check ruled out a vitest/jest/pytest test fixture.",
      )
      .reference({
        id: "CWE-306",
        title: "CWE-306 Missing Authentication for Critical Function",
        url: "https://cwe.mitre.org/data/definitions/306.html",
        relevance:
          "A network-exposed MCP server that accepts tool invocations without " +
          "authentication is a textbook CWE-306 instance. Each tool is a " +
          "critical function (executes on behalf of the user), and the absence " +
          "of an auth gate matches the weakness exactly.",
      })
      .verification(stepInspectListenCall(fact))
      .verification(stepCheckAuthMiddleware(fact))
      .verification(stepCheckDeploymentScope(fact));

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

function kindAdjustment(kind: C8LeakKind): number {
  switch (kind) {
    case "listen-explicit-wildcard-host":
      return 0.15;
    case "python-uvicorn-wildcard":
      return 0.15;
    case "listen-default-host-no-auth":
      return 0.05;
  }
}

function describeKindLong(kind: C8LeakKind): string {
  switch (kind) {
    case "listen-explicit-wildcard-host":
      return "Server explicitly binds to 0.0.0.0 (or :: / IPv6 wildcard) — all network interfaces";
    case "listen-default-host-no-auth":
      return "Bare `listen(port)` call with no host argument — defaults to 0.0.0.0 on most Node stacks";
    case "python-uvicorn-wildcard":
      return "uvicorn.run / hypercorn.run with `host=\"0.0.0.0\"` (or `\"::\"`)";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C8 charter caps confidence at ${cap}. The remaining gap to 1.0 is ` +
      `reserved for network-level isolation (Docker network, service-mesh ` +
      `mTLS, sidecar reverse proxy with auth) the static analyser cannot ` +
      `observe.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new NoAuthOnNetworkRule());

export { NoAuthOnNetworkRule };
