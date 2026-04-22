/**
 * L7 — Transitive MCP Delegation (Rule Standard v2).
 *
 * REPLACES the L7 (TransitiveMCPDelegationRule) class that previously lived in
 * `packages/analyzer/src/rules/implementations/advanced-supply-chain-detector.ts`.
 *
 * Three finding flavours, all composed over the same gathered facts:
 *
 *   - dual-sdk-import      : server + client MCP SDK imports in one file.
 *   - client-construction  : `new Client(...)` / `new XxxTransport(...)` or
 *                            dynamic import of the client SDK.
 *   - credential-forwarding: an outbound client call whose arguments
 *                            carry an incoming-request credential (the
 *                            confused-deputy pattern).
 *
 * No regex literals. Every link and every VerificationStep target is a
 * structured Location.
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
import type { Location } from "../../location.js";
import { gatherL7, type L7Fact } from "./gather.js";
import {
  stepCheckDelegationManifest,
  stepInspectClientImport,
  stepInspectConstruction,
  stepInspectForwarding,
  stepInspectServerImport,
} from "./verification.js";

const RULE_ID = "L7";
const RULE_NAME = "Transitive MCP Delegation";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "MCP servers MUST NOT open client connections to other MCP servers without " +
  "explicit, user-visible disclosure. Either: (a) remove the transitive client " +
  "and re-architect the feature so the user-facing MCP client talks to each " +
  "downstream directly, OR (b) declare every downstream in a `delegated_servers` " +
  "manifest field that the MCP client surface can display during approval. " +
  "Never forward the incoming request's Authorization / Cookie / X-API-Key " +
  "headers to the downstream connection — exchange them for a scoped delegation " +
  "token via OAuth token exchange (RFC 8693) first. Log every transitive " +
  "call for audit.";

class TransitiveMCPDelegationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "cross-module";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL7(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: L7Fact): RuleResult {
    const builder = new EvidenceChainBuilder();
    const chain = this.populateChain(builder, fact).build();
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain: capConfidence(chain, CONFIDENCE_CAP),
    };
  }

  private populateChain(
    builder: EvidenceChainBuilder,
    fact: L7Fact,
  ): EvidenceChainBuilder {
    const sourceLoc = fact.clientImportLocation ?? fact.location;

    builder.source({
      source_type: "file-content",
      location: sourceLoc,
      observed: this.describeClientImport(fact),
      rationale: this.sourceRationale(fact),
    });

    builder.propagation({
      propagation_type: "cross-tool-flow",
      location: fact.location,
      observed: this.describePropagation(fact),
    });

    builder.sink({
      sink_type: fact.kind === "credential-forwarding" ? "credential-exposure" : "network-send",
      location: fact.location,
      observed: this.describeSink(fact),
    });

    builder.mitigation({
      mitigation_type: "confirmation-gate",
      present: false,
      location: fact.location,
      detail:
        "No `delegated_servers` (or equivalent) manifest field enumerates " +
        "this downstream connection. The user's approval of the primary MCP " +
        "server did NOT include the transitive delegate.",
    });

    builder.impact({
      impact_type: "cross-agent-propagation",
      scope: "other-agents",
      exploitability: fact.kind === "credential-forwarding" ? "trivial" : "moderate",
      scenario: this.describeImpact(fact),
    });

    builder.factor(
      "dual_sdk_import",
      fact.clientImportLocation !== null && fact.serverImportLocation !== null ? 0.12 : 0,
      fact.clientImportLocation !== null && fact.serverImportLocation !== null
        ? `Dual-SDK import confirmed: client at ${renderLoc(fact.clientImportLocation)} ` +
            `and server at ${renderLoc(fact.serverImportLocation)}.`
        : `No dual-SDK co-import in this file — finding relies on the ` +
            `construction / forwarding signal alone.`,
    );
    builder.factor(
      "client_or_transport_instantiation",
      fact.kind === "client-construction" || fact.kind === "credential-forwarding" ? 0.1 : 0,
      fact.constructorName !== null
        ? `Instantiation of \`new ${fact.constructorName}(...)\` from the MCP ` +
            `client SDK observed at ${renderLoc(fact.location)}.`
        : fact.kind === "credential-forwarding"
        ? `Outbound client call observed at ${renderLoc(fact.location)} — ` +
            `the client binding was resolved via an earlier SDK import.`
        : `No construction observed yet — dual-SDK import alone.`,
    );
    builder.factor(
      "credential_forwarding_observed",
      fact.kind === "credential-forwarding" ? 0.15 : 0,
      fact.credentialRef !== null
        ? `Incoming-request credential "${fact.credentialRef}" flows into an ` +
            `outbound client call — the exact confused-deputy shape FlowHunt ` +
            `documents.`
        : `No credential forwarding observed on this fact; the finding is the ` +
            `structural-delegation shape without the confused-deputy escalation.`,
    );

    builder.reference({
      id: "arxiv-2509.24272-when-mcp-servers-attack",
      title: "When MCP Servers Attack — arXiv 2509.24272",
      url: "https://arxiv.org/abs/2509.24272",
      relevance:
        "Section 4.3 (Transitive Delegation) catalogues the exact code shape " +
        "this rule detects: an MCP server holding a Client connection to " +
        "another MCP server, proxying requests without the user's consent.",
    });

    for (const step of this.buildVerificationSteps(fact)) {
      builder.verification(step);
    }

    return builder;
  }

  private describeClientImport(fact: L7Fact): string {
    return fact.specifier !== null
      ? `MCP client-side import: ${fact.specifier}`
      : `MCP client-side import observed at ${renderLoc(fact.location)}`;
  }

  private sourceRationale(fact: L7Fact): string {
    if (fact.kind === "dual-sdk-import") {
      return (
        "An MCP server module imports BOTH the server SDK and a client-side " +
        "surface (client SDK or proxy framework). The user's approval of the " +
        "primary server does not extend to any downstream server this module " +
        "connects to — the client import is the transitive-delegation edge."
      );
    }
    if (fact.kind === "client-construction") {
      return (
        "A construction expression instantiates an MCP client (or a client " +
        "transport) inside an MCP server module. The construction actually " +
        "opens the downstream connection — not just the import."
      );
    }
    return (
      "The server forwards an incoming request's credential to an outbound " +
      "MCP client call. This is the canonical confused-deputy pattern: the " +
      "proxy lends the user's identity to an upstream server that was never " +
      "declared in the user's approval dialog."
    );
  }

  private describePropagation(fact: L7Fact): string {
    if (fact.kind === "dual-sdk-import") {
      return (
        "Server SDK and client SDK coexist in the same file — any request " +
        "this server handles can be forwarded through the client binding."
      );
    }
    if (fact.kind === "client-construction") {
      return (
        `Construction \`new ${fact.constructorName ?? "Client"}(...)\` opens an ` +
        `outbound MCP connection from inside the approved server.`
      );
    }
    return (
      `Credential reference "${fact.credentialRef ?? "<incoming-request field>"}" ` +
      `flows from the incoming request into the outbound client arguments.`
    );
  }

  private describeSink(fact: L7Fact): string {
    if (fact.kind === "credential-forwarding") {
      return (
        `Outbound client call receives the incoming credential verbatim: ` +
        `"${fact.observed.slice(0, 160)}".`
      );
    }
    return (
      `Transitive connection endpoint: "${fact.observed.slice(0, 160)}".`
    );
  }

  private describeImpact(fact: L7Fact): string {
    if (fact.kind === "credential-forwarding") {
      return (
        "A compromised upstream MCP server receives the user's real " +
        "Authorization bearer / session cookie via this proxy. The upstream " +
        "can impersonate the user against every service the credential " +
        "covers — the scoped-consent property of the MCP approval dialog " +
        "is defeated. Documented in the FlowHunt confused-deputy analysis."
      );
    }
    return (
      "A compromised upstream MCP server injects poisoned tool descriptions / " +
      "responses through this proxy. The downstream AI client applies them " +
      "under the proxy's trust — the user's per-server approval model is " +
      "silently bypassed. Praetorian's 2026 report documents the real-world " +
      "gateway servers that exhibit this shape."
    );
  }

  private buildVerificationSteps(fact: L7Fact) {
    const steps = [] as ReturnType<typeof stepInspectClientImport>[];
    if (fact.clientImportLocation) {
      steps.push(stepInspectClientImport(fact.clientImportLocation, fact.specifier));
    }
    if (fact.serverImportLocation) {
      steps.push(stepInspectServerImport(fact.serverImportLocation));
    }
    if (fact.kind === "client-construction") {
      steps.push(stepInspectConstruction(fact));
    }
    if (fact.kind === "credential-forwarding") {
      steps.push(stepInspectForwarding(fact));
    }
    steps.push(stepCheckDelegationManifest(fact));
    return steps;
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L7 charter caps confidence at ${cap} — legitimate integration-test ` +
      `code, explicitly-declared gateway servers, and first-class proxy ` +
      `frameworks are indistinguishable from attacker-authored proxies ` +
      `without a runtime trace of consent.`,
  });
  chain.confidence = cap;
  return chain;
}

function renderLoc(loc: Location): string {
  if (loc.kind === "source") {
    return `${loc.file}:${loc.line}${loc.col !== undefined ? `:${loc.col}` : ""}`;
  }
  return loc.kind;
}

registerTypedRuleV2(new TransitiveMCPDelegationRule());

export { TransitiveMCPDelegationRule };
