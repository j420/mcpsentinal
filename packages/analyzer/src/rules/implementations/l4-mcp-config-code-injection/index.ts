/**
 * L4 — MCP Config File Code Injection (v2).
 *
 * Orchestrator. Consumes the structural facts gathered by `gather.ts`
 * (object literals matching the MCP config shape; primitives on their
 * command/args/env children) and emits one RuleResult per primitive.
 *
 * Zero regex. Confidence cap 0.85 (CHARTER §"Why confidence is capped").
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
import { renderLocation, type Location } from "../../location.js";
import { gatherL4, type L4ConfigContext, type L4Primitive, type L4PrimitiveKind } from "./gather.js";
import {
  stepInspectConfigLiteral,
  stepInspectPrimitive,
  stepInspectTargetConfigFile,
} from "./verification.js";

const RULE_ID = "L4";
const RULE_NAME = "MCP Config File Code Injection";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0060" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Remove shell interpreters from MCP config command fields — use direct " +
  "binary paths and pass arguments as array elements (never as a single -c " +
  "string). Reject any env-block key whose name is not on a strict safe-list " +
  "(PORT, HOST, LOG_LEVEL, NODE_ENV); API-base overrides (ANTHROPIC_API_URL, " +
  "OPENAI_API_BASE, AZURE_OPENAI_ENDPOINT) must be blocked at parse time. " +
  "Never ship credentials as command-line arguments — use a credential-store " +
  "delivery mechanism. Apply the CVE-2025-59536 and CVE-2026-21852 patches " +
  "on Claude Code; on Cursor require the workspace-trust prompt BEFORE MCP " +
  "servers execute (see CVE-2025-54135 for the auto-start primitive).";

/** Map a primitive kind to the EvidenceChain sink/impact taxonomy. */
function classifyPrimitive(kind: L4PrimitiveKind): {
  sinkType: "command-execution" | "network-send" | "credential-exposure";
  impactType: "remote-code-execution" | "credential-theft";
  impactScope: "server-host" | "connected-services";
  cve: string;
  threatTitle: string;
  threatUrl: string;
} {
  switch (kind) {
    case "shell-interpreter-command":
    case "fetch-and-execute-in-args":
      return {
        sinkType: "command-execution",
        impactType: "remote-code-execution",
        impactScope: "server-host",
        cve: "CVE-2025-59536",
        threatTitle:
          "Claude Code — repository-controlled .mcp.json executes server " +
          "command before user trust dialog",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2025-59536",
      };
    case "api-base-env-redirect":
      return {
        sinkType: "network-send",
        impactType: "credential-theft",
        impactScope: "connected-services",
        cve: "CVE-2026-21852",
        threatTitle:
          "Claude Code API key exfiltration — MCP config env override redirects " +
          "ANTHROPIC_API_URL to attacker",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-21852",
      };
    case "sensitive-env-in-args":
      return {
        sinkType: "credential-exposure",
        impactType: "credential-theft",
        impactScope: "connected-services",
        cve: "CVE-2026-21852",
        threatTitle:
          "Claude Code API key exfiltration — MCP config ships credentials as " +
          "plain-text command arguments",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-21852",
      };
  }
}

class MCPConfigCodeInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL4(context);
    if (gathered.isTestFile) return [];

    const out: RuleResult[] = [];
    for (const ctx of gathered.contexts) {
      for (const primitive of ctx.primitives) {
        out.push(this.buildFinding(ctx, primitive));
      }
    }
    return out;
  }

  private buildFinding(ctx: L4ConfigContext, primitive: L4Primitive): RuleResult {
    const c = classifyPrimitive(primitive.kind);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: ctx.literalLocation,
        observed: `MCP config literal at ${summariseLocation(ctx.literalLocation)}`,
        rationale:
          `Source code defines an MCP server entry whose child fields carry a ` +
          `code-execution or credential-exfiltration primitive. When this literal ` +
          `reaches an MCP config loader (either via writeFileSync in this file or ` +
          `via export to an out-of-file consumer), the primitive executes with the ` +
          `agent's permissions.`,
      })
      .propagation({
        propagation_type: ctx.writesToConfigFile ? "direct-pass" : "variable-assignment",
        location: ctx.literalLocation,
        observed: ctx.writesToConfigFile
          ? `Literal is serialised into an MCP config file via writeFileSync/writeFile.`
          : `Literal is exported as config; the consumer loads it into an MCP config.`,
      })
      .sink({
        sink_type: c.sinkType,
        location: primitive.location,
        observed: primitive.observed,
        cve_precedent: c.cve,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: primitive.location,
        detail:
          `No config-content allowlist, command-field sanitiser, or env-block ` +
          `key filter intercepts this primitive before the MCP client loads it.`,
      })
      .impact({
        impact_type: c.impactType,
        scope: c.impactScope,
        exploitability: ctx.writesToConfigFile ? "trivial" : "moderate",
        scenario: impactScenarioFor(primitive.kind, ctx),
      })
      .factor(
        "mcp_config_context_identified",
        0.08,
        `Object-literal structurally matches the MCP config shape (mcpServers → ` +
          `{ name: { command, args, env } }).`,
      )
      .factor(
        "primitive_classified",
        0.12,
        `Primitive identified: ${primitive.kind} — ${primitive.detail}`,
      )
      .factor(
        ctx.writesToConfigFile ? "config_write_in_same_file" : "config_literal_exported",
        ctx.writesToConfigFile ? 0.1 : 0.02,
        ctx.writesToConfigFile
          ? `A writeFileSync / writeFile targeting an MCP config filename exists in ` +
            `the same file — the literal almost certainly lands on disk.`
          : `No config write observed in this file; the literal may be consumed by ` +
            `an out-of-file loader.`,
      )
      .reference({
        id: c.cve,
        title: c.threatTitle,
        url: c.threatUrl,
        relevance:
          `The ${c.cve} advisory documents this exact primitive. The finding ` +
          `matches the CVE's technique; apply the referenced patch.`,
      })
      .verification(stepInspectConfigLiteral(ctx))
      .verification(stepInspectPrimitive(primitive))
      .verification(stepInspectTargetConfigFile(ctx));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function impactScenarioFor(kind: L4PrimitiveKind, ctx: L4ConfigContext): string {
  switch (kind) {
    case "shell-interpreter-command":
      return (
        `On next MCP client launch, the config's command field spawns a shell ` +
        `interpreter whose -c argument is an arbitrary string. CVE-2025-59536 ` +
        `(CVSS 8.7) demonstrates this primitive executes BEFORE the user sees ` +
        `the trust dialog on Claude Code. A repository-committed .mcp.json ` +
        `compromises every developer who opens the project.`
      );
    case "fetch-and-execute-in-args":
      return (
        `The args array carries a fetch-and-execute payload (curl | sh style). ` +
        `On next MCP client launch the shell runs a network fetch of attacker- ` +
        `controlled content and pipes it to a shell — the CVE-2025-59536 remote- ` +
        `fetch variant. No authentication, no user confirmation.`
      );
    case "api-base-env-redirect":
      return (
        `The env block redirects the server's outbound AI-API traffic to an ` +
        `attacker-controlled endpoint. CVE-2026-21852 demonstrates this exfiltrates ` +
        `the user's API key on first invocation — no shell execution required, ` +
        `no user-facing indicator.` +
        (ctx.writesToConfigFile ? " Config file is written in the same file — the redirect persists across sessions." : "")
      );
    case "sensitive-env-in-args":
      return (
        `Credentials (API_KEY / ACCESS_TOKEN / SECRET) are passed as plain-text ` +
        `command arguments. The server process reads its own argv and forwards ` +
        `the credential to an attacker-controlled endpoint — CVE-2026-21852's ` +
        `exfiltration primitive. The MCP client has no mechanism to redact ` +
        `per-argument credentials.`
      );
  }
}

function summariseLocation(loc: Location): string {
  return renderLocation(loc);
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L4 charter caps confidence at ${cap} — the config literal may be a ` +
      `test fixture, documentation sample, or a template a safer wrapper is ` +
      `about to re-validate. Static analysis cannot distinguish those from ` +
      `a live primitive without runtime information.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new MCPConfigCodeInjectionRule());

export { MCPConfigCodeInjectionRule };
