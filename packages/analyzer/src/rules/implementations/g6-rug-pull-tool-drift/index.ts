/**
 * G6 — Rug Pull / Tool Behavior Drift (v2)
 *
 * Orchestrator. Consumes the diff against the previous-scan baseline
 * produced by `gather.ts` and emits v2 RuleResult[] with evidence
 * chains showing the added/modified tool surface.
 *
 * Charter contract: G6 is context-dependent. When no baseline exists
 * the rule MUST NOT fire. Current scanner architecture provides a
 * single-prior-scan pin; this is the "weak" mode with confidence
 * capped at 0.40. A future multi-scan baseline will lift the cap to
 * 0.80 and the "stable" mode.
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
import { gatherG6, type G6Gathered, type AddedTool } from "./gather.js";
import {
  stepInspectAddedTool,
  stepCompareBaseline,
  stepInspectModifiedTool,
} from "./verification.js";

const RULE_ID = "G6";
const RULE_NAME = "Rug Pull / Tool Behavior Drift";
const OWASP = "MCP02-tool-poisoning" as const;
const MITRE = "AML.T0054" as const;
/** Weak-baseline confidence cap — current architecture. */
const WEAK_CAP = 0.4;
/** Stable-baseline confidence cap — future multi-scan architecture. */
const STABLE_CAP = 0.8;

const REMEDIATION =
  "Investigate the newly-added or mutated tools against the server's release " +
  "notes. If the addition is an unauthorised or unannounced change, revoke the " +
  "client-side approval for this server, remove it from any allowlist, and pin " +
  "to a known-good version. If the server is essential, consider disabling it " +
  "until you can audit the added tools' source code. Users operating " +
  "trust-on-first-use MCP clients should adopt a client build that re-prompts " +
  "on tool-surface change (composite_hash differs from the prior session).";

const REF_EMBRACE_THE_RED = {
  id: "EmbraceTheRed-2025-MCP-Rug-Pull",
  title: "Embrace The Red — MCP Rug Pull",
  url: "https://embracethered.com/blog/posts/2025/mcp-rug-pull/",
  relevance:
    "Johann Rehberger's 2025 demonstration of the MCP rug-pull attack is the " +
    "primary public reference for G6. The rule operationalises Rehberger's " +
    "threat model as a per-scan temporal signal.",
} as const;

class RugPullToolDriftRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  /** Declare scan_history as a logical requirement — engine uses this for coverage reporting. */
  readonly requires: RuleRequirements = { scan_history: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherG6(context);

    // Charter edge case: no baseline → rule MUST NOT fire.
    if (gathered.mode === "absent") return [];

    // No drift since baseline → nothing to report.
    if (
      gathered.addedTools.length === 0 &&
      gathered.modifiedTools.length === 0 &&
      !gathered.fullReplacement
    ) {
      return [];
    }

    // Whether we fire only depends on: ≥1 added tool OR ≥1 modified tool OR
    // full replacement. We emit one finding per rug-pull event per server
    // (not per added tool) to keep the finding list audit-friendly.
    return [this.buildFinding(gathered)];
  }

  private buildFinding(g: G6Gathered): RuleResult {
    const primaryAdded = g.addedTools[0] ?? null;
    const sourceLocation = primaryAdded?.toolLocation ?? g.capabilityLocation;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: sourceLocation,
        observed: describeSource(g),
        rationale:
          "Rug-pull attacks establish initial trust with a benign tool surface, " +
          "then silently mutate in a later release. MCP clients typically cache " +
          "approval decisions against the server identifier and do not re-prompt " +
          "when the tool list changes. The difference between the previous-scan " +
          "fingerprint and today's is the temporal signal that reveals the " +
          "mutation to the scanner even though the client is still treating the " +
          "server as 'approved'.",
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: g.capabilityLocation,
        observed:
          `Tool surface mutation: +${g.addedTools.length} added, ` +
          `${g.modifiedTools.length} modified, ${g.diff?.unchanged ?? 0} unchanged.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: sourceLocation,
        observed:
          g.dangerousAddedCount > 0
            ? `${g.dangerousAddedCount} of the newly-added tools map to the ` +
              `dangerous-tool vocabulary (command-execution, filesystem- ` +
              `destructive, network-egress, credential-access, or administrative). ` +
              `These inherit the server's existing trust grant.`
            : `Newly-added or mutated tools inherit the server's existing trust ` +
              `grant without a fresh user approval prompt.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "ai-client",
        exploitability: g.dangerousAddedCount > 0 ? "trivial" : "moderate",
        scenario:
          `Users originally approved this server based on the baseline tool ` +
          `surface. The AI client has cached that approval and does not re-prompt ` +
          `when the tool list mutates. The ${g.addedTools.length} new tool(s) ` +
          `can be invoked by the LLM under the original trust grant, even though ` +
          `the user has never seen their names, descriptions, or schemas. This is ` +
          `the canonical Embrace-The-Red rug-pull attack model applied to an MCP ` +
          `server.`,
      });

    addBaselineFactor(builder, g);
    addDangerFactor(builder, g);
    addMagnitudeFactor(builder, g);

    builder.reference(REF_EMBRACE_THE_RED);
    for (const added of g.addedTools) {
      builder.verification(stepInspectAddedTool(added));
    }
    for (const modified of g.modifiedTools) {
      builder.verification(stepInspectModifiedTool(modified));
    }
    builder.verification(stepCompareBaseline(g.capabilityLocation));

    // Weak baseline (single prior scan) caps at 0.40; stable baseline caps at 0.80.
    const cap = g.mode === "stable" ? STABLE_CAP : WEAK_CAP;
    const chain = capConfidence(builder.build(), cap, g.mode);

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

// ─── Factor builders ───────────────────────────────────────────────────────

function addBaselineFactor(builder: EvidenceChainBuilder, g: G6Gathered): void {
  if (g.mode === "weak") {
    builder.factor(
      "baseline_reference",
      0.08,
      "Single-prior-scan baseline available. This is the current scanner " +
        "architecture; confidence is capped at 0.40 until a multi-scan stable " +
        "baseline is persisted. An honest version upgrade is indistinguishable " +
        "from a rug-pull with only one prior data point.",
    );
  } else {
    builder.factor(
      "baseline_reference",
      0.15,
      "Stable baseline available (two or more prior scans with unchanged " +
        "fingerprint). A mutation against a stable-for-two-scans baseline is " +
        "the canonical rug-pull signal.",
    );
  }
}

function addDangerFactor(builder: EvidenceChainBuilder, g: G6Gathered): void {
  if (g.dangerousAddedCount === 0) return;
  const primary = g.addedTools.find((a) => a.danger !== null);
  if (!primary || !primary.danger) return;
  builder.factor(
    "dangerous_new_tool",
    g.dangerousAddedCount > 2 ? 0.15 : 0.08,
    `${g.dangerousAddedCount} newly-added tool(s) named against the ` +
      `dangerous-tool vocabulary. Representative example: "${primary.name}" ` +
      `(${primary.danger.class}). ${primary.danger.rationale}`,
  );
}

function addMagnitudeFactor(builder: EvidenceChainBuilder, g: G6Gathered): void {
  if (g.fullReplacement) {
    builder.factor(
      "full_tool_replacement",
      0.12,
      "Every tool in the server's surface differs from the baseline — the tool " +
        "set has been wholesale replaced. This is a degenerate rug-pull where " +
        "the attacker has repurposed the server identifier for a new product.",
    );
    return;
  }
  if (g.addedTools.length > 5) {
    builder.factor(
      "large_addition_batch",
      0.05,
      `${g.addedTools.length} new tools added in a single scan window (>5 ` +
        `threshold). A typical honest version bump ships fewer new tools at ` +
        `once; the magnitude is a rug-pull amplifier.`,
    );
  }
}

function describeSource(g: G6Gathered): string {
  const primary: AddedTool | undefined = g.addedTools[0];
  if (primary) {
    return (
      `Tool surface mutation detected: new tool "${primary.name}" (hash ` +
      `${primary.hash.slice(0, 12)}…) was not present in the previous scan's ` +
      `baseline pin.`
    );
  }
  const mod = g.modifiedTools[0];
  if (mod) {
    return (
      `Tool surface mutation detected: existing tool "${mod.name}" has mutated ` +
      `field(s) ${mod.changedFields.join(", ")} (previous ${mod.previousHash.slice(0, 12)}…, ` +
      `current ${mod.currentHash.slice(0, 12)}…).`
    );
  }
  return `Tool surface mutation detected (full replacement).`;
}

function capConfidence(chain: EvidenceChain, cap: number, mode: G6Gathered["mode"]): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      mode === "weak"
        ? `G6 weak-baseline mode caps confidence at ${cap} — a single prior ` +
          `scan cannot distinguish an honest version upgrade from a rug-pull. ` +
          `The reviewer must corroborate against the server's release history.`
        : `G6 charter caps confidence at ${cap} — even with a stable baseline, ` +
          `intent is not statically observable. The reviewer must inspect the ` +
          `release notes before concluding deliberate rug-pull.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new RugPullToolDriftRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { RugPullToolDriftRule };
