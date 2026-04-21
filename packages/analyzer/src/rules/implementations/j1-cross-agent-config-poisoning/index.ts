/**
 * J1 — Cross-Agent Configuration Poisoning (v2).
 *
 * Builds on the shared taint-rule-kit and then post-filters to writes whose
 * destination matches a known AI-agent config file (registry in
 * `data/agent-config-targets.ts`). Evidence chain names the victim agent
 * and the specific CVE-2025-53773 primitive observed.
 *
 * Zero regex. Confidence cap 0.90 (CHARTER §"Why confidence is capped").
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
import {
  buildTaintChain,
  capConfidence,
  type TaintChainDescriptor,
} from "../_shared/taint-rule-kit/index.js";
import { gatherJ1, type J1Fact } from "./gather.js";
import {
  stepInspectSanitiser,
  stepInspectWritePrimitive,
  stepTracePathToConfigTarget,
  stepVerifyVictimAgentConfig,
} from "./verification.js";

const RULE_ID = "J1";
const RULE_NAME = "Cross-Agent Configuration Poisoning";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0060" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "MCP servers MUST NOT write to another agent's configuration directory " +
  "(.claude/, .cursor/, .vscode/, .gemini/, .continue/, .amp/, ~/.mcp.json). " +
  "If configuration management is the server's declared purpose, require an " +
  "explicit, non-bypassable user confirmation before every write and assert " +
  "the destination path resolves inside the server's own namespace — symlink-" +
  "aware (use fs.realpath before comparison). Reject append-mode writes to " +
  "agent-config files; stealth mutation of a previously-approved config entry " +
  "is the CVE-2025-54136 MCPoison primitive. See CVE-2025-53773 for the " +
  "canonical cross-agent RCE chain.";

const SANITISED_REMEDIATION =
  "A charter-audited sanitiser was observed on the path. Confirm it truly " +
  "rejects the J1 target registry rather than a narrower subset, and that it " +
  "runs BEFORE any path normalisation that would strip a `..` escape. The " +
  "finding remains at informational severity so a reviewer can verify the " +
  "binding and the strict-mode flag.";

/**
 * Descriptor factory. Closes over the J1-specific target host/role so the
 * shared taint-rule-kit's impactScenario callback can see them. We build
 * one descriptor per fact rather than one module-level constant.
 */
function descriptorFor(fact: J1Fact): TaintChainDescriptor {
  return {
    ruleId: RULE_ID,
    sourceType: "agent-output",
    sinkType: "config-modification",
    cvePrecedent: "CVE-2025-53773",
    impactType: "cross-agent-propagation",
    impactScope: "other-agents",
    sourceRationale: (f) =>
      `Untrusted ${f.sourceCategory} source whose value becomes the destination ` +
      `(or content) of a filesystem write. In cross-agent architectures, output ` +
      `from one agent can be the input to another agent's config-writing tool — ` +
      `a primitive that CVE-2025-53773 demonstrated is enough to pivot into ` +
      `arbitrary code execution on the downstream agent.`,
    impactScenario: (f) =>
      `An adversary who can influence the ${f.sourceCategory} source (a prompt-` +
      `injected upstream agent, a web-fetched page, an agent-to-agent message) ` +
      `crafts an MCP server entry and relies on this write to persist it into ` +
      `${fact.targetRole}. On the next launch, the victim agent ` +
      `(${fact.targetHost}) auto-loads the attacker-controlled server — exactly ` +
      `the CVE-2025-53773 GitHub-Copilot-to-Claude-Code chain. Because MCP ` +
      `servers execute with the victim agent's permissions, the consequence is ` +
      `full RCE on the host, with no user interaction beyond the next session ` +
      `start.`,
    threatReference: {
      id: "CVE-2025-53773",
      title: "GitHub Copilot MCP config-write cross-agent RCE",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53773",
      year: 2025,
      relevance:
        "CVE-2025-53773 (CVSS 9.3, disclosed 2025-08-06) is the canonical public " +
        "demonstration of this primitive — a Copilot-side prompt injection writes " +
        "an MCP-server entry into ~/.claude/settings.local.json and achieves RCE " +
        "on the victim's Claude Code session.",
    },
    unmitigatedDetail:
      "No path-scope assertion, user-confirmation gate, or charter-audited target " +
      "allowlist found between the source and the write. The write lands directly " +
      "on the victim agent's configuration file.",
    mitigatedCharterKnownDetail: (name) =>
      `A charter-audited sanitiser \`${name}\` was observed on the path. Severity ` +
      `drops to informational but the finding remains in the evidence trail — the ` +
      `reviewer must confirm the sanitiser's strict mode is enabled.`,
    mitigatedCharterUnknownDetail: (name) =>
      `A sanitiser-named call \`${name}\` was observed but is NOT on the J1 charter ` +
      `list. A validator that calls path.normalize or JSON.stringify does not prevent ` +
      `writing to an agent-config file — a reviewer MUST audit the body.`,
  };
}

class CrossAgentConfigPoisoningRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "composite"; // ast-taint + structural path match

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherJ1(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: J1Fact): RuleResult {
    const builder: EvidenceChainBuilder = buildTaintChain(fact, descriptorFor(fact));

    // J1-specific factors — encoded on the evidence chain so the regulator
    // can see WHY the finding is J1 and not a generic C-rule match.
    builder.factor(
      "agent_config_target_identified",
      0.1,
      `Write destination matches the J1 agent-config registry entry ` +
        `\`${fact.targetSuffix}\` — ${fact.targetRole} (${fact.targetHost}).`,
    );

    // CHARTER lethal edge case #3: append mode is the MCPoison / stealth variant.
    if (fact.appendMode) {
      builder.factor(
        "append_mode_stealth",
        0.08,
        `Write is in append / appendFile mode. CVE-2025-54136 MCPoison showed that ` +
          `mutating an already-approved config entry (rather than replacing the file) ` +
          `bypasses the user-approval check because the file itself was previously ` +
          `approved.`,
      );
    }

    // CHARTER lethal edge case #4: dynamic path construction.
    if (fact.dynamicPath) {
      builder.factor(
        "dynamic_path_assembly",
        0.05,
        `Destination path is assembled at runtime from env vars / homedir() / string ` +
          `concatenation. This is the CVE-2025-53773 primitive's typical shape — the ` +
          `literal agent-config components are the fingerprint, not the full path.`,
      );
    }

    builder.verification(stepInspectWritePrimitive(fact));
    builder.verification(stepTracePathToConfigTarget(fact));
    builder.verification(stepVerifyVictimAgentConfig(fact));
    builder.verification(stepInspectSanitiser(fact));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP, RULE_ID);

    return {
      rule_id: RULE_ID,
      severity: fact.sanitiser && fact.sanitiser.charterKnown ? "informational" : "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: fact.sanitiser && fact.sanitiser.charterKnown
        ? SANITISED_REMEDIATION
        : REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new CrossAgentConfigPoisoningRule());

export { CrossAgentConfigPoisoningRule };
