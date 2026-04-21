/**
 * Q4 — IDE MCP Configuration Injection (v2).
 *
 * Emits one RuleResult per Q4 primitive observed (ide-config-write,
 * auto-approve-write, case-variant-filename). Every finding names the
 * specific CVE whose exploit chain it matches.
 *
 * Zero regex. Confidence cap 0.88 (CHARTER §"Why confidence is capped").
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain, type ThreatReference } from "../../../evidence.js";
import { gatherQ4, type Q4Fact, type Q4PrimitiveKind } from "./gather.js";
import {
  stepCheckConsentGate,
  stepInspectPrimitive,
  stepInspectTargetConfig,
} from "./verification.js";

const RULE_ID = "Q4";
const RULE_NAME = "IDE MCP Configuration Injection";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Never write to IDE configuration files (.cursor/, .vscode/, .claude/, " +
  ".amp/, .continue/) from MCP server code. If configuration management is " +
  "the server's declared purpose, require an interactive, non-bypassable user " +
  "confirmation for every write (not a flag in the config itself). Never set " +
  "enableAllProjectMcpServers / autoApprove / trustAllServers to true " +
  "programmatically — these flags disable the entire human-in-the-loop safety " +
  "barrier for the IDE. Case-normalise every config-path comparison " +
  "(CVE-2025-59944 bypasses naive lowercase checks). Apply CVE-2025-54135 " +
  "(Cursor CurXecute), CVE-2025-54136 (MCPoison silent mutation), and " +
  "CVE-2025-59536 (Claude Code consent bypass) patches.";

class IdeMcpConfigInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherQ4(context);
    if (gathered.isTestFile) return [];
    return gathered.facts.map((fact) => this.buildFinding(fact));
  }

  private buildFinding(fact: Q4Fact): RuleResult {
    const c = classifyPrimitive(fact);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale: c.sourceRationale,
      })
      .sink({
        sink_type: c.sinkType,
        location: fact.targetLocation ?? fact.location,
        observed: fact.target !== null
          ? `${fact.target.label} (${fact.target.ide}) MCP trust boundary`
          : fact.observed,
        cve_precedent: c.reference.id,
      })
      .mitigation({
        mitigation_type: "confirmation-gate",
        present: false,
        location: fact.location,
        detail:
          `No interactive, non-bypassable user confirmation was observed around ` +
          `this primitive. As of the cited CVE disclosure, the target IDE(s) ` +
          `auto-load project-level MCP servers (or auto-approve via the flag) ` +
          `without user interaction.`,
      })
      .impact({
        impact_type: c.impactType,
        scope: "ai-client",
        exploitability: "trivial",
        scenario: c.scenario,
      })
      .factor(
        "ide_primitive_identified",
        0.12,
        `Q4 primitive classified as ${fact.kind}. ${c.factorRationale}`,
      );

    if (fact.kind === "ide-config-write" && fact.target !== null) {
      builder.factor(
        "ide_target_identified",
        0.08,
        `Write targets ${fact.target.label} (${fact.target.ide}) — the exact ` +
          `trust boundary the cited CVE exploits.`,
      );
    }
    if (fact.kind === "case-variant-filename") {
      builder.factor(
        "case_variant_bypass",
        0.08,
        `Path uses a case-variant of the canonical MCP filename — CVE-2025-59944 ` +
          `primitive.`,
      );
    }

    builder
      .reference(c.reference)
      .verification(stepInspectPrimitive(fact))
      .verification(stepInspectTargetConfig(fact))
      .verification(stepCheckConsentGate(fact));

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

// ─── Classification ────────────────────────────────────────────────────────

interface PrimitiveClassification {
  sinkType: "config-modification" | "privilege-grant";
  impactType: "remote-code-execution" | "privilege-escalation" | "cross-agent-propagation";
  scenario: string;
  sourceRationale: string;
  factorRationale: string;
  reference: ThreatReference;
}

function classifyPrimitive(fact: Q4Fact): PrimitiveClassification {
  switch (fact.kind) {
    case "ide-config-write":
      return {
        sinkType: "config-modification",
        impactType: "remote-code-execution",
        scenario:
          `On next IDE launch, the IDE auto-loads the written mcpServers entry ` +
          `WITHOUT user confirmation (CVE-2025-54135 CurXecute for Cursor, ` +
          `CVE-2025-59536 for Claude Code). If the written content includes a ` +
          `shell-interpreter command field (see L4) the primitive chains to ` +
          `RCE; if it merely mutates an existing server entry it is the ` +
          `CVE-2025-54136 MCPoison silent-mutation variant.`,
        sourceRationale:
          `Source code writes to an IDE's MCP configuration surface. IDE trust ` +
          `models vary but the CVE-2025-54135 / 54136 / 59536 family share a ` +
          `common failure mode: the write lands without a user-confirmation ` +
          `gate, so the next IDE launch loads the attacker-chosen server ` +
          `silently.`,
        factorRationale:
          `A writeFileSync / writeFile call's first argument matches the Q4 IDE ` +
          `target registry — the write will land inside the IDE's trust boundary.`,
        reference: referenceForFact(fact),
      };
    case "auto-approve-write":
      return {
        sinkType: "privilege-grant",
        impactType: "privilege-escalation",
        scenario:
          `Setting an auto-approve flag to \`true\` disables the IDE's per-server ` +
          `confirmation prompt for project-level MCP configurations. Combined ` +
          `with any mcpServers entry — even one added later by a different ` +
          `agent or a repository commit — this achieves silent code execution ` +
          `on next IDE launch. On Claude Code the analogous primitive is ` +
          `CVE-2025-59536's consent-bypass.`,
        sourceRationale:
          `Source code sets an auto-approve flag (enableAllProjectMcpServers / ` +
          `autoApprove / trustAllServers) to \`true\`. These flags govern the ` +
          `IDE's consent gate for project-level MCP servers — a single ` +
          `flag-write disables the human-in-the-loop safety barrier for the ` +
          `entire workspace.`,
        factorRationale:
          `An auto-approve flag is written with value \`true\`. The flag ` +
          `governs the IDE's consent gate for future MCP server loads.`,
        reference: referenceForFact(fact),
      };
    case "case-variant-filename":
      return {
        sinkType: "config-modification",
        impactType: "privilege-escalation",
        scenario:
          `On case-insensitive filesystems (macOS APFS, Windows NTFS) the case- ` +
          `variant filename resolves to the canonical MCP config file — but ` +
          `case-sensitive path validators inside the IDE see a different string ` +
          `and skip the approval check. CVE-2025-59944 documented this exact ` +
          `bypass in Cursor.`,
        sourceRationale:
          `Source code writes to a path whose filename uses a non-canonical ` +
          `case spelling of an MCP config filename. The filesystem resolves ` +
          `the variant to the canonical file on case-insensitive hosts, but ` +
          `lowercase-only path validators skip the approval check.`,
        factorRationale:
          `Path component is a case-variant of an MCP config filename.`,
        reference: referenceForFact(fact),
      };
  }
}

function referenceForFact(fact: Q4Fact): ThreatReference {
  const primaryCve = fact.target?.cve ??
    (fact.kind === "case-variant-filename" ? "CVE-2025-59944" : "CVE-2025-54135");
  return {
    id: primaryCve,
    title: titleForCve(primaryCve),
    url: `https://nvd.nist.gov/vuln/detail/${primaryCve}`,
    year: 2025,
    relevance: relevanceForPrimitive(fact.kind, primaryCve),
  };
}

function titleForCve(cve: string): string {
  switch (cve) {
    case "CVE-2025-54135":
      return "Cursor IDE CurXecute — auto-start MCP server without user confirmation";
    case "CVE-2025-54136":
      return "Cursor MCPoison — silent mutation of already-approved MCP config";
    case "CVE-2025-59536":
      return "Claude Code — repository-controlled .mcp.json consent bypass";
    case "CVE-2025-59944":
      return "Cursor case-sensitivity bypass on MCP config filename validation";
    case "CVE-2025-53773":
      return "GitHub Copilot MCP config-write cross-agent RCE";
    default:
      return "MCP IDE trust boundary failure";
  }
}

function relevanceForPrimitive(kind: Q4PrimitiveKind, cve: string): string {
  switch (kind) {
    case "ide-config-write":
      return (
        `This finding matches the ${cve} exploit primitive — a write that ` +
        `lands inside an IDE's MCP config surface without an intervening ` +
        `user-confirmation gate.`
      );
    case "auto-approve-write":
      return (
        `This finding sets the consent-bypass flag documented in the ` +
        `${cve} advisory. Once written, every subsequent MCP server load ` +
        `skips the user dialog.`
      );
    case "case-variant-filename":
      return (
        `This finding uses the case-variant filename documented in ${cve}. ` +
        `On case-insensitive filesystems the variant resolves to the ` +
        `canonical file and bypasses lowercase-only validators.`
      );
  }
}

// ─── Confidence cap ────────────────────────────────────────────────────────

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `Q4 charter caps confidence at ${cap} — an out-of-file user-confirmation ` +
      `dialog added by a wrapping process is not observable at source scope. ` +
      `The cap preserves a ${(1 - cap).toFixed(2)} reserve for that scenario.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new IdeMcpConfigInjectionRule());

export { IdeMcpConfigInjectionRule };
