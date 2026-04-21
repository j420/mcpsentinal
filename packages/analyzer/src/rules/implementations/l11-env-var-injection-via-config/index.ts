/**
 * L11 — Environment Variable Injection via MCP Config (v2).
 *
 * Consumes the structural facts from `gather.ts` and emits one finding per
 * risky env key observed in an MCP-config env block. The sink type and
 * impact classification are selected by the key's risk class (library-
 * hijack / runtime-injection / path-override / proxy-mitm / api-endpoint).
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
import { gatherL11, type L11Fact } from "./gather.js";
import type { EnvRiskClass } from "./data/risky-env-keys.js";
import {
  stepCheckAllowlistFilter,
  stepInspectEnvEntry,
  stepInspectLiteral,
} from "./verification.js";

const RULE_ID = "L11";
const RULE_NAME = "Environment Variable Injection via MCP Config";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0060" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "MCP config env blocks MUST be filtered against a strict allowlist before " +
  "they reach the spawned server process. Safe keys are the operational " +
  "basics (PORT, HOST, LOG_LEVEL, LOG_FORMAT, NODE_ENV, TZ, LANG, DEBUG). " +
  "Reject every other key at parse time, with a visible user notification. " +
  "In particular, NEVER accept LD_PRELOAD, DYLD_INSERT_LIBRARIES, " +
  "NODE_OPTIONS, PYTHONPATH, PYTHONSTARTUP, PATH, HTTP_PROXY / HTTPS_PROXY / " +
  "ALL_PROXY, ANTHROPIC_API_URL, OPENAI_API_BASE, or AZURE_OPENAI_ENDPOINT — " +
  "each of these turns the config env block into a direct code-execution " +
  "or traffic-interception primitive. Apply the CVE-2026-21852 patch on " +
  "Claude Code; treat the env section of MCP configs as a security boundary.";

class EnvVarInjectionViaConfigRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL11(context);
    if (gathered.isTestFile) return [];
    return gathered.facts.map((fact) => this.buildFinding(fact));
  }

  private buildFinding(fact: L11Fact): RuleResult {
    const classification = classifyRisk(fact.riskClass);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.literalLocation,
        observed: `MCP config literal containing env.${fact.observedKey}`,
        rationale:
          `Source code defines an MCP server configuration whose env block ` +
          `carries the ${fact.riskClass} primitive "${fact.canonicalKey}". When ` +
          `the MCP client loads this config and spawns the server, the env is ` +
          `passed to the child process — the primitive activates immediately.`,
      })
      .sink({
        sink_type: classification.sinkType,
        location: fact.entryLocation,
        observed: `env.${fact.observedKey} = ${fact.observedValue.slice(0, 80)}`,
        cve_precedent: classification.cve,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: fact.entryLocation,
        detail: fact.coexistsWithSafeKeys
          ? `Safe-listed keys (PORT / HOST / LOG_LEVEL / NODE_ENV) coexist in the ` +
            `same env block. An allowlist filter would have passed those keys while ` +
            `rejecting this risky entry — a single parse-time filter stops the attack.`
          : `No env-key allowlist between this config and the spawn() of the server ` +
            `process. Claude Code (pre-CVE-2026-21852 patch) and Cursor both ship the ` +
            `unfiltered env directly to the child process.`,
      })
      .impact({
        impact_type: classification.impactType,
        scope: classification.impactScope,
        exploitability: "trivial",
        scenario: classification.impactScenario(fact),
      })
      .factor(
        "risky_env_key_identified",
        0.1,
        `Env key \`${fact.canonicalKey}\` is on the L11 dangerous-key registry.`,
      )
      .factor(
        "risk_class_classified",
        0.08,
        `Classified as ${fact.riskClass} — ${fact.rationale}.`,
      );

    if (fact.caseMutated) {
      builder.factor(
        "case_mutated_variant",
        0.03,
        `Observed spelling "${fact.observedKey}" differs from canonical ` +
          `"${fact.canonicalKey}" — cross-platform bypass primitive.`,
      );
    }
    if (fact.coexistsWithSafeKeys) {
      builder.factor(
        "allowlist_would_have_caught",
        0.05,
        `Same env block contains safe-listed keys — an allowlist filter was a ` +
          `2-line fix that would have blocked this attack.`,
      );
    }

    builder
      .reference({
        id: classification.cve,
        title: classification.threatTitle,
        url: classification.threatUrl,
        relevance: classification.threatRelevance,
      })
      .verification(stepInspectLiteral(fact))
      .verification(stepInspectEnvEntry(fact))
      .verification(stepCheckAllowlistFilter(fact));

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

// ─── Risk-class classification ─────────────────────────────────────────────

interface RiskClassification {
  sinkType: "code-evaluation" | "network-send" | "credential-exposure" | "command-execution";
  impactType: "remote-code-execution" | "credential-theft" | "privilege-escalation";
  impactScope: "server-host" | "connected-services" | "user-data";
  cve: string;
  threatTitle: string;
  threatUrl: string;
  threatRelevance: string;
  impactScenario: (fact: L11Fact) => string;
}

function classifyRisk(kind: EnvRiskClass): RiskClassification {
  switch (kind) {
    case "library-hijack":
      return {
        sinkType: "code-evaluation",
        impactType: "remote-code-execution",
        impactScope: "server-host",
        cve: "CVE-2026-21852",
        threatTitle: "Claude Code API key exfiltration — MCP config env override",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-21852",
        threatRelevance:
          "CVE-2026-21852 documented the env-block primitive on Claude Code. " +
          "The library-hijack variant (LD_PRELOAD / DYLD_INSERT_LIBRARIES) is " +
          "the native-code RCE sibling of the API-URL-override variant the CVE " +
          "specifically enumerated.",
        impactScenario: (fact) =>
          `On next MCP client launch, the spawned server inherits ` +
          `${fact.canonicalKey} from the config env. The dynamic linker loads ` +
          `the attacker-chosen shared library BEFORE any server code runs — ` +
          `native-code RCE with the server's permissions, no user interaction, ` +
          `no trust dialog.`,
      };
    case "runtime-injection":
      return {
        sinkType: "code-evaluation",
        impactType: "remote-code-execution",
        impactScope: "server-host",
        cve: "CVE-2026-21852",
        threatTitle: "Claude Code API key exfiltration — MCP config env override",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-21852",
        threatRelevance:
          "CVE-2026-21852's env-override primitive generalises to NODE_OPTIONS " +
          "and PYTHONPATH — both deliver arbitrary code into the server " +
          "process's address space at startup.",
        impactScenario: (fact) =>
          `On next launch, ${fact.canonicalKey} causes the Node.js / Python ` +
          `runtime to load the attacker-chosen module before the server's ` +
          `main code runs. For NODE_OPTIONS=--require=./payload.js this is ` +
          `immediate RCE; for PYTHONPATH it shadows legit imports with ` +
          `attacker modules and achieves the same outcome.`,
      };
    case "path-override":
      return {
        sinkType: "command-execution",
        impactType: "privilege-escalation",
        impactScope: "server-host",
        cve: "CVE-2026-21852",
        threatTitle: "Claude Code API key exfiltration — MCP config env override",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-21852",
        threatRelevance:
          "CVE-2026-21852 primitive family includes PATH override — any " +
          "subsequent shell-out by the server resolves to an attacker binary.",
        impactScenario: (fact) =>
          `${fact.canonicalKey} override causes subsequent binary resolutions ` +
          `(git, curl, sh, node …) to hit attacker-controlled binaries first. ` +
          `The server process becomes a confused-deputy executor of attacker code.`,
      };
    case "proxy-mitm":
      return {
        sinkType: "network-send",
        impactType: "credential-theft",
        impactScope: "connected-services",
        cve: "CVE-2026-21852",
        threatTitle: "Claude Code API key exfiltration — MCP config env override",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-21852",
        threatRelevance:
          "CVE-2026-21852's proxy-override sibling — all outbound traffic " +
          "from the server process is interceptable by the attacker's proxy.",
        impactScenario: (fact) =>
          `All outbound HTTP/HTTPS traffic from the server process is routed ` +
          `through the attacker proxy set via ${fact.canonicalKey}. For HTTPS ` +
          `this is a TLS-MITM primitive (client trusts proxy-signed cert only ` +
          `if the attacker can install a CA) — the usual result is credential ` +
          `theft on first outbound request.`,
      };
    case "api-endpoint":
      return {
        sinkType: "network-send",
        impactType: "credential-theft",
        impactScope: "connected-services",
        cve: "CVE-2026-21852",
        threatTitle: "Claude Code API key exfiltration — MCP config env override",
        threatUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-21852",
        threatRelevance:
          "Direct match of CVE-2026-21852: an MCP-config env entry overrides " +
          "the AI-API endpoint and redirects all outbound AI traffic (carrying " +
          "the user's API key in the Authorization header) to the attacker.",
        impactScenario: (fact) =>
          `On next AI call, the server sends the user's API key in the ` +
          `Authorization header to the attacker proxy set via ` +
          `${fact.canonicalKey}. The attacker records the key and forwards ` +
          `requests to the real AI provider so the MITM is invisible to the ` +
          `user. This is the exact CVE-2026-21852 chain.`,
      };
  }
}

// ─── Confidence cap ────────────────────────────────────────────────────────

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L11 charter caps confidence at ${cap} — the config literal may be test ` +
      `data or a template the wrapping process will re-validate. Static ` +
      `analysis cannot distinguish those from a live primitive.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new EnvVarInjectionViaConfigRule());

export { EnvVarInjectionViaConfigRule };
