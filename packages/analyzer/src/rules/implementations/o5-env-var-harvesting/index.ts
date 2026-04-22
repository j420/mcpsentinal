/**
 * O5 — Environment Variable Harvesting (Rule Standard v2).
 *
 * AST detection of bulk env-var reads in MCP server code.
 * Confidence cap 0.85. Very high signal: bulk reads have no
 * legitimate server-side use outside a debugging harness (which
 * the test-file structural skip already filters).
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
import { gatherO5, type EnvBulkReadSite } from "./gather.js";
import { stepInspectCallSite, stepCheckAllowlist } from "./verification.js";

const RULE_ID = "O5";
const RULE_NAME = "Environment Variable Harvesting";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Never enumerate the full process environment. Replace bulk reads " +
  "(Object.keys / Object.entries / Object.values / JSON.stringify / " +
  "object spread on process.env; os.environ.items / keys / values / " +
  "copy; dict(os.environ)) with named single-variable reads for " +
  "exactly the variables the server needs. If a filtered subset is " +
  "genuinely required, enforce an explicit allowlist — `ALLOWED_ENV_VARS` " +
  "or `PUBLIC_ENV_PREFIX` — and filter BEFORE the data leaves scope. " +
  "The environment commonly holds cloud credentials (AWS/GCP/Azure), " +
  "third-party API tokens, database URLs; bulk export is a full-" +
  "inventory credential dump.";

const STRATEGY_AST_BULK_SHAPE = "ast-bulk-read-shape-match";
const STRATEGY_SHARED_VOCAB = "shared-env-var-vocabulary";
const STRATEGY_SPREAD = "spread-destructure-detection";
const STRATEGY_TEST_SKIP = "test-file-structural-skip";

class EnvVarHarvestingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_AST_BULK_SHAPE,
    STRATEGY_SHARED_VOCAB,
    STRATEGY_SPREAD,
    STRATEGY_TEST_SKIP,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherO5(context);
    if (gathered.isTestFile) return [];
    const out: RuleResult[] = [];
    for (const site of gathered.sites) {
      if (site.enclosingHasAllowlist) continue;
      out.push(this.buildFinding(site));
    }
    return out.slice(0, 10);
  }

  private buildFinding(site: EnvBulkReadSite): RuleResult {
    const chain = this.buildChain(site);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private buildChain(site: EnvBulkReadSite): EvidenceChain {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: site.location,
        observed: site.observed,
        rationale:
          `The bulk access "${site.observed}" returns every variable ` +
          `the server process inherited from its parent shell — cloud ` +
          `credentials, API tokens, database URLs, GitHub PATs. Every ` +
          `user secret that is normally stored in the environment is ` +
          `now in-scope for exfiltration.`,
      })
      .propagation({
        propagation_type: "function-call",
        location: site.location,
        observed:
          `Env enumerated via ${site.kind}; receiver ${site.receiver}. ` +
          `The result is a plain JS/Python object that can flow anywhere.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed: `Bulk env read: ${site.observed}`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "user-data",
        exploitability: "trivial",
        scenario:
          `A single invocation lifts the user's entire credential ` +
          `inventory. The attacker does not need a selection heuristic — ` +
          `any AWS key, any Anthropic token, any database URL is now ` +
          `accessible. Downstream, the payload is forwarded via any ` +
          `tool response or network sink.`,
      })
      .factor(
        "env_var_bulk_read_observed",
        0.18,
        `AST-classified bulk env-var access (${site.kind}) against ` +
          `${site.receiver} (${STRATEGY_AST_BULK_SHAPE} / ` +
          `${STRATEGY_SHARED_VOCAB}).`,
      )
      .factor(
        "no_allowlist_filter_in_scope",
        0.10,
        `No allowlist / safelist / ALLOWED_ENV_VARS identifier found ` +
          `in the enclosing function — the bulk result is returned raw.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML-T0057",
        title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
        url: "https://atlas.mitre.org/techniques/AML.T0057",
        relevance:
          "Env-var harvesting is the highest-yield single call a " +
          "malicious MCP server can execute against user secrets.",
      });

    builder.verification(stepInspectCallSite(site));
    builder.verification(stepCheckAllowlist(site));

    const chain = builder.build();
    return capConfidence(chain, CONFIDENCE_CAP);
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `O5 charter caps confidence at ${cap}. Legitimate debug code ` +
      `outside a detectable test file could, in rare cases, dump env ` +
      `for diagnostic purposes; ${STRATEGY_TEST_SKIP} handles the ` +
      `common case but not every disguised test.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new EnvVarHarvestingRule());

export { EnvVarHarvestingRule };
