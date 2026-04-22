/**
 * C2 — Path Traversal (Taint-Aware), Rule Standard v2.
 *
 * REPLACES the C2 definition in
 * `packages/analyzer/src/rules/implementations/code-security-deep-detector.ts`.
 *
 * Uses the shared taint-rule-kit. Zero regex literals. Zero string-literal
 * arrays > 5 in this file. All configuration data lives in
 * `./data/config.ts` (under the guard-skipped `data/` directory).
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
  buildTaintChain,
  capConfidence,
  type TaintChainDescriptor,
  type TaintFact,
} from "../_shared/taint-rule-kit/index.js";
import { gatherC2 } from "./gather.js";
import {
  stepInspectPathSource,
  stepInspectPathSink,
  stepTracePathFlow,
  stepInspectPathSanitiser,
} from "./verification.js";

const RULE_ID = "C2";
const RULE_NAME = "Path Traversal (Taint-Aware)";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Never pass user-controlled path components directly to fs APIs. " +
  "Clamp every path to a base directory: `const resolved = path.resolve(baseDir, userPath); " +
  "if (!resolved.startsWith(baseDir + path.sep)) throw new Error(\"path escape\");`. " +
  "Reject any input containing `..`, null bytes (\\x00), Windows UNC " +
  "prefixes (\\\\?\\, \\\\.\\), or URL-encoded variants (%2e%2e, %2f, %5c). " +
  "Prefer a canonicalise-then-validate helper (for example the charter-" +
  "audited `resolveWithin` / `isSubpath` / `safeJoin` patterns) to ad-hoc " +
  "string manipulation. If the filesystem scope is fixed at build time, " +
  "hardcode it — do not accept it as input.";

const SANITIZED_REMEDIATION =
  "A sanitiser was detected on the taint path; nonetheless, confirm the " +
  "binding really resolves to a base-directory clamp (path.relative + " +
  "startsWith, resolveWithin). Bare `path.resolve` / `path.normalize` " +
  "without a subsequent `startsWith(baseDir)` check do NOT prove the " +
  "result stays inside the base directory — the finding remains at " +
  "informational until a reviewer confirms the clamp is real.";

const DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "user-parameter",
  sinkType: "file-write",
  cvePrecedent: "CVE-2025-53109",
  impactType: "privilege-escalation",
  impactScope: "server-host",
  sourceRationale: (fact) =>
    `Untrusted ${fact.sourceCategory} source — the expression reads from an ` +
    `external input surface (HTTP body/query/params, MCP tool parameter, ` +
    `process.env, process.argv, request.form). Nothing on the path clamps ` +
    `the value to a base directory, so every \`..\` segment survives into ` +
    `the filesystem API call.`,
  impactScenario: (fact) =>
    `Attacker crafts a traversal payload (\`../../etc/passwd\`, \`..%2f..%2fetc%2fshadow\`, ` +
    `or a null-byte termination like \`../secrets\\x00safe.txt\`) in the ` +
    `${fact.sourceCategory} source. The payload propagates through ` +
    `${fact.path.length} hop(s) to the filesystem sink, where it is ` +
    `concatenated into the path that node / Python opens. Result on READ: ` +
    `exfiltration of MCP server secrets, SSH private keys (~/.ssh/id_rsa), ` +
    `systemd unit files, environment configuration. Result on WRITE: ` +
    `overwrite of systemd units, addition of authorized_keys entries, ` +
    `replacement of an existing config file with attacker content. Canonical ` +
    `real-world precedent: CVE-2025-53109/53110 (Anthropic filesystem MCP ` +
    `server root-boundary bypass).`,
  threatReference: {
    id: "CVE-2025-53109",
    title: "Anthropic filesystem MCP server root boundary bypass",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53109",
    relevance:
      "2025 canonical example of unvalidated path construction in an MCP " +
      "server: user-controllable path components reached fs APIs without a " +
      "base-directory clamp, allowing an LLM-driven agent to read and write " +
      "outside its declared root. Same sink class as this finding.",
  },
  unmitigatedDetail:
    "No base-directory clamp (path.relative + startsWith / isSubpath / " +
    "resolveWithin / safeJoin) found on the taint path. The source value " +
    "reaches the filesystem call with its `..` segments intact.",
  mitigatedCharterKnownDetail: (name) =>
    `Sanitiser \`${name}\` is on the C2 charter-audited list of path-clamp ` +
    `helpers. Severity drops to informational but the finding remains so a ` +
    `reviewer can confirm the binding really resolves to a clamp.`,
  mitigatedCharterUnknownDetail: (name) =>
    `Sanitiser \`${name}\` was found on the taint path but is NOT on the ` +
    `C2 charter list. \`path.resolve\` / \`path.normalize\` are classified ` +
    `as sanitisers by the underlying analyser, but neither proves the ` +
    `result stays inside a base directory — a reviewer must audit the ` +
    `calling code for a subsequent startsWith(baseDir) check.`,
};

export class PathTraversalRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC2(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: TaintFact): RuleResult {
    const builder = buildTaintChain(fact, DESCRIPTOR);

    builder.verification(stepInspectPathSource(fact));
    builder.verification(stepInspectPathSink(fact));
    builder.verification(stepTracePathFlow(fact));
    const sanitiserStep = stepInspectPathSanitiser(fact);
    if (sanitiserStep) builder.verification(sanitiserStep);

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP, RULE_ID);

    return {
      rule_id: RULE_ID,
      severity: fact.sanitiser ? "informational" : "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: fact.sanitiser ? SANITIZED_REMEDIATION : REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new PathTraversalRule());
