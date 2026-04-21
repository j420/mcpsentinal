/**
 * J2 — Git Argument Injection (Taint-Aware + Structural), v2.
 *
 * REPLACES the J2 definition in `tainted-execution-detector.ts`. Builds on
 * the shared taint-rule-kit and then applies a git-specific filter to
 * distinguish J2 from C1 (generic command injection). Findings carry
 * additional factors recording which CVE-chain primitive was observed
 * (dangerous flag, sensitive path, or plain git-with-tainted-arg).
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
} from "../_shared/taint-rule-kit/index.js";
import { gatherJ2, type J2Fact } from "./gather.js";
import {
  stepInspectGitSource,
  stepInspectGitSink,
  stepTraceGitPath,
  stepInspectGitSanitiser,
} from "./verification.js";

const RULE_ID = "J2";
const RULE_NAME = "Git Argument Injection (Taint-Aware + Structural)";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.93;

const REMEDIATION =
  "Never pass user input to git as a raw exec argument. Use a validated " +
  "git library (simple-git with strictArgCheck mode, nodegit, isomorphic-" +
  "git) whose argv is constructed from typed, validated parameters. Always " +
  "terminate git argument lists with `--` before user-supplied paths. " +
  "Block arguments whose first characters are `--` when they originate " +
  "from user input (refuse any argv element matching the pattern — use " +
  "a character check in code, not regex). Never allow git_init on " +
  "directories outside the configured workspace; reject `.ssh`, " +
  "`.git/config`, `.git/hooks` paths explicitly. Disable git alias " +
  "expansion in MCP server contexts (`git -c alias.* =` is a known " +
  "allowlist-bypass primitive). See CVE-2025-68143 / CVE-2025-68144 / " +
  "CVE-2025-68145 for the canonical attack chain against Anthropic's " +
  "own mcp-server-git.";

const SANITIZED_REMEDIATION =
  "A git-wrapper library was detected on the path. Audit the library's " +
  "argument-validation mode (simple-git's strictArgCheck flag is the " +
  "relevant control). The finding remains in the evidence trail at " +
  "informational severity so a reviewer can verify the binding.";

const DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "user-parameter",
  sinkType: "command-execution",
  cvePrecedent: "CVE-2025-68143",
  impactType: "remote-code-execution",
  impactScope: "server-host",
  sourceRationale: (fact) =>
    `Untrusted ${fact.sourceCategory} source — the expression reads from an ` +
    `external input surface (tool argument, req.body, process.argv) and ` +
    `flows unchanged into a git invocation. The CVE-2025-68143 chain ` +
    `demonstrated that tool-parameter inputs reach git via exec without ` +
    `validation.`,
  impactScenario: (fact) =>
    `Attacker crafts a git-specific payload — a ref or path argument ` +
    `starting with \`--upload-pack=CMD\` (CVE-2025-68145), a repository ` +
    `path pointing at \`.ssh\` (CVE-2025-68144), or a \`-c core.sshCommand\` ` +
    `override — via the ${fact.sourceCategory} source. The payload ` +
    `propagates through ${fact.path.length} hop(s) to the git invocation, ` +
    `which interprets it as a git FLAG (not a data value) and executes ` +
    `the attacker's command during the git operation. Result: full RCE ` +
    `on the MCP server host, exactly as demonstrated by the Anthropic ` +
    `mcp-server-git CVE chain in October 2025.`,
  threatReference: {
    id: "CVE-2025-68143",
    title: "Anthropic mcp-server-git path validation bypass (CVE chain)",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2025-68143",
    relevance:
      "First link of the three-CVE chain (68143 + 68144 + 68145, CVSS 9.1 " +
      "combined) that achieved RCE against Anthropic's official git MCP " +
      "server via unvalidated tool-argument flow to git.",
  },
  unmitigatedDetail:
    "No git-wrapper library or argv validator found on the path — the " +
    "tainted value reaches the git exec call unchanged, giving an attacker " +
    "a git command-line with attacker-controlled arguments.",
  mitigatedCharterKnownDetail: (name) =>
    `Git wrapper \`${name}\` is on the J2 charter-audited list (simple-git, ` +
    `nodegit, isomorphic-git, or a named local validator). Severity drops ` +
    `to informational but the finding remains so a reviewer can verify ` +
    `that the library's strictArgCheck / validation mode is actually ` +
    `enabled.`,
  mitigatedCharterUnknownDetail: (name) =>
    `A sanitiser-named call \`${name}\` was found but is NOT on the J2 ` +
    `charter list. A reviewer must audit it — git-specific argument ` +
    `validators must reject leading "--", ".ssh" / ".git" paths, and "-c" ` +
    `overrides; a generic validate() function may not cover these.`,
};

export class GitArgumentInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "composite"; // ast-taint + structural

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherJ2(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: J2Fact): RuleResult {
    const builder = buildTaintChain(fact, DESCRIPTOR);

    builder.factor(
      "git_specific_sink_confirmed",
      0.1,
      `Sink expression contains a git marker; this is J2 (git-specific ` +
        `argument injection) territory rather than generic C1 command injection.`,
    );

    if (fact.dangerousFlag) {
      builder.factor(
        "cve_2025_68145_flag_observed",
        0.1,
        `Sink expression contains the dangerous git flag ` +
          `\`${fact.dangerousFlag}\` — direct match of the CVE-2025-68145 ` +
          `exploit primitive.`,
      );
    }
    if (fact.sensitivePath) {
      builder.factor(
        "cve_2025_68144_path_observed",
        0.08,
        `Sink expression touches the sensitive path \`${fact.sensitivePath}\` ` +
          `— direct match of the CVE-2025-68144 git_init primitive.`,
      );
    }

    builder.verification(stepInspectGitSource(fact));
    builder.verification(stepInspectGitSink(fact));
    builder.verification(stepTraceGitPath(fact));
    const sanitiserStep = stepInspectGitSanitiser(fact);
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

registerTypedRuleV2(new GitArgumentInjectionRule());
