/**
 * C13 — Server-Side Template Injection (Taint-Aware), Rule Standard v2.
 *
 * REPLACES the C13 definition in
 * `packages/analyzer/src/rules/implementations/tainted-execution-detector.ts`.
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
import { gatherC13 } from "./gather.js";
import {
  stepInspectTemplateSource,
  stepInspectTemplateSink,
  stepTraceTemplatePath,
  stepInspectTemplateSanitiser,
} from "./verification.js";

const RULE_ID = "C13";
const RULE_NAME = "Server-Side Template Injection (Taint-Aware)";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Never pass a user-controlled string as the TEMPLATE SOURCE to a server-" +
  "side template engine. Pass user data only as TEMPLATE VARIABLES (context) " +
  "to a template whose source is a trusted literal or a file loaded from a " +
  "trusted location. For Jinja2: `Environment().from_string(STATIC)` + " +
  "`render(data=user_data)` — never `from_string(user_input)`. For Handlebars " +
  "/ EJS / Pug / Nunjucks / Mako: the same split — compile from a literal, " +
  "render with user data. If dynamic templates are a product requirement, " +
  "run the template engine inside a proper sandbox (Jinja2 " +
  "SandboxedEnvironment, Nunjucks with a locked-down Environment).";

const SANITIZED_REMEDIATION =
  "A sandbox was detected on the taint path; nonetheless, audit the sandbox " +
  "configuration to confirm it really restricts expression-evaluation " +
  "primitives (attribute access, class traversal, module lookup). Jinja2's " +
  "SandboxedEnvironment is the gold standard; custom sandboxes frequently " +
  "leak.";

const DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "user-parameter",
  sinkType: "template-render",
  cvePrecedent: "CWE-1336",
  impactType: "remote-code-execution",
  impactScope: "server-host",
  sourceRationale: (fact) =>
    `Untrusted ${fact.sourceCategory} source — the expression reads from an ` +
    `external input surface and its bytes flow into the template-source ` +
    `argument of a compile / render / from_string call. Template engines ` +
    `treat that first argument as CODE, not data.`,
  impactScenario: (fact) =>
    `Attacker injects a template-engine expression (e.g. Jinja2 \`{{ ` +
    `self.__init__.__globals__["os"].popen("id").read() }}\`, Handlebars ` +
    `\`{{#with "s" as |string|}}...{{/with}}\`, EJS \`<%= process.exit() ` +
    `%>\`) via the ${fact.sourceCategory} source. The payload propagates ` +
    `through ${fact.path.length} hop(s) to the template compile / render / ` +
    `from_string call, which interprets it as template syntax and evaluates ` +
    `the expression. Result: full RCE on the MCP server host because most ` +
    `template engines grant access to attribute lookup, class traversal, ` +
    `and module import primitives that break out of the sandbox.`,
  threatReference: {
    id: "CWE-1336",
    title: "Server-Side Template Injection (SSTI)",
    url: "https://cwe.mitre.org/data/definitions/1336.html",
    relevance:
      "User-controlled strings passed as templates to Jinja2 / Handlebars / " +
      "EJS / Pug / Nunjucks / Mako enable arbitrary code execution via the " +
      "template engine's expression-evaluation primitives.",
  },
  unmitigatedDetail:
    "No sandbox or template-source validator found on the taint path — the " +
    "user string reaches the template compile / render / from_string call " +
    "as the first argument (the template source), where it is parsed as " +
    "template code and any expression-evaluation primitive is available.",
  mitigatedCharterKnownDetail: (name) =>
    `Safeguard \`${name}\` is on the C13 charter-audited list (Jinja2 ` +
    `SandboxedEnvironment, ImmutableSandboxedEnvironment, or a named ` +
    `project-local validator). Severity drops to informational.`,
  mitigatedCharterUnknownDetail: (name) =>
    `Safeguard \`${name}\` was found on the path but is NOT on the C13 ` +
    `charter list. A reviewer must audit it — template engine sandboxes ` +
    `are notoriously leaky, and autoescape / escapeHtml helpers do NOT ` +
    `mitigate SSTI (they affect runtime variable interpolation, not the ` +
    `template source).`,
};

export class SsTiRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC13(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: TaintFact): RuleResult {
    const builder = buildTaintChain(fact, DESCRIPTOR);

    builder.verification(stepInspectTemplateSource(fact));
    builder.verification(stepInspectTemplateSink(fact));
    builder.verification(stepTraceTemplatePath(fact));
    const sanitiserStep = stepInspectTemplateSanitiser(fact);
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

registerTypedRuleV2(new SsTiRule());
