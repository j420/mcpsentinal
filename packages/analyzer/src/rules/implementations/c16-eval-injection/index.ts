/**
 * C16 — Dynamic Code Evaluation with User Input (Taint-Aware), v2.
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
import type { SinkLink } from "../../../evidence.js";
import { gatherC16 } from "./gather.js";
import {
  stepInspectEvalSource,
  stepInspectEvalSink,
  stepTraceEvalPath,
  stepInspectEvalSanitiser,
} from "./verification.js";

const RULE_ID = "C16";
const RULE_NAME = "Dynamic Code Evaluation with User Input (Taint-Aware)";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Remove eval() / new Function() / setTimeout-with-string / vm.runInNewContext " +
  "/ __import__ / importlib.import_module calls that receive user input. Use " +
  "JSON.parse() for data deserialisation, a proper expression parser " +
  "(math.js, expr-eval, jsep + an AST walker) for math expressions, or map " +
  "a user-supplied KEY to a hardcoded handler (switch / lookup table) rather " +
  "than evaluating the user-supplied code. For Python: ast.literal_eval() " +
  "parses literal primitives (int, float, str, list, dict, tuple, bool, None) " +
  "without executing code. If code execution really is the feature (code " +
  "sandbox, REPL), run the evaluator inside a proper isolate (isolated-vm, " +
  "Node Worker with --experimental-permission and no require access, or a " +
  "separate container with no network, filesystem, or process privileges).";

const SANITIZED_REMEDIATION =
  "A parser or validator was detected on the taint path; nonetheless, confirm " +
  "the binding really resolves to a data parser (JSON.parse, ast.literal_eval, " +
  "a charter-audited allowlist check) rather than a generic validator that " +
  "lets the string through unchanged. CHARTER edge case: a function named " +
  "'validate' that only checks length does not sanitise the contents.";

const DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "user-parameter",
  sinkType: "code-evaluation" as SinkLink["sink_type"],
  cvePrecedent: "CWE-95",
  impactType: "remote-code-execution",
  impactScope: "server-host",
  sourceRationale: (fact) =>
    `Untrusted ${fact.sourceCategory} source — the expression reads from an ` +
    `external input surface and its bytes reach an eval-family call. The ` +
    `eval family interprets its argument as CODE (JavaScript expression, ` +
    `Python module name, VM script), not as data.`,
  impactScenario: (fact) =>
    `Attacker places arbitrary JavaScript (\`require('child_process').` +
    `execSync('id')\`), a Python module name that fetches and executes code ` +
    `during import, or a VM script that escapes the context, in the ` +
    `${fact.sourceCategory} source. The payload propagates through ` +
    `${fact.path.length} hop(s) to the eval / Function / setTimeout-string ` +
    `/ vm.run / __import__ sink and executes on the MCP server host with ` +
    `the server process's full privileges — no sandbox, no quoting, no ` +
    `syntactic boundary to protect.`,
  threatReference: {
    id: "CWE-95",
    title: "Eval Injection — Dynamic Code Evaluation with User Input",
    url: "https://cwe.mitre.org/data/definitions/95.html",
    relevance:
      "User input reaching eval / new Function / setTimeout(string) / " +
      "vm.run* / importlib.import_module / __import__ enables arbitrary " +
      "code execution with the server process's privileges.",
  },
  unmitigatedDetail:
    "No parser or allowlist validator found on the taint path — the user " +
    "string reaches the eval-family call unchanged, so its bytes are " +
    "interpreted as CODE and executed on the MCP server host.",
  mitigatedCharterKnownDetail: (name) =>
    `Parser \`${name}\` is on the C16 charter-audited list (JSON.parse, ` +
    `ast.literal_eval, parseInt/parseFloat/Number for numerics). Severity ` +
    `drops to informational but the finding remains for reviewer audit.`,
  mitigatedCharterUnknownDetail: (name) =>
    `A validator named \`${name}\` was found on the path but is NOT on the ` +
    `C16 charter list. A reviewer must audit its body — a function named ` +
    `"validate" that only checks length or membership does NOT sanitise ` +
    `the contents against eval execution.`,
};

export class DynamicCodeEvalRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC16(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: TaintFact): RuleResult {
    const builder = buildTaintChain(fact, DESCRIPTOR);

    builder.verification(stepInspectEvalSource(fact));
    builder.verification(stepInspectEvalSink(fact));
    builder.verification(stepTraceEvalPath(fact));
    const sanitiserStep = stepInspectEvalSanitiser(fact);
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

registerTypedRuleV2(new DynamicCodeEvalRule());
