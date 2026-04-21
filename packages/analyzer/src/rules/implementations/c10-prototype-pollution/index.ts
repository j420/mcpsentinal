/**
 * C10 — Prototype Pollution (Taint-Aware), Rule Standard v2.
 *
 * REPLACES the C10 definition in
 * `packages/analyzer/src/rules/implementations/code-security-deep-detector.ts`.
 *
 * Custom AST walker (not the shared taint-rule-kit) because the sink is
 * a property-write / merge-call pattern rather than a named function
 * call the kit understands. All detection data lives in `./data/config.ts`
 * (under the guard-skipped `data/` directory).
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
  EvidenceChainBuilder,
  type EvidenceChain,
} from "../../../evidence.js";
import type { Location } from "../../location.js";
import { gatherC10, type PollutionHit } from "./gather.js";
import {
  stepInspectPollutionSource,
  stepInspectPollutionSink,
  stepInspectGuard,
  stepConfirmScope,
} from "./verification.js";

const RULE_ID = "C10";
const RULE_NAME = "Prototype Pollution (Taint-Aware)";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Do not merge user-controlled objects into plain objects. Choose one: " +
  "(a) Use Object.create(null) for any target of a merge — its prototype " +
  "is null and cannot be polluted. (b) Use a Map<string, unknown> for " +
  "dynamic-key data instead of a plain object. (c) Validate every key " +
  "against an allowlist before writing: `if (!ALLOWED_KEYS.has(key)) " +
  "throw; target[key] = value;`. (d) If using lodash, upgrade to " +
  ">=4.17.21 AND avoid _.merge with untrusted input — prefer " +
  "Object.assign({}, safeWhitelistedInput) with a manually curated " +
  "subset of keys. (e) Run Node.js with --disallow-prototype-mutation " +
  "(Node 22+) to make this class of bug fail fast.";

const SANITIZED_REMEDIATION =
  "A guard (hasOwnProperty / Object.create(null) target / key allowlist " +
  "function) was observed in scope. Confirm it executes on every " +
  "control-flow path before the merge. An `if (legacy)` branch that " +
  "skips the guard is not adequate mitigation — static analysis cannot " +
  "prove coverage, so the finding remains at informational until a " +
  "reviewer audits the control flow.";

class PrototypePollutionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC10(context);
    if (gathered.mode !== "facts") return [];

    return gathered.hits.map((hit) => this.buildFinding(hit, gathered.file));
  }

  private buildFinding(hit: PollutionHit, file: string): RuleResult {
    const severity: "critical" | "informational" = hit.guardPresent ? "informational" : "critical";
    const fileLocation: Location = { kind: "source", file, line: 1, col: 1 };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: hit.kind === "critical-key" ? "file-content" : "user-parameter",
        location: hit.sourceLocation,
        observed: hit.sourceExpression,
        rationale:
          hit.kind === "critical-key"
            ? `Literal assignment to a critical-key property (${CRITICAL_KEY_LABEL(hit)}). The ` +
              `code itself is the vulnerability: writing any value to this key mutates ` +
              `Object.prototype or the constructor chain for every object in the process.`
            : `Untrusted ${hit.sourceCategory} source — the expression carries attacker-` +
              `controllable keys (for a merge: any __proto__ / constructor / prototype entry ` +
              `flows through the merge; for a dynamic-key write: the key name itself is ` +
              `attacker-controlled).`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: hit.sinkLocation,
        observed: hit.sinkExpression,
        cve_precedent: "CVE-2019-10744",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: hit.guardPresent,
        location: hit.sinkLocation,
        detail: hit.guardPresent
          ? hit.guardDetail
          : "No hasOwnProperty / Object.create(null) / freeze / seal / allowlist guard " +
            "was observed in the enclosing scope. The merge or write has no barrier " +
            "between attacker-controlled keys and Object.prototype.",
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: hit.guardPresent ? "complex" : "moderate",
        scenario:
          `Attacker sends a payload containing a "__proto__" key. When the ` +
          `${sinkKindLabel(hit)} runs, Object.prototype gains an attacker-defined ` +
          `property (e.g. \`shell = "/bin/sh"\`, \`isAdmin = true\`, \`exec = childProcessExec\`). ` +
          `The pollution persists across every subsequent object in the process. Typical ` +
          `cascade: (1) polluted property name matches an option consulted by a later ` +
          `operation (template renderer, child_process, jwt.verify, express middleware); ` +
          `(2) the operation uses the attacker-supplied value; (3) RCE or auth bypass. ` +
          `CVE-2019-10744 (lodash.defaultsDeep) demonstrated this end-to-end.`,
      })
      .factor(
        "tainted_source_proximity",
        hit.kind === "critical-key" ? 0.12 : 0.1,
        hit.kind === "critical-key"
          ? "Literal critical-key write — the code itself is the vulnerability; no source " +
            "proximity reasoning is needed."
          : `Tainted source traced to sink via AST walk. Source category: ${hit.sourceCategory}.`,
      )
      .factor(
        "sink_function_identity",
        0.1,
        `Sink kind "${hit.kind}" — ` +
          (hit.kind === "merge-call"
            ? "a merge API recognised by the C10 charter (lodash._.merge family, " +
              "Object.assign, Object.fromEntries, deepmerge, $.extend)."
            : hit.kind === "critical-key"
              ? "a literal __proto__ / constructor / prototype write (CWE-1321)."
              : "a dynamic-key assignment whose key binding is user-controlled."),
      )
      .factor(
        "hasownproperty_guard_present",
        hit.guardPresent ? -0.3 : 0.05,
        hit.guardPresent
          ? `Guard in scope: ${hit.guardDetail}`
          : "No guard detected — no barrier between attacker keys and Object.prototype.",
      )
      .reference({
        id: "CVE-2019-10744",
        title: "lodash defaultsDeep prototype pollution RCE",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
        relevance:
          "Canonical CVE demonstrating end-to-end exploitation of prototype " +
          "pollution through lodash.defaultsDeep / _.merge in a Node.js " +
          "application. Same sink-class as this finding.",
      })
      .verification(stepInspectPollutionSource(hit))
      .verification(stepInspectPollutionSink(hit))
      .verification(stepInspectGuard(hit, fileLocation))
      .verification(stepConfirmScope(hit));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: hit.guardPresent ? SANITIZED_REMEDIATION : REMEDIATION,
      chain,
    };
  }
}

function CRITICAL_KEY_LABEL(hit: PollutionHit): string {
  const expr = hit.sourceExpression;
  if (expr.includes("__proto__")) return "__proto__";
  if (expr.includes("constructor")) return "constructor";
  if (expr.includes("prototype")) return "prototype";
  return "critical-key";
}

function sinkKindLabel(hit: PollutionHit): string {
  switch (hit.kind) {
    case "merge-call":
      return "merge call";
    case "critical-key":
      return "critical-key assignment";
    case "dynamic-key":
      return "dynamic-key assignment";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C10 charter caps AST-confirmed in-file taint at ${cap}. The 0.08 ` +
      `gap is reserved for runtime controls the static analyser cannot ` +
      `observe (--disallow-prototype-mutation flag, proxy wrappers, ` +
      `library validators, Map-of-Map structures where the top-level key ` +
      `cannot be proven user-controlled).`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new PrototypePollutionRule());

export { PrototypePollutionRule };
