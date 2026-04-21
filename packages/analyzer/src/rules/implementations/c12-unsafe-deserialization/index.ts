/**
 * C12 — Unsafe Deserialization (Taint-Aware), Rule Standard v2.
 *
 * REPLACES the C12 definition in
 * `packages/analyzer/src/rules/implementations/tainted-execution-detector.ts`.
 *
 * No regex literals. No string-literal arrays > 5. All data lives in
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
import { gatherC12 } from "./gather.js";
import {
  stepInspectDeserSource,
  stepInspectDeserSink,
  stepTraceDeserPath,
  stepInspectDeserSanitiser,
} from "./verification.js";

const RULE_ID = "C12";
const RULE_NAME = "Unsafe Deserialization (Taint-Aware)";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Never deserialise untrusted data with pickle, yaml.load, node-serialize, " +
  "marshal, ObjectInputStream, or PHP unserialize. Use safe alternatives: " +
  "json.loads (Python) or JSON.parse (JS) for JSON, yaml.safe_load / " +
  "SafeLoader for YAML, ast.literal_eval for Python literals, msgpack / cbor " +
  "for typed binary data. If the payload truly needs complex object " +
  "serialisation, define an explicit schema (Zod, Pydantic, protobuf) and " +
  "validate the input BEFORE reconstructing objects. Reject any class-name " +
  "field in the payload; never look up classes from user-controlled names.";

const SANITIZED_REMEDIATION =
  "A safe deserialiser was detected on the taint path; nonetheless, confirm " +
  "the binding really resolves to the charter-audited function (yaml.safe_load, " +
  "JSON.parse, ast.literal_eval) rather than a shadowed or locally-defined " +
  "identifier. See CHARTER edge case 5 — custom wrappers named like a safe API " +
  "can still call the unsafe variant internally.";

const DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "user-parameter",
  sinkType: "deserialization",
  cvePrecedent: "CVE-2017-5941",
  impactType: "remote-code-execution",
  impactScope: "server-host",
  sourceRationale: (fact) =>
    `Untrusted ${fact.sourceCategory} source — the expression reads from an ` +
    `external input surface whose bytes may encode a deserialisation payload ` +
    `(pickle header, YAML with !!python/object, node-serialize IIFE, PHP ` +
    `O-tag serialisation). Nothing on the path strips these primitives.`,
  impactScenario: (fact) =>
    `Attacker crafts a deserialisation payload — a pickle with a __reduce__ ` +
    `returning (os.system, (cmd,)), a YAML document with !!python/object/apply, ` +
    `a node-serialize IIFE, or an ObjectInputStream object with a malicious ` +
    `readObject — and places it in the ${fact.sourceCategory} source. The ` +
    `payload propagates through ${fact.path.length} hop(s) to the ` +
    `deserialiser, which constructs the object AND executes the embedded ` +
    `code during reconstruction. Result: full RCE on the MCP server host ` +
    `with the server process's privileges — exactly the class of attack ` +
    `CVE-2017-5941 demonstrated in the wild against node-serialize.`,
  threatReference: {
    id: "CVE-2017-5941",
    title: "node-serialize arbitrary code execution via untrusted deserialisation",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2017-5941",
    relevance:
      "Canonical deserialisation → eval CVE. Same class as pickle.loads / " +
      "yaml.load / PHP unserialize / ObjectInputStream.readObject on " +
      "attacker-controlled input.",
  },
  unmitigatedDetail:
    "No safe-deserialiser call found on the taint path between source and " +
    "sink — the bytes reach pickle.loads / yaml.load / node-serialize / " +
    "marshal / ObjectInputStream unfiltered, so any embedded object-" +
    "construction code executes on the server host.",
  mitigatedCharterKnownDetail: (name) =>
    `Sanitiser \`${name}\` is on the C12 charter-audited list of safe ` +
    `deserialisers (json.loads, yaml.safe_load, ast.literal_eval, msgpack). ` +
    `Severity drops to informational but the finding remains so a reviewer ` +
    `can verify the binding is in force (CHARTER edge case 5).`,
  mitigatedCharterUnknownDetail: (name) =>
    `A deserialiser call named \`${name}\` was found on the path but is NOT ` +
    `on the C12 charter list. A reviewer must audit the function body — the ` +
    `name alone does not prove the payload is parsed without executing ` +
    `embedded code (CHARTER edge case on sanitiser-identity bypass).`,
};

export class UnsafeDeserializationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC12(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: TaintFact): RuleResult {
    const builder = buildTaintChain(fact, DESCRIPTOR);

    builder.verification(stepInspectDeserSource(fact));
    builder.verification(stepInspectDeserSink(fact));
    builder.verification(stepTraceDeserPath(fact));
    const sanitiserStep = stepInspectDeserSanitiser(fact);
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

registerTypedRuleV2(new UnsafeDeserializationRule());
