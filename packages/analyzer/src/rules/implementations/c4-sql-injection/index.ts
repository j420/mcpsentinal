/**
 * C4 — SQL Injection (Taint-Aware), Rule Standard v2.
 *
 * REPLACES the C4 definition in
 * `packages/analyzer/src/rules/implementations/tainted-execution-detector.ts`.
 *
 * Orchestrator. Loads the charter's contract from `CHARTER.md` and turns
 * the deterministic facts gathered via the shared taint-rule-kit into
 * RuleResult[] with v2-compliant EvidenceChains:
 *
 *   - every link carries a structured Location (not prose);
 *   - every VerificationStep.target is a Location produced in verification.ts;
 *   - AST-confirmed unsanitised flows are critical;
 *   - sanitised flows drop to informational per CHARTER edge case on
 *     sanitiser-identity bypass (the sanitiser is still visible to a
 *     reviewer via the dedicated verification step);
 *   - lightweight-taint findings stay at critical too because a real
 *     source→sink edge was observed, but carry a smaller positive factor
 *     (0.05 vs 0.15 for AST) so scorers can distinguish them;
 *   - confidence is capped at 0.92 per CHARTER — the 0.08 gap is reserved
 *     for ORM wrappers, tagged-template parameterisers, and second-order
 *     flows the static analyser cannot observe.
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
import { gatherC4 } from "./gather.js";
import {
  stepInspectSqlSource,
  stepInspectSqlSink,
  stepTraceSqlPath,
  stepInspectSqlSanitiser,
} from "./verification.js";

// ─── Charter-controlled constants ────────────────────────────────────────

const RULE_ID = "C4";
const RULE_NAME = "SQL Injection (Taint-Aware)";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.92;

const REMEDIATION =
  "Use parameterised queries or prepared statements exclusively: pass user " +
  "data as bound parameters ($1, $2, ? placeholders, or the driver-native " +
  "named-parameter form). Never concatenate user input into a SQL string or " +
  "substitute it into a template literal passed to .query() / .execute() / " +
  ".raw() / cursor.execute(). Use an ORM (Prisma, Drizzle, Kysely, SQLAlchemy) " +
  "or a query-builder (Knex) that parameterises by default. When a raw query " +
  "is unavoidable, use only tagged-template APIs whose tag function is known " +
  "to parameterise (prisma.$queryRaw, not prisma.$queryRawUnsafe). For " +
  "identifier interpolation (table / column names), validate against a " +
  "hand-maintained allowlist — parameterisation cannot protect identifiers.";

const SANITIZED_REMEDIATION =
  "A sanitiser was detected on the taint path; nonetheless, prefer parameterised " +
  "queries. Audit the sanitiser's body to confirm it actually parameterises / " +
  "validates (Number / parseInt are weak — they only handle numeric columns " +
  "and fail open on string columns). See CHARTER edge case 2 — numeric-coercion " +
  "weak sanitiser.";

// ─── Descriptor for the shared evidence-chain builder ────────────────────

const DESCRIPTOR: TaintChainDescriptor = {
  ruleId: RULE_ID,
  sourceType: "user-parameter",
  sinkType: "sql-execution",
  cvePrecedent: "CWE-89",
  impactType: "data-exfiltration",
  impactScope: "connected-services",
  sourceRationale: (fact) =>
    `Untrusted ${fact.sourceCategory} source — the expression reads from an ` +
    `external input surface (HTTP body/query/params, MCP tool parameter, ` +
    `process.env, process.argv) and therefore carries attacker-controlled ` +
    `content until a parameteriser / validator proves otherwise.`,
  impactScenario: (fact) =>
    `Attacker crafts a SQL injection payload (e.g. \`' OR 1=1 --\` or a UNION ` +
    `extracting column metadata) in the ${fact.sourceCategory} source. The ` +
    `payload propagates through ${fact.path.length} hop(s) to the .query / ` +
    `.execute / .raw sink, where it is concatenated or interpolated into the ` +
    `SQL string that the database engine receives. Result: data exfiltration ` +
    `(SELECT … from tables the app never exposes), authentication bypass, ` +
    `INSERT/UPDATE tampering, or — on engines with FFI like PostgreSQL ` +
    `COPY TO PROGRAM — out-of-band command execution. Exploitability is ` +
    `${fact.path.length === 0 ? "trivial" : "moderate"} because ${fact.path.length === 0 ? "the source is the sink's first argument on the same call" : "the flow requires the attacker to trace the assignment chain"}.`,
  threatReference: {
    id: "CWE-89",
    title: "SQL Injection via untrusted input in query construction",
    url: "https://cwe.mitre.org/data/definitions/89.html",
    relevance:
      "User-controlled input concatenated into SQL queries enables data " +
      "exfiltration, authentication bypass, and — on engines supporting " +
      "in-query command execution — remote code execution.",
  },
  unmitigatedDetail:
    "No parameteriser or validator found on the taint path between source " +
    "and sink — the source value reaches the .query / .execute / .raw " +
    "call unquoted, so every SQL metacharacter in the value survives as " +
    "SQL syntax.",
  mitigatedCharterKnownDetail: (name) =>
    `Sanitiser \`${name}\` is on the C4 charter-audited list of SQL-safe ` +
    `transforms (parameterise / prepare / validator / numeric coercion). ` +
    `Severity drops to informational but the finding remains in the ` +
    `evidence trail so a reviewer can confirm the sanitiser is in force.`,
  mitigatedCharterUnknownDetail: (name) =>
    `Sanitiser \`${name}\` was found on the taint path but is NOT on the ` +
    `C4 charter list. A reviewer must audit its body to confirm it ` +
    `parameterises or escapes SQL metacharacters (CHARTER edge case: ` +
    `sanitiser-identity bypass).`,
};

// ─── Rule class ──────────────────────────────────────────────────────────

export class SqlInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC4(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: TaintFact): RuleResult {
    const builder = buildTaintChain(fact, DESCRIPTOR);

    builder.verification(stepInspectSqlSource(fact));
    builder.verification(stepInspectSqlSink(fact));
    builder.verification(stepTraceSqlPath(fact));
    const sanitiserStep = stepInspectSqlSanitiser(fact);
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

registerTypedRuleV2(new SqlInjectionRule());
