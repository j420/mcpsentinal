/**
 * K20 — Insufficient Audit Context in Logging (v2)
 *
 * Orchestrator. Translates the deterministic facts produced by
 * `gather.ts` into RuleResult[] with v2-compliant EvidenceChains:
 *
 *   - every link carries a structured Location (not prose);
 *   - every VerificationStep.target is a Location;
 *   - threat_reference cites ISO 27001 A.8.15 (primary) with
 *     ISO 42001 A.8.1 and MAESTRO L5 as supporting references in
 *     the CHARTER frontmatter;
 *   - confidence is capped at 0.85 per charter (bindings, mixins,
 *     winston formats, and AsyncLocalStorage contexts can all inject
 *     fields invisibly at emission time).
 *
 * No regex literals, no string-arrays > 5.
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
import type { Location } from "../../location.js";
import {
  classifyCallAdequacy,
  gatherK20,
  missingGroups,
  type FileEvidence,
  type LoggerCallSite,
} from "./gather.js";
import {
  stepCheckLoggerImport,
  stepInspectBindings,
  stepInspectCall,
  stepInspectMixinFormat,
  stepRemediationPreview,
} from "./verification.js";

const RULE_ID = "K20";
const RULE_NAME = "Insufficient Audit Context in Logging";
const OWASP = "MCP09-logging-monitoring" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.85;
const MAX_FINDINGS_PER_SCAN = 10;

const REMEDIATION =
  "Replace bare-string or empty-object log calls in handlers and tool paths with " +
  "structured records that carry ALL five ISO 27001 A.8.15 audit groups: " +
  "(1) correlation — correlation_id / request_id / trace_id; " +
  "(2) caller identity — user_id / session_id / agent_id; " +
  "(3) tool — tool / tool_name / action / operation; " +
  "(4) timestamp — timestamp / ts; " +
  "(5) outcome — outcome / status / result. " +
  "Example: `logger.info({ correlation_id, user_id, tool, outcome, timestamp }, 'handled tool call')`. " +
  "Use pino's logger.child({ correlation_id }) pattern or AsyncLocalStorage to " +
  "propagate the correlation id automatically; attach caller identity from the " +
  "authenticated principal; attach the tool/operation from the handler name; " +
  "attach the outcome from the success/failure branch of the handler.";

const REF_ISO_27001_A_8_15 = {
  id: "ISO-27001-A.8.15",
  title: "ISO/IEC 27001:2022 Annex A Control 8.15 — Logging",
  url: "https://www.iso.org/standard/82875.html",
  relevance:
    "A.8.15 requires event logs to be produced, stored, PROTECTED, and ANALYSED. " +
    "Analysis presumes correlation across services (correlation id), attribution " +
    "to a caller (user/session id), and reconstruction of operations (tool name, " +
    "timestamp, outcome). A call that emits a bare-string record carries none of " +
    "these — the record is stored but cannot be analysed.",
} as const;

class K20InsufficientAuditContextRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK20(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const site of file.calls) {
        if (!this.shouldConsider(site, file)) continue;
        const adequacy = classifyCallAdequacy(site);
        if (adequacy !== "insufficient") continue;
        findings.push(this.buildFinding(site, file));
        if (findings.length >= MAX_FINDINGS_PER_SCAN) return findings;
      }
    }
    return findings;
  }

  /**
   * Scope filter — when a structured logger is imported in the file,
   * defer bare console.* calls to K1 (architectural gap). Structured-
   * logger calls are always K20's concern regardless.
   */
  private shouldConsider(site: LoggerCallSite, file: FileEvidence): boolean {
    if (site.receiverShape === "console" && file.importedLoggerPackages.size > 0) {
      return false;
    }
    return true;
  }

  private buildFinding(site: LoggerCallSite, file: FileEvidence): RuleResult {
    const fileLocation: Location = {
      kind: "source",
      file: site.file,
      line: 1,
      col: 1,
    };
    const missing = missingGroups(site);
    const observedList = Array.from(site.observedAliases).sort();
    const observedLabel =
      observedList.length > 0 ? observedList.join(", ") : "<none>";
    const importPresent = file.importedLoggerPackages.size > 0;
    const mixinPresent = file.mixinFormatSites.length > 0;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `Log call \`${site.receiverLabel}.${site.method}(...)\` emits a record with ` +
          `${site.observedAliases.size} recognised audit-field aliases (observed: ` +
          `${observedLabel}). The ISO 27001 A.8.15 audit skeleton requires correlation, ` +
          `caller identity, tool/operation, timestamp, and outcome; groups currently ` +
          `missing from this call: ${missing.length > 0 ? missing.join(", ") : "none"}. ` +
          `A record this thin cannot be correlated across services nor attributed to a ` +
          `specific agent action.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed:
          `Audit gap materialises at the log call: the runtime record will carry ` +
          `${site.isStringOnly ? "only a bare string message" : "an object-literal with <2 recognised aliases"}, ` +
          `failing the A.8.15 "analyse" requirement for cross-service correlation.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: importPresent,
        location: fileLocation,
        detail: importPresent
          ? `A structured logger package is imported in this file — the library is ` +
            `available, so the call is a partial-adoption gap rather than a total ` +
            `absence of audit capability.`
          : `No structured logger package imported in this file — the audit capability ` +
            `is absent at the module level. K1 additionally covers this architectural ` +
            `gap; K20 names the per-call completeness gap.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "connected-services",
        exploitability: "complex",
        scenario:
          `During incident response, the log record produced by this call is opened ` +
          `without a correlation id (so it cannot be joined to telemetry from other ` +
          `services), without a caller identity (so the action cannot be attributed), ` +
          `${site.observedAliases.size === 0 ? "and without any structured fields at all" : `and with only ${observedLabel}`}. ` +
          `ISO 27001:2022 A.8.15 and ISO 42001 A.8.1 auditors will flag this as an ` +
          `incomplete audit trail; Mandiant M-Trends 2024 attributes 23% of prolonged ` +
          `breach dwell time to exactly this class of log-field incompleteness.`,
      });

    builder
      .factor(
        "audit_fields_observed_count",
        site.observedAliases.size === 0 ? 0.12 : 0.06,
        `${site.observedAliases.size} recognised audit-field alias(es) observed ` +
          `across call arguments and bindings (threshold: 2).`,
      )
      .factor(
        importPresent ? "structured_logger_in_file" : "no_structured_logger_in_file",
        importPresent ? -0.1 : 0.05,
        importPresent
          ? `A structured logger package is imported in this file (${[...file.importedLoggerPackages].join(", ")}) — ` +
            `the call is a partial-adoption gap.`
          : `No structured logger package imported in this file — the gap is ` +
            `module-wide.`,
      )
      .factor(
        `call_receiver_shape_${site.receiverShape.split("-").join("_")}`,
        site.receiverShape === "child-chain" ? -0.05 : 0.02,
        `Receiver classified as \`${site.receiverShape}\` (\`${site.receiverLabel}\`).`,
      );

    if (mixinPresent) {
      builder.factor(
        "mixin_or_format_in_scope",
        -0.1,
        `A pino mixin or winston format transformer is observed in scope — fields may ` +
          `be added to the emitted record at runtime that are invisible at this call site.`,
      );
    }
    if (site.bindingsSites.length > 0) {
      const totalBindingsAliases = site.bindingsSites.reduce(
        (n, b) => n + b.observedAliases.length,
        0,
      );
      builder.factor(
        "bindings_chain_observed",
        totalBindingsAliases > 0 ? -0.05 : 0.02,
        `${site.bindingsSites.length} bindings call(s) observed on the receiver chain ` +
          `contributing ${totalBindingsAliases} alias(es).`,
      );
    }

    builder.reference(REF_ISO_27001_A_8_15);

    // Verification step sequence — one per observable site plus the
    // remediation preview. The first step targets the call's source
    // Location; the last step targets the same Location (closing the
    // loop per v2 contract §4).
    builder.verification(stepInspectCall(site));
    for (const b of site.bindingsSites) {
      builder.verification(stepInspectBindings(b));
    }
    for (const mix of file.mixinFormatSites) {
      builder.verification(stepInspectMixinFormat(mix));
    }
    builder.verification(
      stepCheckLoggerImport(fileLocation as Location & { kind: "source" }, importPresent),
    );
    builder.verification(stepRemediationPreview(site, missing));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "medium",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Confidence capping ────────────────────────────────────────────────────

/**
 * Clamp `chain.confidence` to `cap`, recording the cap as an auditable
 * factor (not a magic number).
 */
function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K20 charter caps confidence at ${cap} — bindings (pino.child), mixins ` +
      `(pino({ mixin })), format transformers (winston.format.combine), and ` +
      `AsyncLocalStorage contexts can all inject fields invisibly at emission ` +
      `time. A maximum-confidence claim would overstate the static evidence.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new K20InsufficientAuditContextRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { K20InsufficientAuditContextRule };
