/**
 * K1 — Absent Structured Logging (v2)
 *
 * Orchestrator. Loads the charter's contract from `CHARTER.md` (which is
 * also parsed by the charter-traceability guard) and turns the deterministic
 * facts gathered by `gather.ts` into RuleResult[] with v2-compliant
 * EvidenceChains:
 *
 *   - every link carries a structured Location (not prose);
 *   - every VerificationStep.target is a Location;
 *   - threat_reference cites ISO 27001 A.8.15 (EU AI Act Art.12 / CoSAI MCP-T12
 *     are covered in CHARTER.md threat_refs; the chain selects the most direct
 *     reference for the finding emitted);
 *   - confidence is capped at 0.90 per charter (room for middleware-wrapped
 *     logging the static analyzer cannot see).
 *
 * No regex literals. No string-literal arrays > 5. Detection data lives in
 * ./data/*.json and is loaded at module init.
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
  gatherK1,
  type ConsoleCallSite,
  type DisableLoggingSite,
  type FileEvidence,
  type HandlerSite,
  type K1Gathered,
} from "./gather.js";
import {
  stepCheckDependency,
  stepCheckLoggerImport,
  stepInspectConsoleCall,
  stepInspectHandler,
  stepInspectSuppression,
} from "./verification.js";

const RULE_ID = "K1";
const RULE_NAME = "Absent Structured Logging";
const OWASP = "MCP09-logging-monitoring" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Replace console.log/warn/error in request and tool handlers with a structured " +
  "logging library (pino, winston, bunyan, tslog, structlog, loguru). The logger " +
  "must emit JSON per record, carry a correlation id, and be retained per ISO 27001 " +
  "A.8.15. Example: `const logger = pino(); app.post('/tool', (req, res) => { " +
  "logger.info({ requestId: req.id, tool: req.body.tool }, 'handling tool call'); });`. " +
  "If a structured logger is already imported, wire it into the flagged handler.";

class AbsentStructuredLoggingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK1(context);
    if (gathered.perFile.length === 0) return [];

    const findings: RuleResult[] = [];

    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      findings.push(...this.findConsoleInHandlerFindings(file, gathered));
      findings.push(...this.findSuppressionFindings(file, gathered));
    }

    return findings;
  }

  // ─── Finding A: console call inside a handler without structured logger use ─

  private findConsoleInHandlerFindings(file: FileEvidence, g: K1Gathered): RuleResult[] {
    const out: RuleResult[] = [];

    for (const handler of file.handlers) {
      // Only flag handlers whose scope contains console calls AND which do NOT
      // already use a structured logger binding (alias-resolved in gather.ts).
      const consoleCalls = file.consoleCalls.filter(
        (c) => c.enclosingHandler === handler,
      );
      if (consoleCalls.length === 0) continue;
      if (file.handlersUsingLogger.has(handler)) continue;

      out.push(this.buildHandlerFinding(file, handler, consoleCalls, g));
    }

    return out;
  }

  private buildHandlerFinding(
    file: FileEvidence,
    handler: HandlerSite,
    consoleCalls: ConsoleCallSite[],
    g: K1Gathered,
  ): RuleResult {
    const primaryCall = consoleCalls[0];
    const handlerLocation = handler.location as Location;
    const fileLocation: Location = { kind: "source", file: file.file, line: 1, col: 1 };

    const importPresentInThisFile = file.loggerImports.length > 0;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: primaryCall.location,
        observed: primaryCall.observed,
        rationale:
          `${consoleCalls.length === 1 ? "A" : `${consoleCalls.length}`} unstructured ` +
          `console.${primaryCall.method}(...) call(s) inside the request handler ` +
          `${handler.label}. Unstructured logging provides no correlation id, no ` +
          `machine-parseable fields, and no retention guarantee — failing ISO 27001 ` +
          `A.8.15 and EU AI Act Art.12 requirements for audit evidence.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: handlerLocation,
        observed:
          `The handler ${handler.label} (lines ${handler.startLine}–${handler.endLine}) ` +
          `processes externally-arriving events; every console call inside its scope ` +
          `represents a missing audit record for an action of the agent.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: handlerLocation,
        observed:
          `Audit gap materialises at the handler boundary: logs produced by ` +
          `console.${primaryCall.method}(...) cannot be correlated, searched, ` +
          `or forwarded to a SIEM/retention store.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: importPresentInThisFile,
        location: fileLocation,
        detail: importPresentInThisFile
          ? `A structured logger IS imported in ${file.file} but is not used by this ` +
            `handler — partial migration gap.`
          : `No structured logger imported in ${file.file}.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          `Security events raised by ${handler.label} — authentication failures, ` +
          `tool invocation attempts, authorization outcomes — are emitted as plain ` +
          `text without a correlation id or timestamp schema. During incident response ` +
          `these events cannot be tied to the caller or to downstream services, which ` +
          `regulators (ISO 27001:2022 A.8.15, EU AI Act Art.12) will flag as an ` +
          `inadequate audit trail.`,
      })
      .factor(
        "ast_handler_scope",
        0.1,
        `Confirmed via AST: console.${primaryCall.method}(...) is inside the scope ` +
          `of ${handler.label} (lines ${handler.startLine}–${handler.endLine}), not ` +
          `a utility function.`,
      )
      .factor(
        "console_call_count",
        consoleCalls.length > 2 ? 0.05 : 0.02,
        `${consoleCalls.length} console call(s) observed in this handler — ` +
          (consoleCalls.length > 2
            ? "multiple unstructured calls indicate a systematic logging gap."
            : "single call may be a one-off that should still carry structure."),
      )
      .factor(
        importPresentInThisFile ? "logger_import_present_but_unused" : "no_logger_import",
        importPresentInThisFile ? -0.15 : 0.08,
        importPresentInThisFile
          ? `Logger import at ${renderLocations(file.loggerImports.map((i) => i.location))} ` +
            `exists but is not used in the flagged handler — the finding is a ` +
            `partial-migration gap, not a total absence.`
          : `No structured logger imported in ${file.file}.`,
      )
      .factor(
        g.dependencyHasLogger ? "logger_dependency_present" : "no_logger_dependency",
        g.dependencyHasLogger ? -0.1 : 0.05,
        g.dependencyHasLogger
          ? `A structured logger appears in project dependencies — the library is ` +
            `available, suggesting the handler gap is an oversight rather than a ` +
            `systemic absence.`
          : `No structured logger in project dependencies — the gap is project-wide.`,
      )
      .reference({
        id: "ISO-27001-A.8.15",
        title: "ISO/IEC 27001:2022 Annex A Control 8.15 — Logging",
        url: "https://www.iso.org/standard/82875.html",
        relevance:
          "A.8.15 requires event logs for activities, exceptions, faults, and " +
          "information security events — produced, stored, protected, and analysed. " +
          "console.log meets none of the four requirements.",
      })
      .verification(stepInspectHandler(handler));

    for (const call of consoleCalls) {
      builder.verification(stepInspectConsoleCall(call, handler));
    }
    builder
      .verification(stepCheckLoggerImport(fileLocation as Location & { kind: "source" }, importPresentInThisFile))
      .verification(stepCheckDependency(g.dependencyHasLogger, g.dependencyLocation));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  // ─── Finding B: explicit audit suppression ─────────────────────────────────

  private findSuppressionFindings(file: FileEvidence, g: K1Gathered): RuleResult[] {
    return file.disableSites.map((site) => this.buildSuppressionFinding(file, site, g));
  }

  private buildSuppressionFinding(
    _file: FileEvidence,
    site: DisableLoggingSite,
    g: K1Gathered,
  ): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          site.variant === "logging.disable"
            ? `logging.disable(...) disables the logging framework for the entire ` +
              `process. This is a deliberate audit trail destruction, not an oversight.`
            : `logger.silent = true / logger.level = "silent" disables the configured ` +
              `logger. This is a deliberate audit trail destruction.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed:
          `All subsequent logging calls (including security events) are suppressed ` +
          `from this point on.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          "With logging suppressed, authentication failures, authorisation rejections, " +
          "tool-call errors, and deserialisation failures are silently dropped. " +
          "Incident responders cannot reconstruct the sequence of events. ISO 27001 " +
          "A.8.15 and EU AI Act Art.12 compliance becomes impossible on the record-" +
          "keeping dimension.",
      })
      .factor(
        "explicit_disable",
        0.18,
        "Logging suppression is an explicit, deliberate choice, not a logging gap.",
      )
      .factor(
        g.dependencyHasLogger ? "logger_dependency_present" : "no_logger_dependency",
        g.dependencyHasLogger ? -0.05 : 0.03,
        g.dependencyHasLogger
          ? "A structured logger is installed — suppression is still a violation."
          : "No structured logger in dependencies — compounding the suppression gap.",
      )
      .reference({
        id: "ISO-27001-A.8.15",
        title: "ISO/IEC 27001:2022 Annex A Control 8.15 — Logging",
        url: "https://www.iso.org/standard/82875.html",
        relevance:
          "Explicit suppression of logging directly violates A.8.15's requirement for " +
          "logs to be produced, stored, protected, and analysed.",
      })
      .verification(stepInspectSuppression(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Confidence capping ────────────────────────────────────────────────────

/**
 * Clamp `chain.confidence` to `cap`, recording the reason in
 * `confidence_factors` so the cap is auditable (not a magic number).
 * Mutates the chain — the builder's output is owned by the rule.
 */
function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K1 charter caps confidence at ${cap} — middleware-wrapped logging ` +
      `(e.g. morgan → syslog) is not observable at source-file scope, ` +
      `so a maximum-confidence claim would overstate the evidence.`,
  });
  chain.confidence = cap;
  return chain;
}

function renderLocations(locs: Location[]): string {
  if (locs.length === 0) return "<none>";
  if (locs.length === 1) return render(locs[0]);
  const first = render(locs[0]);
  return `${first} (+${locs.length - 1} more)`;
}

function render(loc: Location): string {
  return loc.kind === "source"
    ? `${loc.file}:${loc.line}${loc.col !== undefined ? `:${loc.col}` : ""}`
    : loc.kind;
}

registerTypedRuleV2(new AbsentStructuredLoggingRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { AbsentStructuredLoggingRule };
