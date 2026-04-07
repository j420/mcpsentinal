/**
 * K1 — Absent Structured Logging (v2: AST Structural Analysis)
 *
 * REPLACES the regex rule: /console\.log.*request/ in compliance-remaining-detector.ts
 *
 * Old behavior: Fires on any `console.log("request...")` anywhere in source code.
 *   False positive: console.log("requesting user input") in a utility function.
 *   False negative: console.warn(req.url) in a handler (no "request" keyword).
 *
 * New behavior: Uses TypeScript compiler API to:
 *   1. Find request handler functions (app.get, router.post, server.on, etc.)
 *   2. Check if console.log/warn/error is called INSIDE those handlers
 *   3. Cross-check: is a structured logger imported ANYWHERE in the file?
 *   4. Cross-check: is a structured logging library in the dependency list?
 *   5. Confidence adjusts based on how many independent signals confirm the finding
 *
 * Why this matters for compliance:
 *   - ISO 27001 A.8.15: Requires structured audit logging
 *   - EU AI Act Art. 12: Requires record-keeping of AI system operations
 *   - MAESTRO L5: Requires observable, searchable log streams
 *   - CoSAI MCP-T12: Requires correlation IDs for incident response
 *   console.log provides none of these — no structured fields, no correlation,
 *   no searchability, no SIEM integration.
 *
 * Detection pipeline:
 *   Phase 1: AST structural analysis (TypeScript compiler API)
 *   Phase 2: Cross-module dependency check (structured logger in deps?)
 *   Phase 3: Confidence calibration from independent signals
 *
 * Confidence model:
 *   - Console in handler + no logger import + no logger dep: 0.85-0.90
 *   - Console in handler + no logger import + logger dep exists: 0.60-0.70
 *   - Console in handler + logger import exists but unused in handler: 0.55-0.65
 *   - logging.disable() detected: 0.88 (explicit audit suppression)
 */

import ts from "typescript";
import type { AnalysisContext } from "../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../base.js";
import { EvidenceChainBuilder } from "../../evidence.js";

const RULE_ID = "K1";
const RULE_NAME = "Absent Structured Logging";
const OWASP = "MCP09-logging-monitoring";
const REMEDIATION =
  "Replace console.log/warn/error in request handlers with a structured logging library " +
  "(pino, winston, bunyan, tslog). Structured loggers provide: correlation IDs for tracing " +
  "requests across services, machine-parseable JSON output for SIEM integration, log levels " +
  "for filtering, and child loggers for per-request context. " +
  "Example: `const logger = pino(); app.get('/path', (req, res) => { logger.info({ requestId: req.id }, 'handling request'); });`";

/** Structured logging libraries — if any of these are imported, the file has a logger */
const STRUCTURED_LOGGERS = [
  "pino", "winston", "bunyan", "log4js", "tslog", "loglevel",
  "signale", "consola", "roarr", "bristol",
];

/** Package names of structured logging libraries — checked against dependency list */
const STRUCTURED_LOGGER_PACKAGES = new Set([
  "pino", "winston", "bunyan", "log4js", "tslog", "loglevel",
  "signale", "consola", "roarr", "bristol",
  // Pino ecosystem
  "pino-pretty", "pino-http", "pino-multi-stream",
  // Winston ecosystem
  "winston-daily-rotate-file", "winston-transport",
]);

/** Patterns that identify request handler registration */
const HANDLER_PATTERNS = [
  // Express: app.get/post/put/delete/patch/all/use
  /\b(?:app|router|server)\s*\.\s*(?:get|post|put|delete|patch|all|use|options|head)\s*\(/,
  // Koa: app.use(async (ctx) => ...)
  /\bapp\s*\.\s*use\s*\(\s*(?:async\s+)?\(?(?:ctx|context)\b/,
  // Fastify: fastify.get/post/route
  /\b(?:fastify|server)\s*\.\s*(?:get|post|put|delete|patch|route)\s*\(/,
  // HTTP module: server.on('request', ...)
  /\bserver\s*\.\s*on\s*\(\s*['"]request['"]/,
  // Next.js: export default handler / export async function GET
  /export\s+(?:default\s+)?(?:async\s+)?function\s+(?:handler|GET|POST|PUT|DELETE|PATCH)\b/,
  // Hono: app.get/post
  /\bapp\s*\.\s*(?:get|post|put|delete|patch)\s*\(/,
  // MCP tool handler: server.setRequestHandler / server.tool
  /\b(?:server|app)\s*\.\s*(?:setRequestHandler|tool)\s*\(/,
];

interface HandlerInfo {
  name: string;
  startLine: number;
  endLine: number;
  startPos: number;
  endPos: number;
}

interface ConsoleCallInfo {
  method: string; // "log", "warn", "error"
  line: number;
  text: string;   // the full console.xxx(...) text
}

class AbsentStructuredLoggingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];

    const source = context.source_code;

    // Skip test files — they're allowed to use console.log
    if (/(?:__tests?__|\.(?:test|spec)\.)/.test(source)) return [];

    const findings: RuleResult[] = [];

    // ── Phase 1: Detect logging.disable() — explicit audit suppression ──
    // This is the most severe variant: someone deliberately turning off logging
    const disableMatch = /logging\.disable\s*\(/.exec(source);
    if (disableMatch) {
      const line = source.substring(0, disableMatch.index).split("\n").length;
      findings.push(this.buildDisableLoggingFinding(line, disableMatch[0], context));
    }

    // ── Phase 2: AST analysis — find handlers and console calls ──
    const handlers = this.findRequestHandlers(source);
    if (handlers.length === 0) return findings; // No handlers → console.log is not a compliance issue

    const hasLoggerImport = this.checkLoggerImport(source);
    const hasLoggerDep = this.checkLoggerDependency(context.dependencies);

    // For each handler, check if it uses console instead of structured logger
    for (const handler of handlers) {
      const handlerSource = source.substring(handler.startPos, handler.endPos);
      const consoleCalls = this.findConsoleCalls(handlerSource, handler.startLine);

      if (consoleCalls.length === 0) continue;

      // Check if this specific handler also uses a logger (partial migration scenario)
      const handlerUsesLogger = this.handlerUsesLogger(handlerSource);

      if (handlerUsesLogger) continue; // Handler is using structured logging — skip

      findings.push(
        this.buildConsoleFinding(handler, consoleCalls, hasLoggerImport, hasLoggerDep, context)
      );
    }

    return findings;
  }

  /**
   * Find request handler functions using TypeScript AST.
   * Falls back to regex if AST parsing fails (malformed code).
   */
  private findRequestHandlers(source: string): HandlerInfo[] {
    const handlers: HandlerInfo[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Look for method calls: app.get(..., handler), router.post(..., handler)
        if (ts.isCallExpression(node)) {
          const text = node.expression.getText(sf);
          const fullText = node.getFullText(sf).trim();

          // Check if this is a handler registration call
          const isHandler = HANDLER_PATTERNS.some((p) => p.test(fullText));

          if (isHandler) {
            const startLine = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            const endLine = sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1;

            handlers.push({
              name: text.replace(/\s+/g, ""),
              startLine,
              endLine,
              startPos: node.getStart(sf),
              endPos: node.getEnd(),
            });
          }
        }

        // Also match exported functions: export async function GET/POST/handler
        if (ts.isFunctionDeclaration(node) && node.name) {
          const funcName = node.name.getText(sf);
          const modifiers = ts.getModifiers(node);
          const isExported = modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
          const isHandlerName = /^(handler|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/.test(funcName);

          if (isExported && isHandlerName) {
            const startLine = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            const endLine = sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1;

            handlers.push({
              name: `export function ${funcName}`,
              startLine,
              endLine,
              startPos: node.getStart(sf),
              endPos: node.getEnd(),
            });
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch {
      // AST parsing failed — fall back to regex-based handler detection
      for (const pattern of HANDLER_PATTERNS) {
        const global = new RegExp(pattern.source, "g" + (pattern.flags.includes("i") ? "i" : ""));
        let match: RegExpExecArray | null;
        while ((match = global.exec(source)) !== null) {
          const line = source.substring(0, match.index).split("\n").length;
          // Estimate handler span: find matching closing paren/brace
          const endLine = Math.min(line + 50, source.split("\n").length); // conservative
          handlers.push({
            name: match[0].trim().slice(0, 40),
            startLine: line,
            endLine,
            startPos: match.index,
            endPos: Math.min(match.index + 2000, source.length),
          });
        }
      }
    }

    return handlers;
  }

  /** Find console.log/warn/error calls within a code block */
  private findConsoleCalls(handlerSource: string, baseLineOffset: number): ConsoleCallInfo[] {
    const calls: ConsoleCallInfo[] = [];
    const pattern = /console\.(log|warn|error|info|debug|trace)\s*\(/g;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(handlerSource)) !== null) {
      const localLine = handlerSource.substring(0, match.index).split("\n").length;
      const lineText = handlerSource.split("\n")[localLine - 1] || "";

      // Skip if the console call is in a comment
      if (lineText.trimStart().startsWith("//") || lineText.trimStart().startsWith("*")) continue;

      calls.push({
        method: match[1],
        line: baseLineOffset + localLine - 1,
        text: lineText.trim(),
      });
    }

    return calls;
  }

  /** Check if any structured logger is imported in the file */
  private checkLoggerImport(source: string): boolean {
    for (const logger of STRUCTURED_LOGGERS) {
      // import pino from 'pino' / const pino = require('pino')
      const importRegex = new RegExp(
        `(?:import\\s+.*from\\s+['"]${logger}['"]|` +
        `require\\s*\\(\\s*['"]${logger}['"]\\))`,
      );
      if (importRegex.test(source)) return true;
    }
    return false;
  }

  /** Check if any structured logging library is in the dependency list */
  private checkLoggerDependency(
    deps: AnalysisContext["dependencies"],
  ): boolean {
    return deps.some((d) => STRUCTURED_LOGGER_PACKAGES.has(d.name));
  }

  /** Check if a specific handler scope uses a structured logger (not just console) */
  private handlerUsesLogger(handlerSource: string): boolean {
    // Look for logger method calls: logger.info(), log.warn(), etc.
    return /\b(?:logger|log)\s*\.\s*(?:info|warn|error|debug|fatal|trace|child)\s*\(/.test(handlerSource);
  }

  /** Build finding for console.log in handler (the primary detection) */
  private buildConsoleFinding(
    handler: HandlerInfo,
    consoleCalls: ConsoleCallInfo[],
    hasLoggerImport: boolean,
    hasLoggerDep: boolean,
    context: AnalysisContext,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    // Source: the console calls inside the handler
    const callSummary = consoleCalls.length === 1
      ? `console.${consoleCalls[0].method}() at line ${consoleCalls[0].line}`
      : `${consoleCalls.length} console calls (lines ${consoleCalls.map((c) => c.line).join(", ")})`;

    builder.source({
      source_type: "file-content",
      location: `lines ${handler.startLine}-${handler.endLine}`,
      observed: consoleCalls[0].text.slice(0, 120),
      rationale:
        `${callSummary} found inside request handler "${handler.name}" ` +
        `(lines ${handler.startLine}-${handler.endLine}). Request handlers require ` +
        `structured logging for audit compliance — console.log produces unstructured, ` +
        `unsearchable output with no correlation IDs or machine-parseable fields.`,
    });

    // Propagation: handler context
    builder.propagation({
      propagation_type: "direct-pass",
      location: `handler "${handler.name}" at line ${handler.startLine}`,
      observed:
        `Handler registered at line ${handler.startLine} processes incoming requests. ` +
        `All ${consoleCalls.length} logging call(s) in this handler use console.* ` +
        `instead of a structured logger. ` +
        (hasLoggerImport
          ? "A structured logger IS imported in this file but is NOT used in this handler."
          : "No structured logging library is imported in this file."),
    });

    // Sink: the compliance gap
    builder.sink({
      sink_type: "credential-exposure", // closest match for "audit data loss"
      location: `handler "${handler.name}"`,
      observed:
        `Request handling events logged via console.${consoleCalls[0].method}() — ` +
        `produces plain text output with no structured fields. Cannot be: ` +
        `(1) queried by SIEM/log aggregators, ` +
        `(2) correlated across services via request ID, ` +
        `(3) filtered by log level in production, ` +
        `(4) forwarded to compliance audit trail.`,
    });

    // Mitigation checks
    builder.mitigation({
      mitigation_type: "sanitizer-function",
      present: hasLoggerImport,
      location: hasLoggerImport ? "file-level import" : "not found",
      detail: hasLoggerImport
        ? "Structured logger IS imported but NOT used in this specific handler — partial migration"
        : "No structured logging library (pino/winston/bunyan/tslog) imported anywhere in file",
    });

    // Impact
    builder.impact({
      impact_type: "config-poisoning", // compliance gap
      scope: "connected-services",
      exploitability: "moderate",
      scenario:
        `Without structured logging in handler "${handler.name}", security events ` +
        `(authentication failures, authorization checks, data access, errors) cannot be ` +
        `correlated, searched, or forwarded to SIEM. During an incident, responders cannot ` +
        `trace request flow through this handler. For MCP servers handling sensitive tool ` +
        `invocations, this creates an audit gap that regulators (ISO 27001 auditors, ` +
        `EU AI Act assessors) will flag as a non-conformity.`,
    });

    // Confidence factors — each is an independent signal
    builder.factor(
      "ast_handler_scope",
      0.10,
      `Confirmed via AST: console call is inside request handler "${handler.name}" ` +
      `(not utility code, not test code)`,
    );

    builder.factor(
      "console_call_count",
      consoleCalls.length > 2 ? 0.05 : 0.02,
      `${consoleCalls.length} console call(s) in handler — ` +
      (consoleCalls.length > 2
        ? "multiple unstructured calls indicate systematic logging gap"
        : "single call may be a one-off debug statement"),
    );

    if (!hasLoggerImport) {
      builder.factor(
        "no_logger_import",
        0.08,
        "No structured logging library imported anywhere in the file",
      );
    } else {
      builder.factor(
        "logger_import_present_but_unused",
        -0.15,
        "Structured logger IS imported — this handler may be an oversight in a partial migration",
      );
    }

    if (!hasLoggerDep) {
      builder.factor(
        "no_logger_dependency",
        0.05,
        "No structured logging library in project dependencies — systemic gap, not just this file",
      );
    } else {
      builder.factor(
        "logger_dep_present",
        -0.10,
        "Structured logging library IS in project dependencies — used elsewhere, may reach this file",
      );
    }

    // References
    builder.reference({
      id: "ISO-27001-A.8.15",
      title: "Logging — ISO/IEC 27001:2022 Annex A Control 8.15",
      relevance:
        "Requires that logs are produced for activities, exceptions, faults, " +
        "and information security events. console.log does not meet the structured, " +
        "tamper-evident, retainable requirements of A.8.15.",
    });

    // Verification steps
    builder.verification({
      step_type: "inspect-source",
      instruction:
        `Examine handler "${handler.name}" at lines ${handler.startLine}-${handler.endLine}. ` +
        `Verify that: (1) the handler processes incoming requests (not a utility/helper), ` +
        `(2) the console.* calls are genuinely logging request-handling events ` +
        `(not debug output behind a feature flag).`,
      target: `source_code:${handler.startLine}-${handler.endLine}`,
      expected_observation:
        `console.${consoleCalls[0].method}() call(s) in a request handler without ` +
        `corresponding structured logger usage.`,
    });

    builder.verification({
      step_type: "check-dependency",
      instruction:
        `Check project dependencies (package.json / requirements.txt) for a structured ` +
        `logging library: pino, winston, bunyan, tslog, log4js. ` +
        (hasLoggerDep
          ? "Found in deps — verify it is actually configured and used in production."
          : "Not found — recommend adding pino as the default."),
      target: "package.json:dependencies",
      expected_observation: hasLoggerDep
        ? "Structured logger in deps but not used in this handler"
        : "No structured logging library in project dependencies",
    });

    const chain = builder.build();

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }

  /** Build finding for logging.disable() — explicit audit suppression */
  private buildDisableLoggingFinding(
    line: number,
    matchText: string,
    _context: AnalysisContext,
  ): RuleResult {
    const chain = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: matchText,
        rationale:
          "Explicit logging suppression detected — logging.disable() disables the " +
          "logging framework entirely. This is a deliberate audit trail destruction " +
          "that prevents any security events from being recorded.",
      })
      .sink({
        sink_type: "credential-exposure",
        location: `line ${line}`,
        observed: "logging.disable() — all audit events suppressed",
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          "With logging disabled, no security events (authentication failures, " +
          "unauthorized access, data exfiltration attempts) are recorded. " +
          "Incident response is impossible. This violates ISO 27001 A.8.15, " +
          "EU AI Act Art. 12, and MAESTRO L5 requirements.",
      })
      .factor("explicit_disable", 0.18, "logging.disable() is a deliberate suppression, not an oversight")
      .reference({
        id: "ISO-27001-A.8.15",
        title: "Logging — ISO/IEC 27001:2022 Annex A Control 8.15",
        relevance: "Explicitly disabling logging directly violates the requirement for audit trails.",
      })
      .reference({
        id: "EU-AI-Act-Art12",
        title: "EU AI Act Article 12 — Record-keeping",
        relevance: "AI systems must automatically record logs. Disabling logging makes compliance impossible.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Examine line ${line}: verify logging.disable() is not inside a test file or behind an environment check.`,
        target: `source_code:${line}`,
        expected_observation: "logging.disable() call in production code path",
      })
      .build();

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new AbsentStructuredLoggingRule());
