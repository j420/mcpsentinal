/**
 * N1, N2, N3, N7, N8, N10 — JSON-RPC Protocol rules (TypedRuleV2)
 *
 * N1:  JSON-RPC Batch Request Abuse — batch handling without size limits
 * N2:  Notification Flooding — emit/notify in loops without throttle
 * N3:  Progress Token Spoofing — predictable/user-controlled progress tokens
 * N7:  Initialization Race Condition — parallel init without sync
 * N8:  Ping Abuse for Side Channels — data in heartbeat messages
 * N10: Cancellation Token Injection — cancel tokens from user input
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

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }

function getEnclosingFunc(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isFunctionDeclaration(cur) || ts.isFunctionExpression(cur) ||
        ts.isArrowFunction(cur) || ts.isMethodDeclaration(cur)) return cur;
    cur = cur.parent;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// N1 — JSON-RPC Batch Request Abuse
// ═══════════════════════════════════════════════════════════════════════════════

const BATCH_PROCESS_PATTERNS = [
  /\.forEach\s*\(/,
  /\.map\s*\(/,
  /for\s*\(\s*(?:const|let|var)\s+\w+\s+of\b/,
  /for\s*\(\s*(?:let|var)\s+\w+\s*=/,
];
const BATCH_LIMIT_PATTERNS = [
  /\.length\s*(?:>|>=|<|<=|===?)\s*\d/,
  /\bmax\w*(?:Batch|Size|Length|Count|Requests)\b/i,
  /\blimit\b/i,
  /\bthrottle\b/i,
  /\brate\s*limit/i,
  /\.slice\s*\(/,
];

class N1Rule implements TypedRuleV2 {
  readonly id = "N1";
  readonly name = "JSON-RPC Batch Request Abuse";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Look for Array.isArray checks on request/body — indicates batch handling
        if (ts.isIfStatement(node)) {
          const condText = node.expression.getText(sf);
          if (/Array\.isArray\s*\(\s*(?:req|request|body|message|data|batch|payload)/i.test(condText)) {
            const blockText = node.thenStatement.getText(sf);
            const hasIteration = BATCH_PROCESS_PATTERNS.some(p => p.test(blockText));
            const hasLimit = BATCH_LIMIT_PATTERNS.some(p => p.test(blockText));

            if (hasIteration && !hasLimit) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              findings.push(this.buildFinding(line, source));
            }
          }
        }

        // Also check for direct iteration of request arrays with batch-related names
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
          const obj = node.expression.expression.getText(sf);
          const method = node.expression.name.getText(sf);
          if (/(?:batch|requests|messages)/i.test(obj) && /forEach|map|reduce/.test(method)) {
            const enclosing = getEnclosingFunc(node);
            if (enclosing) {
              const funcText = enclosing.getText(sf);
              if (!BATCH_LIMIT_PATTERNS.some(p => p.test(funcText))) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                findings.push(this.buildFinding(line, source));
              }
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }

    return findings.slice(0, 1);  // One finding per file
  }

  private buildFinding(line: number, source: string): RuleResult {
    const lineText = source.split("\n")[line - 1]?.trim() || "";
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale: "Batch request processing without size limit. Attacker sends array of thousands of requests in one JSON-RPC batch.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: `line ${line}`,
        observed: "Unbounded batch iteration — each request executed without limit check",
      })
      .mitigation({
        mitigation_type: "rate-limit",
        present: false,
        location: `enclosing function of line ${line}`,
        detail: "No batch size limit, rate limiting, or pagination found",
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "server-host",
        exploitability: "trivial",
        scenario: "Single batch request with 10,000 items exhausts server resources. No per-batch limit enforced.",
      })
      .factor("unbounded_batch", 0.10, "Batch iteration without size check")
      .reference({
        id: "JSON-RPC-2.0-Batch",
        title: "JSON-RPC 2.0 Specification — Batch Requests",
        relevance: "JSON-RPC batching enables amplification attacks if not size-limited.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Check line ${line} for batch handling. Verify a size limit exists.`,
        target: `source_code:${line}`,
        expected_observation: "Batch request processing without size/rate limit",
      });

    return {
      rule_id: "N1",
      severity: "high",
      owasp_category: "MCP07-insecure-config",
      mitre_technique: null,
      remediation: "Limit batch request size. Add rate limiting per batch.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// N2 — Notification Flooding
// ═══════════════════════════════════════════════════════════════════════════════

const NOTIFY_PATTERNS = /\b(?:notify|notification|emit|push|broadcast|publish|sendNotification|sendEvent)\s*\(/i;
const LOOP_KINDS = new Set([
  ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.DoStatement,
]);
const THROTTLE_PATTERNS = [
  /\bthrottle\b/i, /\bdebounce\b/i, /\brateLimit\b/i,
  /\bdelay\b/i, /\bsleep\b/i, /\bsetTimeout\b/,
  /\bbreak\b/, /\breturn\b/,
];

class N2Rule implements TypedRuleV2 {
  readonly id = "N2";
  readonly name = "Notification Flooding";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);
          if (NOTIFY_PATTERNS.test(callText + "(")) {
            // Check if inside a loop
            const inLoop = this.isInsideLoop(node);
            // Check if inside setInterval
            const inInterval = this.isInsideSetInterval(node, sf);

            if (inLoop || inInterval) {
              const enclosing = getEnclosingFunc(node);
              const funcText = enclosing ? enclosing.getText(sf) : "";
              const hasThrottle = THROTTLE_PATTERNS.some(p => p.test(funcText));

              if (!hasThrottle) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                const lineText = source.split("\n")[line - 1]?.trim() || "";

                const builder = new EvidenceChainBuilder()
                  .source({
                    source_type: "file-content",
                    location: `line ${line}`,
                    observed: lineText.slice(0, 120),
                    rationale: `Notification emission inside ${inLoop ? "loop" : "setInterval"} without throttling.`,
                  })
                  .sink({
                    sink_type: "network-send",
                    location: `line ${line}`,
                    observed: `Unbounded notifications: ${callText}() in ${inLoop ? "loop" : "interval"}`,
                  })
                  .mitigation({
                    mitigation_type: "rate-limit",
                    present: false,
                    location: `enclosing function of line ${line}`,
                    detail: "No throttle, debounce, or rate limit found",
                  })
                  .impact({
                    impact_type: "denial-of-service",
                    scope: "connected-services",
                    exploitability: "trivial",
                    scenario: "Notification flood overwhelms clients. Each notification consumes bandwidth and processing.",
                  })
                  .factor("notification_in_loop", 0.10, `${callText}() emitted in unbounded ${inLoop ? "loop" : "interval"}`)
                  .verification({
                    step_type: "inspect-source",
                    instruction: `Check line ${line} for notification throttling.`,
                    target: `source_code:${line}`,
                    expected_observation: "Notification in loop without throttle/debounce",
                  });

                findings.push({
                  rule_id: "N2",
                  severity: "high",
                  owasp_category: "MCP07-insecure-config",
                  mitre_technique: null,
                  remediation: "Throttle notifications. Add rate limits and debouncing.",
                  chain: builder.build(),
                });
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 1);
  }

  private isInsideLoop(node: ts.Node): boolean {
    let cur: ts.Node | undefined = node.parent;
    while (cur) {
      if (LOOP_KINDS.has(cur.kind)) return true;
      if (ts.isFunctionDeclaration(cur) || ts.isFunctionExpression(cur) ||
          ts.isArrowFunction(cur)) return false;
      cur = cur.parent;
    }
    return false;
  }

  private isInsideSetInterval(node: ts.Node, sf: ts.SourceFile): boolean {
    let cur: ts.Node | undefined = node.parent;
    while (cur) {
      if (ts.isCallExpression(cur) && /setInterval/.test(cur.expression.getText(sf))) return true;
      cur = cur.parent;
    }
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// N3 — Progress Token Spoofing
// ═══════════════════════════════════════════════════════════════════════════════

const PROGRESS_NAMES = /(?:progress|progressToken|progressId|progressKey)/i;
const USER_INPUT_SOURCES = /(?:req\.|request\.|params\.|body\.|query\.|args\.|input\.)/;
const PREDICTABLE_PATTERNS = [
  /\+\+/, /counter/, /Date\.now/, /\.length/, /index/i, /Math\.floor/,
];
const CRYPTO_TOKEN_GEN = [
  /crypto\.randomUUID/, /crypto\.randomBytes/, /uuid/, /nanoid/, /cuid/,
];

class N3Rule implements TypedRuleV2 {
  readonly id = "N3";
  readonly name = "Progress Token Spoofing";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isVariableDeclaration(node) || ts.isBinaryExpression(node)) {
          const text = node.getText(sf);
          if (PROGRESS_NAMES.test(text)) {
            const initText = ts.isVariableDeclaration(node) && node.initializer
              ? node.initializer.getText(sf) : ts.isBinaryExpression(node) ? node.right.getText(sf) : "";

            const fromUserInput = USER_INPUT_SOURCES.test(initText);
            const isPredictable = PREDICTABLE_PATTERNS.some(p => p.test(initText));
            const isCryptoGen = CRYPTO_TOKEN_GEN.some(p => p.test(initText));

            if ((fromUserInput || isPredictable) && !isCryptoGen) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              const lineText = source.split("\n")[line - 1]?.trim() || "";
              const desc = fromUserInput
                ? "Progress token from user input"
                : "Predictable progress token (sequential/timestamp)";

              const builder = new EvidenceChainBuilder()
                .source({
                  source_type: fromUserInput ? "user-parameter" : "file-content",
                  location: `line ${line}`,
                  observed: lineText.slice(0, 120),
                  rationale: `${desc}. Spoofable tokens allow attackers to hijack or cancel other users' operations.`,
                })
                .sink({
                  sink_type: "config-modification",
                  location: `line ${line}`,
                  observed: `Weak progress token: ${initText.slice(0, 60)}`,
                })
                .impact({
                  impact_type: "session-hijack",
                  scope: "connected-services",
                  exploitability: fromUserInput ? "trivial" : "moderate",
                  scenario: `${desc}. Attacker guesses/controls token → cancels legitimate operations or reads progress data.`,
                })
                .factor("weak_progress_token", fromUserInput ? 0.12 : 0.08, desc)
                .verification({
                  step_type: "inspect-source",
                  instruction: `Check line ${line}: progress token generation. Should use crypto.randomUUID().`,
                  target: `source_code:${line}`,
                  expected_observation: desc,
                });

              findings.push({
                rule_id: "N3",
                severity: "high",
                owasp_category: "MCP07-insecure-config",
                mitre_technique: null,
                remediation: "Validate progress tokens. Use cryptographic tokens, not sequential IDs.",
                chain: builder.build(),
              });
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 1);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// N7 — Initialization Race Condition
// ═══════════════════════════════════════════════════════════════════════════════

const INIT_NAMES = /\binit(?:ialize|ialise|ial)?(?:Server|DB|Connection|Client|App|Service)?\s*\(/i;
const SYNC_PRIMITIVES = [
  /\block\b/i, /\bmutex\b/i, /\bsemaphore\b/i, /\bsynchronized\b/i,
  /\bonce\b/i, /\bsingleton\b/i, /\.acquire\s*\(/i,
];

class N7Rule implements TypedRuleV2 {
  readonly id = "N7";
  readonly name = "Initialization Race Condition";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Find Promise.all/Promise.allSettled/Promise.race with init calls
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);
          if (/Promise\.(?:all|allSettled|race)\s*$/.test(callText)) {
            // Check if any argument contains init calls
            const argsText = node.arguments.map(a => a.getText(sf)).join(" ");
            if (INIT_NAMES.test(argsText)) {
              const enclosing = getEnclosingFunc(node);
              const funcText = enclosing ? enclosing.getText(sf) : source;
              const hasSync = SYNC_PRIMITIVES.some(p => p.test(funcText));

              if (!hasSync) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                const lineText = source.split("\n")[line - 1]?.trim() || "";

                const builder = new EvidenceChainBuilder()
                  .source({
                    source_type: "file-content",
                    location: `line ${line}`,
                    observed: lineText.slice(0, 120),
                    rationale: "Parallel initialization without synchronization. Concurrent init can corrupt shared state.",
                  })
                  .sink({
                    sink_type: "config-modification",
                    location: `line ${line}`,
                    observed: `Race condition: ${callText}() with init functions`,
                  })
                  .mitigation({
                    mitigation_type: "sanitizer-function",
                    present: false,
                    location: `enclosing scope of line ${line}`,
                    detail: "No lock, mutex, semaphore, or once guard found",
                  })
                  .impact({
                    impact_type: "config-poisoning",
                    scope: "server-host",
                    exploitability: "complex",
                    scenario: "Parallel init corrupts shared state. Partially initialized components process requests unsafely.",
                  })
                  .factor("parallel_init_no_sync", 0.08, "Promise.all/race with init calls, no synchronization")
                  .verification({
                    step_type: "inspect-source",
                    instruction: `Check line ${line}: init race. Add mutex or serialize with await.`,
                    target: `source_code:${line}`,
                    expected_observation: "Parallel initialization without synchronization",
                  });

                findings.push({
                  rule_id: "N7",
                  severity: "high",
                  owasp_category: "MCP07-insecure-config",
                  mitre_technique: null,
                  remediation: "Serialize initialization. Use locks/mutexes for concurrent init attempts.",
                  chain: builder.build(),
                });
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 1);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// N8 — Ping Abuse for Side Channels
// ═══════════════════════════════════════════════════════════════════════════════

const PING_NAMES = /\b(?:ping|heartbeat|keepalive|healthCheck)\b/i;
const DATA_PAYLOAD_PATTERNS = [
  /\bdata\b/i, /\bpayload\b/i, /\bcontent\b/i, /\bmessage\b/i,
  /\bbody\b/i, /\binfo\b/i, /\bdetails\b/i, /\bmetadata\b/i,
];
const SAFE_PING_FIELDS = /\b(?:timestamp|ts|time|pong|ok|status|alive)\b/i;

class N8Rule implements TypedRuleV2 {
  readonly id = "N8";
  readonly name = "Ping Abuse for Side Channels";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Find function/method declarations with ping/heartbeat names
        if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name) {
          const name = node.name.getText(sf);
          if (PING_NAMES.test(name) && node.body) {
            const bodyText = node.body.getText(sf);
            // Check if the function sends data beyond simple timestamp
            const hasDataPayload = DATA_PAYLOAD_PATTERNS.some(p => p.test(bodyText));
            const isSafePingOnly = SAFE_PING_FIELDS.test(bodyText) && !hasDataPayload;

            if (hasDataPayload && !isSafePingOnly) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

              const builder = new EvidenceChainBuilder()
                .source({
                  source_type: "file-content",
                  location: `line ${line}`,
                  observed: `function ${name}() contains data payload`,
                  rationale: "Ping/heartbeat function carries data beyond simple health status. Data in pings creates a covert side channel.",
                })
                .sink({
                  sink_type: "network-send",
                  location: `line ${line}`,
                  observed: `Ping function "${name}" sends data payload`,
                })
                .impact({
                  impact_type: "data-exfiltration",
                  scope: "user-data",
                  exploitability: "complex",
                  scenario: "Data embedded in ping messages bypasses request logging and monitoring. Covert exfiltration channel.",
                })
                .factor("data_in_ping", 0.08, `Ping function "${name}" includes data payload fields`)
                .verification({
                  step_type: "inspect-source",
                  instruction: `Review function "${name}" at line ${line}. Pings should be empty or timestamp-only.`,
                  target: `source_code:${line}`,
                  expected_observation: "Data payload in ping/heartbeat function",
                });

              findings.push({
                rule_id: "N8",
                severity: "high",
                owasp_category: "MCP07-insecure-config",
                mitre_technique: null,
                remediation: "Ping messages should be empty or contain only timestamps. Never include data.",
                chain: builder.build(),
              });
            }
          }
        }

        // Also check for send/emit calls with ping + data object
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);
          if (PING_NAMES.test(callText) && node.arguments.length > 0) {
            const argText = node.arguments.map(a => a.getText(sf)).join(" ");
            if (DATA_PAYLOAD_PATTERNS.some(p => p.test(argText)) && !SAFE_PING_FIELDS.test(argText)) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              const lineText = source.split("\n")[line - 1]?.trim() || "";

              const builder = new EvidenceChainBuilder()
                .source({
                  source_type: "file-content",
                  location: `line ${line}`,
                  observed: lineText.slice(0, 120),
                  rationale: "Ping call includes data payload argument. Creates covert side channel.",
                })
                .sink({
                  sink_type: "network-send",
                  location: `line ${line}`,
                  observed: `Ping with data: ${callText}(${argText.slice(0, 60)})`,
                })
                .impact({
                  impact_type: "data-exfiltration",
                  scope: "user-data",
                  exploitability: "complex",
                  scenario: "Data in pings bypasses monitoring. Covert channel for exfiltration.",
                })
                .factor("data_in_ping_call", 0.08, `Ping call with data argument`)
                .verification({
                  step_type: "inspect-source",
                  instruction: `Check line ${line}: ping should not carry data.`,
                  target: `source_code:${line}`,
                  expected_observation: "Data in ping/heartbeat call",
                });

              findings.push({
                rule_id: "N8",
                severity: "high",
                owasp_category: "MCP07-insecure-config",
                mitre_technique: null,
                remediation: "Ping messages should be empty or contain only timestamps. Never include data.",
                chain: builder.build(),
              });
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 1);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// N10 — Cancellation Token Injection
// ═══════════════════════════════════════════════════════════════════════════════

const CANCEL_NAMES = /\b(?:cancel|abort|cancellation)(?:Token|Id|Signal|Key)?\b/i;
const USER_SOURCES = /\b(?:req|request|params|body|query|args|input|ctx)\b\s*[\.\[]/;
const SERVER_GEN = [
  /crypto\.randomUUID/, /uuid/, /nanoid/, /crypto\.randomBytes/,
  /new\s+AbortController/, /AbortController/,
];

class N10Rule implements TypedRuleV2 {
  readonly id = "N10";
  readonly name = "Cancellation Token Injection";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Variable declarations: cancelToken = req.body.token
        if (ts.isVariableDeclaration(node) && node.initializer) {
          const name = node.name.getText(sf);
          if (CANCEL_NAMES.test(name)) {
            const init = node.initializer.getText(sf);
            if (USER_SOURCES.test(init) && !SERVER_GEN.some(p => p.test(init))) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              findings.push(this.buildFinding(line, name, init, source));
            }
          }
        }

        // Property assignments: obj.cancelToken = params.token
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const left = node.left.getText(sf);
          const right = node.right.getText(sf);
          if (CANCEL_NAMES.test(left) && USER_SOURCES.test(right) && !SERVER_GEN.some(p => p.test(right))) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            findings.push(this.buildFinding(line, left, right, source));
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings.slice(0, 1);
  }

  private buildFinding(line: number, name: string, source_expr: string, source: string): RuleResult {
    const lineText = source.split("\n")[line - 1]?.trim() || "";
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale: `Cancellation token "${name}" derived from user input: ${source_expr.slice(0, 60)}. User-controlled cancel tokens enable cancellation of other users' operations.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: `line ${line}`,
        observed: `User input → cancel token: ${name} = ${source_expr.slice(0, 60)}`,
      })
      .sink({
        sink_type: "config-modification",
        location: `line ${line}`,
        observed: `User-controlled cancellation: ${name}`,
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "connected-services",
        exploitability: "trivial",
        scenario: "Attacker controls cancel token → cancels other users' operations, causing denial of service.",
      })
      .factor("user_controlled_cancel", 0.12, `Cancel token from user input: ${source_expr.slice(0, 40)}`)
      .verification({
        step_type: "trace-flow",
        instruction: `Trace "${name}" at line ${line}. Verify token is not from user input.`,
        target: `source_code:${line}`,
        expected_observation: "Cancellation token sourced from user request",
      });

    return {
      rule_id: "N10",
      severity: "high",
      owasp_category: "MCP07-insecure-config",
      mitre_technique: null,
      remediation: "Generate cancellation tokens server-side. Never accept them from user input.",
      chain: builder.build(),
    };
  }
}

// Register all rules
registerTypedRuleV2(new N1Rule());
registerTypedRuleV2(new N2Rule());
registerTypedRuleV2(new N3Rule());
registerTypedRuleV2(new N7Rule());
registerTypedRuleV2(new N8Rule());
registerTypedRuleV2(new N10Rule());
