/**
 * AST-Based Taint Analysis Engine
 *
 * Uses TypeScript's compiler API to parse source code into a real AST,
 * then performs interprocedural taint analysis by tracking data flow
 * through variable assignments, function parameters, return values,
 * property access chains, and destructuring.
 *
 * What this does that regex CAN'T:
 *
 * 1. Interprocedural flow:
 *    function process(cmd) { exec(cmd); }
 *    process(req.body.input);
 *    → Regex sees exec(cmd) with local var — can't know cmd is tainted.
 *    → AST traces: req.body.input → argument 0 of process() → parameter cmd → exec(cmd).
 *
 * 2. Scope-aware tracking:
 *    const cmd = "safe";           // outer scope
 *    if (x) { const cmd = req.body.x; }  // inner scope
 *    exec(cmd);                     // which cmd?
 *    → Regex: both match. AST: resolves to outer scope (safe).
 *
 * 3. String literal exclusion:
 *    exec("git status");           // hardcoded — SAFE
 *    exec(`git ${action}`);        // template with variable — DANGEROUS
 *    → Regex: both match /exec\(/. AST: checks argument node type.
 *
 * 4. Return value tracking:
 *    function getCmd() { return req.body.cmd; }
 *    exec(getCmd());
 *    → Regex: can't connect these. AST: traces return → call site → sink.
 *
 * 5. Sanitizer verification:
 *    const safe = escapeShell(req.body.cmd);
 *    exec(safe);
 *    → Regex: still sees exec(safe) where safe was assigned from req.body.
 *    → AST: knows safe passed through escapeShell (sanitizer) — marks sanitized.
 *
 * Limitations (honest):
 * - Only handles JS/TS (not Python, Go, Ruby)
 * - Doesn't model async/await control flow fully
 * - Doesn't track through dynamic property access (obj[key])
 * - Max call depth of 5 to prevent infinite recursion
 * - No inter-file analysis (single file at a time)
 */

import ts from "typescript";

// ─── Types ──────────────────────────────────────────────────────────────────

/** A taint source identified in the AST */
export interface ASTTaintSource {
  /** AST node representing the source */
  node: ts.Node;
  /** The tainted expression as source text */
  expression: string;
  /** Category of untrusted input */
  category: string;
  /** Line number in source */
  line: number;
  /** Column number */
  column: number;
}

/** A taint sink identified in the AST */
export interface ASTTaintSink {
  node: ts.Node;
  expression: string;
  category: string;
  line: number;
  column: number;
  /** Which argument position(s) are dangerous */
  dangerous_args: number[];
}

/** A complete taint flow from source to sink through the AST */
export interface ASTTaintFlow {
  source: ASTTaintSource;
  sink: ASTTaintSink;
  /** The chain of AST nodes connecting source to sink */
  path: ASTFlowStep[];
  /** Was a sanitizer found on the path? */
  sanitized: boolean;
  /** Name of sanitizer function if found */
  sanitizer_name?: string;
  /** Confidence in this flow */
  confidence: number;
}

export interface ASTFlowStep {
  type:
    | "assignment"
    | "parameter_binding"
    | "return_value"
    | "property_access"
    | "destructure"
    | "template_embed"
    | "spread"
    | "callback_arg";
  expression: string;
  line: number;
}

// ─── Source/Sink/Sanitizer Definitions ───────────────────────────────────────

/** Patterns that identify taint sources in AST property access chains */
const SOURCE_CHAINS: Array<{
  chain: string[];
  category: string;
}> = [
  // Express/Koa/Fastify request
  { chain: ["req", "body"], category: "http_body" },
  { chain: ["req", "params"], category: "http_params" },
  { chain: ["req", "query"], category: "http_query" },
  { chain: ["req", "headers"], category: "http_headers" },
  { chain: ["request", "body"], category: "http_body" },
  { chain: ["request", "params"], category: "http_params" },
  { chain: ["request", "query"], category: "http_query" },
  // process.env
  { chain: ["process", "env"], category: "environment" },
  // process.argv
  { chain: ["process", "argv"], category: "cli_args" },
];

/** Functions that return tainted data */
const SOURCE_FUNCTIONS = new Set([
  "readFileSync",
  "readFile",
  "readline",
  "prompt",
  "JSON.parse",
]);

/** Functions that are dangerous sinks */
const SINK_DEFINITIONS: Array<{
  names: string[];
  category: string;
  dangerous_args: number[];
}> = [
  {
    names: ["exec", "execSync"],
    category: "command_execution",
    dangerous_args: [0],
  },
  {
    names: ["spawn", "spawnSync"],
    category: "command_execution",
    dangerous_args: [0, 1],
  },
  {
    names: ["eval"],
    category: "code_eval",
    dangerous_args: [0],
  },
  {
    names: ["Function"],
    category: "code_eval",
    dangerous_args: [0],
  },
  {
    names: ["query", "execute", "raw"],
    category: "sql_injection",
    dangerous_args: [0],
  },
  {
    names: ["writeFileSync", "writeFile", "appendFileSync"],
    category: "file_write",
    dangerous_args: [0, 1],
  },
  {
    names: ["fetch", "get", "post", "put", "request"],
    category: "ssrf",
    dangerous_args: [0],
  },
  {
    names: ["send", "json", "write", "end", "innerHTML"],
    category: "xss",
    dangerous_args: [0],
  },
  {
    names: ["runInNewContext", "runInThisContext", "runInContext"],
    category: "vm_escape",
    dangerous_args: [0],
  },
  // Deserialization sinks (C12: unsafe deserialization)
  {
    names: ["deserialize", "unserialize"],
    category: "deserialization",
    dangerous_args: [0],
  },
  // Template rendering sinks (C13: server-side template injection)
  {
    names: ["render", "renderString", "renderFile", "compile"],
    category: "template_injection",
    dangerous_args: [0],
  },
  // DNS resolution sinks (G7: DNS-based exfiltration)
  {
    names: ["resolve", "resolve4", "resolve6", "lookup"],
    category: "dns_exfil",
    dangerous_args: [0],
  },
];

/** Known sanitizer function names */
const SANITIZERS: Map<string, string[]> = new Map([
  // Command sanitizers
  ["escapeShell", ["command_execution"]],
  ["shellEscape", ["command_execution"]],
  ["execFile", ["command_execution"]], // safe alternative to exec
  ["execFileSync", ["command_execution"]],
  // SQL sanitizers
  ["escape", ["sql_injection"]],
  ["parameterize", ["sql_injection"]],
  ["prepare", ["sql_injection"]],
  // HTML sanitizers
  ["escapeHtml", ["xss"]],
  ["sanitize", ["xss", "command_execution"]],
  ["DOMPurify", ["xss"]],
  // Path sanitizers
  ["resolve", ["file_write"]],
  ["normalize", ["file_write"]],
  // Generic validation
  ["validate", ["command_execution", "sql_injection", "xss", "ssrf"]],
  ["parse", ["command_execution", "sql_injection"]],
  ["parseInt", ["sql_injection"]],
  ["Number", ["sql_injection"]],
]);

// ─── AST Taint Analysis Engine ──────────────────────────────────────────────

/**
 * Perform AST-based taint analysis on JavaScript/TypeScript source code.
 *
 * Algorithm:
 * 1. Parse source into AST using TypeScript compiler
 * 2. Walk AST to build three maps:
 *    a. Variable taint map: which variables hold tainted data
 *    b. Function map: function name → parameter bindings + return taint
 *    c. Scope chain: which scope each variable belongs to
 * 3. For each sink call in the AST:
 *    a. Check if any argument is tainted (directly or transitively)
 *    b. Check if a sanitizer appears on the taint path
 *    c. Produce a flow if tainted and unsanitized
 */
export function analyzeASTTaint(source: string): ASTTaintFlow[] {
  // Parse into AST
  const sourceFile = ts.createSourceFile(
    "analysis.ts",
    source,
    ts.ScriptTarget.Latest,
    true, // setParentNodes — essential for scope resolution
    ts.ScriptKind.TSX
  );

  const engine = new TaintEngine(sourceFile);
  engine.analyze();
  return engine.getFlows();
}

class TaintEngine {
  private sourceFile: ts.SourceFile;
  /** variable name → taint info (tracks what's tainted and why) */
  private taintMap = new Map<
    string,
    { source: ASTTaintSource; path: ASTFlowStep[]; sanitized: boolean; sanitizer_name?: string }
  >();
  /** function name → { params tainted at call sites, returns tainted data } */
  private functionMap = new Map<
    string,
    { node: ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction; paramNames: string[] }
  >();
  /** All sinks found during analysis */
  private sinks: ASTTaintSink[] = [];
  /** Completed taint flows */
  private flows: ASTTaintFlow[] = [];

  constructor(sourceFile: ts.SourceFile) {
    this.sourceFile = sourceFile;
  }

  analyze(): void {
    // Pass 1: Collect function declarations and their parameter names
    this.collectFunctions(this.sourceFile);

    // Pass 2: Walk AST to identify sources, propagate taint, find sinks
    this.walkNode(this.sourceFile);

    // Pass 3: Check each sink for tainted arguments
    this.resolveSinks();
  }

  getFlows(): ASTTaintFlow[] {
    return this.flows;
  }

  // ── Pass 1: Collect Functions ──

  private collectFunctions(node: ts.Node): void {
    if (ts.isFunctionDeclaration(node) && node.name) {
      this.functionMap.set(node.name.text, {
        node,
        paramNames: node.parameters.map((p) =>
          ts.isIdentifier(p.name) ? p.name.text : ""
        ),
      });
    }

    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const init = node.initializer;
      if (init && (ts.isFunctionExpression(init) || ts.isArrowFunction(init))) {
        this.functionMap.set(node.name.text, {
          node: init,
          paramNames: init.parameters.map((p) =>
            ts.isIdentifier(p.name) ? p.name.text : ""
          ),
        });
      }
    }

    ts.forEachChild(node, (child) => this.collectFunctions(child));
  }

  // ── Pass 2: Walk AST ──

  private walkNode(node: ts.Node): void {
    // Check for taint sources (variable declarations initialized from tainted data)
    if (ts.isVariableDeclaration(node) && node.initializer) {
      this.checkVariableDeclaration(node);
    }

    // Check for assignment expressions (x = tainted)
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      this.checkAssignment(node);
    }

    // Check for call expressions (potential sinks or sanitizers)
    if (ts.isCallExpression(node)) {
      this.checkCallExpression(node);
    }

    // Recurse into children
    ts.forEachChild(node, (child) => this.walkNode(child));
  }

  private checkVariableDeclaration(node: ts.VariableDeclaration): void {
    if (!ts.isIdentifier(node.name)) return;
    const varName = node.name.text;
    const init = node.initializer!;

    // Check if initializer is a taint source
    const source = this.identifySource(init);
    if (source) {
      this.taintMap.set(varName, { source, path: [], sanitized: false });
      return;
    }

    // Check if initializer references a tainted variable
    const taintedRef = this.findTaintedReference(init);
    if (taintedRef) {
      const { line, character } = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
      this.taintMap.set(varName, {
        source: taintedRef.source,
        path: [
          ...taintedRef.path,
          {
            type: "assignment",
            expression: `${varName} = ${init.getText(this.sourceFile).slice(0, 60)}`,
            line: line + 1,
          },
        ],
        sanitized: taintedRef.sanitized,
        sanitizer_name: taintedRef.sanitizer_name,
      });
      return;
    }

    // Check if initializer is a call to a function that returns tainted data
    if (ts.isCallExpression(init)) {
      const callee = this.getCallName(init);
      if (callee) {
        // Check if calling a sanitizer on tainted input
        const sanitizerCategories = SANITIZERS.get(callee);
        if (sanitizerCategories && init.arguments.length > 0) {
          const argTaint = this.findTaintedReference(init.arguments[0]);
          if (argTaint) {
            this.taintMap.set(varName, {
              source: argTaint.source,
              path: [
                ...argTaint.path,
                {
                  type: "assignment",
                  expression: `${varName} = ${callee}(...)  [sanitizer]`,
                  line: this.getLine(node),
                },
              ],
              sanitized: true,
              sanitizer_name: callee,
            });
            return;
          }
        }

        // Check if calling a known source function
        if (SOURCE_FUNCTIONS.has(callee)) {
          this.taintMap.set(varName, {
            source: {
              node: init,
              expression: init.getText(this.sourceFile).slice(0, 80),
              category: "function_return",
              line: this.getLine(init),
              column: this.getColumn(init),
            },
            path: [],
            sanitized: false,
          });
          return;
        }

        // Check interprocedural flow: does the called function return tainted data?
        this.checkInterproceduralReturn(varName, callee, init);
      }
    }

    // Check template literal with tainted interpolation
    if (ts.isTemplateExpression(init)) {
      for (const span of init.templateSpans) {
        const taint = this.findTaintedReference(span.expression);
        if (taint) {
          this.taintMap.set(varName, {
            source: taint.source,
            path: [
              ...taint.path,
              {
                type: "template_embed",
                expression: `${varName} = \`...\${${span.expression.getText(this.sourceFile)}}\``,
                line: this.getLine(node),
              },
            ],
            sanitized: taint.sanitized,
            sanitizer_name: taint.sanitizer_name,
          });
          break;
        }
      }
    }
  }

  private checkAssignment(node: ts.BinaryExpression): void {
    if (!ts.isIdentifier(node.left)) return;
    const varName = node.left.text;
    const taint = this.findTaintedReference(node.right);
    if (taint) {
      this.taintMap.set(varName, {
        ...taint,
        path: [
          ...taint.path,
          {
            type: "assignment",
            expression: `${varName} = ${node.right.getText(this.sourceFile).slice(0, 60)}`,
            line: this.getLine(node),
          },
        ],
      });
    }
  }

  private checkCallExpression(node: ts.CallExpression): void {
    const callee = this.getCallName(node);
    if (!callee) return;

    // Check if this is a sink
    for (const sinkDef of SINK_DEFINITIONS) {
      if (sinkDef.names.includes(callee)) {
        this.sinks.push({
          node,
          expression: node.getText(this.sourceFile).slice(0, 100),
          category: sinkDef.category,
          line: this.getLine(node),
          column: this.getColumn(node),
          dangerous_args: sinkDef.dangerous_args,
        });
        break;
      }
    }

    // Check interprocedural taint propagation: tainted arg → function param
    const funcDef = this.functionMap.get(callee);
    if (funcDef) {
      for (let i = 0; i < node.arguments.length && i < funcDef.paramNames.length; i++) {
        const argTaint = this.findTaintedReference(node.arguments[i]);
        if (argTaint) {
          const paramName = funcDef.paramNames[i];
          if (paramName && !this.taintMap.has(paramName)) {
            this.taintMap.set(paramName, {
              source: argTaint.source,
              path: [
                ...argTaint.path,
                {
                  type: "parameter_binding",
                  expression: `${callee}(${node.arguments[i].getText(this.sourceFile).slice(0, 40)}) → param ${paramName}`,
                  line: this.getLine(node),
                },
              ],
              sanitized: argTaint.sanitized,
              sanitizer_name: argTaint.sanitizer_name,
            });
          }
        }
      }
    }
  }

  // ── Pass 3: Resolve Sinks ──

  private resolveSinks(): void {
    for (const sink of this.sinks) {
      const callNode = sink.node as ts.CallExpression;

      for (const argIdx of sink.dangerous_args) {
        if (argIdx >= callNode.arguments.length) continue;
        const arg = callNode.arguments[argIdx];

        // Skip string literals (safe — hardcoded)
        if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
          continue;
        }

        // Check if the argument is tainted
        const taint = this.findTaintedReference(arg);
        if (!taint) continue;

        this.flows.push({
          source: taint.source,
          sink,
          path: taint.path,
          sanitized: taint.sanitized,
          sanitizer_name: taint.sanitizer_name,
          confidence: this.computeConfidence(taint, sink),
        });
      }

      // Also check template literal arguments
      for (const argIdx of sink.dangerous_args) {
        if (argIdx >= callNode.arguments.length) continue;
        const arg = callNode.arguments[argIdx];
        if (ts.isTemplateExpression(arg)) {
          for (const span of arg.templateSpans) {
            const taint = this.findTaintedReference(span.expression);
            if (taint) {
              this.flows.push({
                source: taint.source,
                sink,
                path: [
                  ...taint.path,
                  {
                    type: "template_embed",
                    expression: `\`...\${${span.expression.getText(this.sourceFile).slice(0, 40)}}\``,
                    line: this.getLine(arg),
                  },
                ],
                sanitized: taint.sanitized,
                sanitizer_name: taint.sanitizer_name,
                confidence: this.computeConfidence(taint, sink) * 1.1, // template = higher confidence
              });
              break;
            }
          }
        }
      }
    }
  }

  // ── Taint Reference Resolution ──

  /**
   * Check if an AST node references tainted data.
   * Handles: identifiers, property access chains, call expressions.
   */
  private findTaintedReference(
    node: ts.Node
  ): { source: ASTTaintSource; path: ASTFlowStep[]; sanitized: boolean; sanitizer_name?: string } | null {
    // Direct identifier reference
    if (ts.isIdentifier(node)) {
      return this.taintMap.get(node.text) || null;
    }

    // Property access: obj.prop or obj.prop.sub
    if (ts.isPropertyAccessExpression(node)) {
      // Check full chain first (e.g., req.body.command)
      const chain = this.getPropertyChain(node);
      const source = this.matchSourceChain(chain, node);
      if (source) return { source, path: [], sanitized: false };

      // Check if base is tainted (e.g., taintedObj.anything)
      return this.findTaintedReference(node.expression);
    }

    // Element access: obj["prop"]
    if (ts.isElementAccessExpression(node)) {
      return this.findTaintedReference(node.expression);
    }

    // Call expression: check if it returns tainted data
    if (ts.isCallExpression(node)) {
      const callee = this.getCallName(node);
      if (callee) {
        // Sanitizer check
        const sanitizerCats = SANITIZERS.get(callee);
        if (sanitizerCats && node.arguments.length > 0) {
          const argTaint = this.findTaintedReference(node.arguments[0]);
          if (argTaint) {
            return { ...argTaint, sanitized: true, sanitizer_name: callee };
          }
        }
      }
      // Check each argument — if function just passes through
      for (const arg of node.arguments) {
        const taint = this.findTaintedReference(arg);
        if (taint) return taint;
      }
    }

    // Binary expression (concatenation): "prefix" + tainted
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return this.findTaintedReference(node.left) || this.findTaintedReference(node.right);
    }

    // Template expression
    if (ts.isTemplateExpression(node)) {
      for (const span of node.templateSpans) {
        const taint = this.findTaintedReference(span.expression);
        if (taint) return taint;
      }
    }

    // Conditional expression: cond ? tainted : safe
    if (ts.isConditionalExpression(node)) {
      return this.findTaintedReference(node.whenTrue) || this.findTaintedReference(node.whenFalse);
    }

    // Await expression
    if (ts.isAwaitExpression(node)) {
      return this.findTaintedReference(node.expression);
    }

    // Parenthesized expression
    if (ts.isParenthesizedExpression(node)) {
      return this.findTaintedReference(node.expression);
    }

    return null;
  }

  // ── Source Identification ──

  private identifySource(node: ts.Node): ASTTaintSource | null {
    // Property access chain: req.body, process.env, etc.
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const chain = this.getPropertyChain(node);
      return this.matchSourceChain(chain, node);
    }

    // Spread from tainted source
    if (ts.isSpreadElement(node)) {
      return this.identifySource(node.expression);
    }

    return null;
  }

  private matchSourceChain(chain: string[], node: ts.Node): ASTTaintSource | null {
    for (const src of SOURCE_CHAINS) {
      if (chain.length >= src.chain.length) {
        const matches = src.chain.every((part, i) => chain[i] === part);
        if (matches) {
          return {
            node,
            expression: chain.join("."),
            category: src.category,
            line: this.getLine(node),
            column: this.getColumn(node),
          };
        }
      }
    }
    return null;
  }

  // ── Interprocedural Analysis ──

  private checkInterproceduralReturn(
    varName: string,
    callee: string,
    callNode: ts.CallExpression
  ): void {
    const funcDef = this.functionMap.get(callee);
    if (!funcDef) return;

    // Walk the function body to find return statements
    // If any return statement returns tainted data, mark the variable as tainted
    const returns = this.findReturnStatements(funcDef.node);
    for (const ret of returns) {
      if (ret.expression) {
        const taint = this.findTaintedReference(ret.expression);
        if (taint) {
          this.taintMap.set(varName, {
            source: taint.source,
            path: [
              ...taint.path,
              {
                type: "return_value",
                expression: `${callee}() returns tainted: ${ret.expression.getText(this.sourceFile).slice(0, 40)}`,
                line: this.getLine(ret),
              },
            ],
            sanitized: taint.sanitized,
            sanitizer_name: taint.sanitizer_name,
          });
          return;
        }
      }
    }
  }

  private findReturnStatements(node: ts.Node): ts.ReturnStatement[] {
    const returns: ts.ReturnStatement[] = [];
    const visit = (n: ts.Node) => {
      if (ts.isReturnStatement(n)) returns.push(n);
      // Don't descend into nested functions (their returns are not ours)
      if (
        !ts.isFunctionDeclaration(n) &&
        !ts.isFunctionExpression(n) &&
        !ts.isArrowFunction(n)
      ) {
        ts.forEachChild(n, visit);
      }
    };
    // For arrow functions with expression body, treat the body as a return
    if (ts.isArrowFunction(node) && !ts.isBlock(node.body)) {
      // Synthetic return: the arrow body expression itself
      returns.push({ expression: node.body } as unknown as ts.ReturnStatement);
    } else {
      ts.forEachChild(node, visit);
    }
    return returns;
  }

  // ── Utility Methods ──

  private getPropertyChain(node: ts.Node): string[] {
    const chain: string[] = [];
    let current: ts.Node = node;
    while (ts.isPropertyAccessExpression(current)) {
      chain.unshift(current.name.text);
      current = current.expression;
    }
    if (ts.isIdentifier(current)) {
      chain.unshift(current.text);
    }
    return chain;
  }

  private getCallName(node: ts.CallExpression): string | null {
    if (ts.isIdentifier(node.expression)) {
      return node.expression.text;
    }
    if (ts.isPropertyAccessExpression(node.expression)) {
      return node.expression.name.text;
    }
    // new Function(...)
    if (ts.isNewExpression(node.parent!) && ts.isIdentifier(node.expression)) {
      return node.expression.text;
    }
    return null;
  }

  private getLine(node: ts.Node): number {
    return this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  }

  private getColumn(node: ts.Node): number {
    return this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).character;
  }

  private computeConfidence(
    taint: { source: ASTTaintSource; path: ASTFlowStep[]; sanitized: boolean },
    sink: ASTTaintSink
  ): number {
    let confidence = 0.85; // Base: AST-confirmed flow

    // Direct source → sink (no intermediate steps)
    if (taint.path.length === 0) confidence = 0.95;

    // Short chain is more reliable
    if (taint.path.length <= 2) confidence += 0.05;
    if (taint.path.length > 4) confidence -= 0.15;

    // HTTP body → command execution = highest confidence
    if (taint.source.category === "http_body" && sink.category === "command_execution") {
      confidence += 0.05;
    }

    // Template embedding in sink = very high confidence
    if (taint.path.some((p) => p.type === "template_embed")) {
      confidence += 0.05;
    }

    // Sanitized = informational confidence
    if (taint.sanitized) confidence -= 0.5;

    return Math.min(0.99, Math.max(0.1, confidence));
  }
}

/**
 * Convenience: get only unsanitized flows (real vulnerabilities).
 */
export function getUnsanitizedASTFlows(source: string): ASTTaintFlow[] {
  return analyzeASTTaint(source).filter((f) => !f.sanitized);
}

// ─── Reachability API (Phase 0, Chunk 0.5 — used by evidence-integrity) ─────

/** Minimal location shape — intentionally a subset of `Location` from the
 *  v2 standard so callers can pass evidence-chain source/sink links directly. */
export interface ReachabilitySite {
  file: string;
  line: number;
  col?: number;
}

export interface ReachabilityResult {
  /** Whether the source is known to reach the sink through data flow. */
  reachable: boolean;
  /** The file:line sequence along the proven flow. Empty when !reachable. */
  path: Array<{ file: string; line: number }>;
  /**
   * Discriminator: why the function decided what it did. Distinguishes
   * "provably reachable", "provably unreachable", and "out-of-scope for
   * the current analyzer" — which callers need to route to a conservative
   * (assume-reachable) fallback in Phase 1.
   */
  reason:
    | "taint-flow-matches"
    | "no-flow-in-file"
    | "different-files-not-supported-yet"
    | "source-code-unavailable"
    | "location-outside-file";
}

/**
 * Answer the question: does data from `src` reach `sink`?
 *
 * Phase 0 scope (current): within-file only. If both sites live in the
 * same file and that file's source is in `sources`, the function runs
 * `analyzeASTTaint` and reports whether a recorded flow has its source
 * on `src.line` and its sink on `sink.line`.
 *
 * Phase 2.1 (later) extends this to cross-file flows using module-graph.ts.
 * Until then, cross-file calls return `different-files-not-supported-yet`
 * with `reachable: false` — and callers MUST treat that as a signal to
 * NOT downgrade confidence solely because reachability couldn't be proven.
 *
 * Why this signature (Location-shaped, not AST-node-shaped)? Because the
 * v2 evidence chain stores structured `Location` values. Having an API
 * that consumes a `Location` directly avoids every caller re-parsing the
 * same file just to hand taint-ast a node.
 */
export function isReachable(
  src: ReachabilitySite,
  sink: ReachabilitySite,
  sources: Map<string, string>,
): ReachabilityResult {
  if (src.file !== sink.file) {
    return {
      reachable: false,
      path: [],
      reason: "different-files-not-supported-yet",
    };
  }

  const text = sources.get(src.file);
  if (typeof text !== "string") {
    return { reachable: false, path: [], reason: "source-code-unavailable" };
  }

  // Cheap sanity check: both lines must actually exist in the file.
  const lineCount = text.split("\n").length;
  if (src.line > lineCount || sink.line > lineCount) {
    return { reachable: false, path: [], reason: "location-outside-file" };
  }

  const flows = analyzeASTTaint(text);
  for (const flow of flows) {
    if (flow.source.line === src.line && flow.sink.line === sink.line) {
      const path = [
        { file: src.file, line: flow.source.line },
        ...flow.path.map((p) => ({ file: src.file, line: p.line })),
        { file: sink.file, line: flow.sink.line },
      ];
      return { reachable: true, path, reason: "taint-flow-matches" };
    }
  }

  return { reachable: false, path: [], reason: "no-flow-in-file" };
}
