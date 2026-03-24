/**
 * Python AST-Based Taint Analysis Engine
 *
 * Uses tree-sitter + tree-sitter-python to parse Python source into a real AST,
 * then performs the same 3-pass interprocedural taint analysis as taint-ast.ts:
 *   Pass 1: Collect function definitions and their parameter names
 *   Pass 2: Walk AST — identify sources, propagate taint, find sinks
 *   Pass 3: Check each sink for tainted arguments
 *
 * Python-specific sources: request.args, request.form, flask.request, os.environ,
 *   FastMCP handler params, sys.argv
 * Python-specific sinks: subprocess.run(shell=True), os.system(), pickle.loads(),
 *   yaml.load(), eval(), cursor.execute()
 * Python-specific sanitizers: shlex.quote(), bleach.clean(), parameterized queries
 */

import Parser from "tree-sitter";
import PythonLanguage from "tree-sitter-python";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface PythonTaintSource {
  expression: string;
  category: string;
  line: number;
  column: number;
}

export interface PythonTaintSink {
  expression: string;
  category: string;
  line: number;
  column: number;
  dangerous_args: number[];
}

export interface PythonTaintFlow {
  source: PythonTaintSource;
  sink: PythonTaintSink;
  path: PythonFlowStep[];
  sanitized: boolean;
  sanitizer_name?: string;
  confidence: number;
}

export interface PythonFlowStep {
  type:
    | "assignment"
    | "parameter_binding"
    | "return_value"
    | "property_access"
    | "f_string_embed"
    | "concatenation"
    | "augmented_assign";
  expression: string;
  line: number;
}

// ─── Source/Sink/Sanitizer Definitions ───────────────────────────────────────

/** Property access chains that identify taint sources */
const SOURCE_CHAINS: Array<{ chain: string[]; category: string }> = [
  // Flask
  { chain: ["request", "args"], category: "http_query" },
  { chain: ["request", "form"], category: "http_body" },
  { chain: ["request", "data"], category: "http_body" },
  { chain: ["request", "json"], category: "http_body" },
  { chain: ["request", "values"], category: "http_body" },
  { chain: ["request", "headers"], category: "http_headers" },
  { chain: ["request", "cookies"], category: "http_cookies" },
  { chain: ["request", "files"], category: "http_files" },
  { chain: ["request", "get_json"], category: "http_body" },
  // FastAPI / Starlette
  { chain: ["request", "query_params"], category: "http_query" },
  { chain: ["request", "path_params"], category: "http_params" },
  { chain: ["request", "body"], category: "http_body" },
  // os.environ
  { chain: ["os", "environ"], category: "environment" },
  // sys.argv
  { chain: ["sys", "argv"], category: "cli_args" },
];

/** Function calls that return tainted data */
const SOURCE_FUNCTIONS = new Set([
  "input",
  "raw_input",
  "open",
  "read",
  "readline",
  "readlines",
  "recv",
  "recvfrom",
]);

/** Sink definitions: dangerous functions */
export interface SinkEntry {
  fn: string;
  module: string | null;
  dangerous_args: number[];
  category: string;
  sanitizers: string[];
  why: string;
  rule_id: string;
}

export const PYTHON_SINKS: SinkEntry[] = [
  // C1: Command Injection
  {
    fn: "system", module: "os", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.quote", "quote"], why: "Direct shell execution", rule_id: "C1",
  },
  {
    fn: "popen", module: "os", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.quote"], why: "Shell execution via popen", rule_id: "C1",
  },
  {
    fn: "run", module: "subprocess", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.split", "shlex.quote"], why: "subprocess with potential shell=True", rule_id: "C1",
  },
  {
    fn: "call", module: "subprocess", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.split"], why: "subprocess.call", rule_id: "C1",
  },
  {
    fn: "check_output", module: "subprocess", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.split"], why: "subprocess.check_output", rule_id: "C1",
  },
  {
    fn: "Popen", module: "subprocess", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.split"], why: "subprocess.Popen", rule_id: "C1",
  },
  // C4: SQL Injection
  {
    fn: "execute", module: "cursor", dangerous_args: [0], category: "sql_injection",
    sanitizers: ["parameterize", "%s", "?"], why: "SQL without parameterization", rule_id: "C4",
  },
  {
    fn: "executemany", module: "cursor", dangerous_args: [0], category: "sql_injection",
    sanitizers: ["parameterize"], why: "SQL executemany without parameterization", rule_id: "C4",
  },
  {
    fn: "raw", module: "django", dangerous_args: [0], category: "sql_injection",
    sanitizers: ["params"], why: "Django raw SQL", rule_id: "C4",
  },
  {
    fn: "execute", module: "sqlalchemy", dangerous_args: [0], category: "sql_injection",
    sanitizers: ["text", "bindparams"], why: "SQLAlchemy raw execute", rule_id: "C4",
  },
  // C12: Unsafe Deserialization
  {
    fn: "loads", module: "pickle", dangerous_args: [0], category: "deserialization",
    sanitizers: [], why: "Arbitrary code execution via pickle", rule_id: "C12",
  },
  {
    fn: "load", module: "pickle", dangerous_args: [0], category: "deserialization",
    sanitizers: [], why: "Arbitrary code execution via pickle file", rule_id: "C12",
  },
  {
    fn: "load", module: "yaml", dangerous_args: [0], category: "deserialization",
    sanitizers: ["safe_load", "SafeLoader"], why: "YAML deserialization RCE", rule_id: "C12",
  },
  {
    fn: "loads", module: "marshal", dangerous_args: [0], category: "deserialization",
    sanitizers: [], why: "marshal deserialization — code execution", rule_id: "C12",
  },
  // C16: Dynamic Code Eval
  {
    fn: "eval", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "Arbitrary Python code execution", rule_id: "C16",
  },
  {
    fn: "exec", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "Arbitrary Python code execution via exec", rule_id: "C16",
  },
  {
    fn: "compile", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "Compiles string to code object", rule_id: "C16",
  },
  {
    fn: "__import__", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "Dynamic import — potential code injection", rule_id: "C16",
  },
  {
    fn: "import_module", module: "importlib", dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "Dynamic module import", rule_id: "C16",
  },
  // C3: SSRF
  {
    fn: "get", module: "requests", dangerous_args: [0], category: "ssrf",
    sanitizers: ["validate_url"], why: "HTTP GET with user-controlled URL", rule_id: "C3",
  },
  {
    fn: "post", module: "requests", dangerous_args: [0], category: "ssrf",
    sanitizers: ["validate_url"], why: "HTTP POST with user-controlled URL", rule_id: "C3",
  },
  {
    fn: "urlopen", module: "urllib", dangerous_args: [0], category: "ssrf",
    sanitizers: ["validate_url"], why: "urllib.request.urlopen", rule_id: "C3",
  },
  // C2: Path Traversal
  {
    fn: "open", module: null, dangerous_args: [0], category: "path_traversal",
    sanitizers: ["os.path.abspath", "os.path.realpath", "secure_filename"],
    why: "File open with user-controlled path", rule_id: "C2",
  },
];

/** Known sanitizer function names */
const SANITIZERS: Map<string, string[]> = new Map([
  ["shlex.quote", ["command_execution"]],
  ["quote", ["command_execution"]],
  ["shlex.split", ["command_execution"]],
  ["bleach.clean", ["xss"]],
  ["escape", ["xss", "sql_injection"]],
  ["html.escape", ["xss"]],
  ["markupsafe.escape", ["xss"]],
  ["Markup.escape", ["xss"]],
  ["parameterize", ["sql_injection"]],
  ["sanitize", ["command_execution", "xss"]],
  ["validate", ["command_execution", "sql_injection", "ssrf"]],
  ["int", ["sql_injection", "command_execution"]],
  ["float", ["sql_injection"]],
  ["secure_filename", ["path_traversal"]],
  ["os.path.abspath", ["path_traversal"]],
  ["os.path.realpath", ["path_traversal"]],
  ["os.path.basename", ["path_traversal"]],
  ["safe_load", ["deserialization"]],
  ["hmac.compare_digest", ["timing_attack"]],
]);

// ─── Python Taint Engine ────────────────────────────────────────────────────

/** Taint record stored per variable */
interface TaintRecord {
  source: PythonTaintSource;
  path: PythonFlowStep[];
  sanitized: boolean;
  sanitizer_name?: string;
}

type SyntaxNode = Parser.SyntaxNode;

class PythonTaintEngine {
  private tree: Parser.Tree;
  private source: string;
  private taintMap = new Map<string, TaintRecord>();
  private functionMap = new Map<string, { node: SyntaxNode; paramNames: string[] }>();
  private sinks: PythonTaintSink[] = [];
  private sinkNodes: SyntaxNode[] = [];
  private flows: PythonTaintFlow[] = [];

  constructor(tree: Parser.Tree, source: string) {
    this.tree = tree;
    this.source = source;
  }

  analyze(): void {
    // Pass 1: Collect function definitions
    this.collectFunctions(this.tree.rootNode);

    // Pass 2: Walk AST — identify sources, propagate taint, find sinks
    this.walkNode(this.tree.rootNode);

    // Pass 3: Check each sink for tainted arguments
    this.resolveSinks();
  }

  getFlows(): PythonTaintFlow[] {
    return this.flows;
  }

  // ── Pass 1: Collect Functions ──

  private collectFunctions(node: SyntaxNode): void {
    if (node.type === "function_definition") {
      const nameNode = node.childForFieldName("name");
      const paramsNode = node.childForFieldName("parameters");
      if (nameNode) {
        const paramNames: string[] = [];
        if (paramsNode) {
          for (const child of paramsNode.namedChildren) {
            if (child.type === "identifier") {
              paramNames.push(child.text);
            } else if (child.type === "default_parameter" || child.type === "typed_parameter" || child.type === "typed_default_parameter") {
              const id = child.namedChildren[0];
              if (id && id.type === "identifier") paramNames.push(id.text);
            }
          }
        }
        this.functionMap.set(nameNode.text, { node, paramNames });
      }
    }

    for (const child of node.namedChildren) {
      this.collectFunctions(child);
    }
  }

  // ── Pass 2: Walk AST ──

  private walkNode(node: SyntaxNode): void {
    // Assignment: x = tainted
    if (node.type === "assignment") {
      this.checkAssignment(node);
    }

    // Augmented assignment: x += tainted
    if (node.type === "augmented_assignment") {
      this.checkAugmentedAssignment(node);
    }

    // Call expressions — potential sinks or taint propagation
    if (node.type === "call") {
      this.checkCallExpression(node);
    }

    // For-loop variable from tainted iterable
    if (node.type === "for_statement") {
      this.checkForLoop(node);
    }

    for (const child of node.namedChildren) {
      this.walkNode(child);
    }
  }

  private checkAssignment(node: SyntaxNode): void {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right) return;

    // Only handle simple identifier targets
    if (left.type !== "identifier") return;
    const varName = left.text;

    // Check if RHS is a taint source
    const source = this.identifySource(right);
    if (source) {
      this.taintMap.set(varName, { source, path: [], sanitized: false });
      return;
    }

    // Check if RHS references tainted data
    const taint = this.findTaintedReference(right);
    if (taint) {
      this.taintMap.set(varName, {
        source: taint.source,
        path: [
          ...taint.path,
          {
            type: "assignment",
            expression: `${varName} = ${right.text.slice(0, 60)}`,
            line: node.startPosition.row + 1,
          },
        ],
        sanitized: taint.sanitized,
        sanitizer_name: taint.sanitizer_name,
      });
      return;
    }

    // Check if RHS is a call to a sanitizer
    if (right.type === "call") {
      const callee = this.getCallName(right);
      if (callee) {
        const sanitizerCats = SANITIZERS.get(callee);
        if (sanitizerCats && right.namedChildren.length > 0) {
          const args = this.getCallArguments(right);
          if (args.length > 0) {
            const argTaint = this.findTaintedReference(args[0]);
            if (argTaint) {
              this.taintMap.set(varName, {
                source: argTaint.source,
                path: [
                  ...argTaint.path,
                  {
                    type: "assignment",
                    expression: `${varName} = ${callee}(...)  [sanitizer]`,
                    line: node.startPosition.row + 1,
                  },
                ],
                sanitized: true,
                sanitizer_name: callee,
              });
              return;
            }
          }
        }

        // Check source functions (input(), open().read(), etc.)
        if (SOURCE_FUNCTIONS.has(callee)) {
          this.taintMap.set(varName, {
            source: {
              expression: right.text.slice(0, 80),
              category: "function_return",
              line: right.startPosition.row + 1,
              column: right.startPosition.column,
            },
            path: [],
            sanitized: false,
          });
          return;
        }

        // Check interprocedural return
        this.checkInterproceduralReturn(varName, callee, right);
      }
    }

    // f-string with tainted interpolation
    if (right.type === "string" || right.type === "concatenated_string") {
      const fstringTaint = this.checkFStringTaint(right);
      if (fstringTaint) {
        this.taintMap.set(varName, {
          source: fstringTaint.source,
          path: [
            ...fstringTaint.path,
            {
              type: "f_string_embed",
              expression: `${varName} = f"...{${fstringTaint.source.expression}}"`,
              line: node.startPosition.row + 1,
            },
          ],
          sanitized: fstringTaint.sanitized,
          sanitizer_name: fstringTaint.sanitizer_name,
        });
      }
    }
  }

  private checkAugmentedAssignment(node: SyntaxNode): void {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;

    const taint = this.findTaintedReference(right);
    if (taint) {
      this.taintMap.set(left.text, {
        source: taint.source,
        path: [
          ...taint.path,
          {
            type: "augmented_assign",
            expression: `${left.text} += ${right.text.slice(0, 40)}`,
            line: node.startPosition.row + 1,
          },
        ],
        sanitized: taint.sanitized,
        sanitizer_name: taint.sanitizer_name,
      });
    }
  }

  private checkCallExpression(node: SyntaxNode): void {
    const callee = this.getCallName(node);
    if (!callee) return;
    const fnName = callee.split(".").pop() || callee;

    // Check if this is a sink
    for (const sinkDef of PYTHON_SINKS) {
      if (sinkDef.fn === fnName || sinkDef.fn === callee) {
        // For subprocess.run/call/Popen — only flag if shell=True
        if (sinkDef.module === "subprocess" && sinkDef.fn !== "Popen") {
          if (!this.hasShellTrue(node)) continue;
        }

        this.sinks.push({
          expression: node.text.slice(0, 100),
          category: sinkDef.category,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          dangerous_args: sinkDef.dangerous_args,
        });
        this.sinkNodes.push(node);
        break;
      }
    }

    // Interprocedural taint: tainted arg → function param
    const funcDef = this.functionMap.get(callee);
    if (funcDef) {
      const args = this.getCallArguments(node);
      for (let i = 0; i < args.length && i < funcDef.paramNames.length; i++) {
        const argTaint = this.findTaintedReference(args[i]);
        if (argTaint) {
          const paramName = funcDef.paramNames[i];
          if (paramName && !this.taintMap.has(paramName)) {
            this.taintMap.set(paramName, {
              source: argTaint.source,
              path: [
                ...argTaint.path,
                {
                  type: "parameter_binding",
                  expression: `${callee}(${args[i].text.slice(0, 40)}) → param ${paramName}`,
                  line: node.startPosition.row + 1,
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

  private checkForLoop(node: SyntaxNode): void {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (!left || !right || left.type !== "identifier") return;

    const taint = this.findTaintedReference(right);
    if (taint) {
      this.taintMap.set(left.text, {
        source: taint.source,
        path: [
          ...taint.path,
          {
            type: "assignment",
            expression: `for ${left.text} in ${right.text.slice(0, 40)}`,
            line: node.startPosition.row + 1,
          },
        ],
        sanitized: taint.sanitized,
        sanitizer_name: taint.sanitizer_name,
      });
    }
  }

  // ── Pass 3: Resolve Sinks ──

  private resolveSinks(): void {
    for (let si = 0; si < this.sinks.length; si++) {
      const sink = this.sinks[si];
      const sinkNode = this.sinkNodes[si];
      const args = this.getCallArguments(sinkNode);

      for (const argIdx of sink.dangerous_args) {
        if (argIdx >= args.length) continue;
        const arg = args[argIdx];

        // Skip plain string literals (safe — hardcoded)
        if (arg.type === "string" && !this.hasFStringInterpolation(arg)) {
          continue;
        }

        // Check if the argument is tainted
        const taint = this.findTaintedReference(arg);
        if (taint) {
          this.flows.push({
            source: taint.source,
            sink,
            path: taint.path,
            sanitized: taint.sanitized,
            sanitizer_name: taint.sanitizer_name,
            confidence: this.computeConfidence(taint, sink),
          });
          continue;
        }

        // Check f-string interpolation in the argument itself
        if (arg.type === "string" || arg.type === "concatenated_string") {
          const fTaint = this.checkFStringTaint(arg);
          if (fTaint) {
            this.flows.push({
              source: fTaint.source,
              sink,
              path: [
                ...fTaint.path,
                {
                  type: "f_string_embed",
                  expression: `f-string in sink arg: ${arg.text.slice(0, 60)}`,
                  line: arg.startPosition.row + 1,
                },
              ],
              sanitized: fTaint.sanitized,
              sanitizer_name: fTaint.sanitizer_name,
              confidence: this.computeConfidence(fTaint, sink) * 1.1,
            });
          }
        }

        // Check binary expression (string concatenation) in argument
        if (arg.type === "binary_operator") {
          const concatTaint = this.findTaintedReference(arg);
          if (concatTaint) {
            this.flows.push({
              source: concatTaint.source,
              sink,
              path: [
                ...concatTaint.path,
                {
                  type: "concatenation",
                  expression: `string concat in sink: ${arg.text.slice(0, 60)}`,
                  line: arg.startPosition.row + 1,
                },
              ],
              sanitized: concatTaint.sanitized,
              sanitizer_name: concatTaint.sanitizer_name,
              confidence: this.computeConfidence(concatTaint, sink),
            });
          }
        }
      }
    }
  }

  // ── Taint Reference Resolution ──

  private findTaintedReference(node: SyntaxNode): TaintRecord | null {
    // Direct identifier
    if (node.type === "identifier") {
      return this.taintMap.get(node.text) || null;
    }

    // Attribute access: obj.attr (e.g., request.args)
    if (node.type === "attribute") {
      const chain = this.getAttributeChain(node);
      const source = this.matchSourceChain(chain, node);
      if (source) return { source, path: [], sanitized: false };

      // Check if the base object is tainted
      const obj = node.childForFieldName("object");
      if (obj) return this.findTaintedReference(obj);
    }

    // Subscript: obj[key] (e.g., request.args['name'])
    if (node.type === "subscript") {
      const value = node.childForFieldName("value");
      if (value) return this.findTaintedReference(value);
    }

    // Call expression — check sanitizer, method on tainted obj, or pass-through
    if (node.type === "call") {
      const callee = this.getCallName(node);
      if (callee) {
        const sanitizerCats = SANITIZERS.get(callee);
        if (sanitizerCats) {
          const args = this.getCallArguments(node);
          if (args.length > 0) {
            const argTaint = this.findTaintedReference(args[0]);
            if (argTaint) {
              return { ...argTaint, sanitized: true, sanitizer_name: callee };
            }
          }
        }
      }
      // Check if this is a method call on a tainted object (e.g., request.args.get("cmd"))
      const fn = node.childForFieldName("function");
      if (fn && fn.type === "attribute") {
        const obj = fn.childForFieldName("object");
        if (obj) {
          const t = this.findTaintedReference(obj);
          if (t) return t;
        }
      }
      // Check if function returns tainted data via arguments
      if (callee) {
        const args = this.getCallArguments(node);
        for (const arg of args) {
          const t = this.findTaintedReference(arg);
          if (t) return t;
        }
      }
    }

    // Binary operator (string concatenation: "SELECT " + user_input)
    if (node.type === "binary_operator") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left) {
        const t = this.findTaintedReference(left);
        if (t) return t;
      }
      if (right) {
        const t = this.findTaintedReference(right);
        if (t) return t;
      }
    }

    // f-string (formatted_string or string with interpolation)
    if (node.type === "string" || node.type === "concatenated_string") {
      const fTaint = this.checkFStringTaint(node);
      if (fTaint) return fTaint;
    }

    // Conditional expression: x if cond else y
    if (node.type === "conditional_expression") {
      for (const child of node.namedChildren) {
        const t = this.findTaintedReference(child);
        if (t) return t;
      }
    }

    // Await expression
    if (node.type === "await") {
      const child = node.namedChildren[0];
      if (child) return this.findTaintedReference(child);
    }

    // Parenthesized expression
    if (node.type === "parenthesized_expression") {
      const child = node.namedChildren[0];
      if (child) return this.findTaintedReference(child);
    }

    return null;
  }

  // ── Source Identification ──

  private identifySource(node: SyntaxNode): PythonTaintSource | null {
    if (node.type === "attribute") {
      const chain = this.getAttributeChain(node);
      return this.matchSourceChain(chain, node);
    }

    if (node.type === "subscript") {
      const value = node.childForFieldName("value");
      if (value) return this.identifySource(value);
    }

    if (node.type === "call") {
      const callee = this.getCallName(node);
      if (callee && SOURCE_FUNCTIONS.has(callee)) {
        return {
          expression: node.text.slice(0, 80),
          category: "function_return",
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
        };
      }
    }

    return null;
  }

  private matchSourceChain(chain: string[], node: SyntaxNode): PythonTaintSource | null {
    for (const src of SOURCE_CHAINS) {
      if (chain.length >= src.chain.length) {
        const matches = src.chain.every((part, i) => chain[i] === part);
        if (matches) {
          return {
            expression: chain.join("."),
            category: src.category,
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
          };
        }
      }
    }
    return null;
  }

  // ── Interprocedural ──

  private checkInterproceduralReturn(varName: string, callee: string, callNode: SyntaxNode): void {
    const funcDef = this.functionMap.get(callee);
    if (!funcDef) return;

    const returns = this.findReturnStatements(funcDef.node);
    for (const ret of returns) {
      const valueNode = ret.namedChildren[0];
      if (valueNode) {
        const taint = this.findTaintedReference(valueNode);
        if (taint) {
          this.taintMap.set(varName, {
            source: taint.source,
            path: [
              ...taint.path,
              {
                type: "return_value",
                expression: `${callee}() returns tainted: ${valueNode.text.slice(0, 40)}`,
                line: ret.startPosition.row + 1,
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

  private findReturnStatements(node: SyntaxNode): SyntaxNode[] {
    const returns: SyntaxNode[] = [];
    const visit = (n: SyntaxNode) => {
      if (n.type === "return_statement") {
        returns.push(n);
      }
      // Don't descend into nested function definitions
      if (n.type !== "function_definition" || n === node) {
        for (const child of n.namedChildren) {
          visit(child);
        }
      }
    };
    visit(node);
    return returns;
  }

  // ── Utility Methods ──

  private getAttributeChain(node: SyntaxNode): string[] {
    const chain: string[] = [];
    let current: SyntaxNode | null = node;
    while (current && current.type === "attribute") {
      const attr = current.childForFieldName("attribute");
      if (attr) chain.unshift(attr.text);
      current = current.childForFieldName("object") || null;
    }
    if (current && current.type === "identifier") {
      chain.unshift(current.text);
    }
    return chain;
  }

  private getCallName(node: SyntaxNode): string | null {
    const fn = node.childForFieldName("function");
    if (!fn) return null;
    if (fn.type === "identifier") return fn.text;
    if (fn.type === "attribute") {
      return this.getAttributeChain(fn).join(".");
    }
    return null;
  }

  private getCallArguments(node: SyntaxNode): SyntaxNode[] {
    const argsNode = node.childForFieldName("arguments");
    if (!argsNode) return [];
    return argsNode.namedChildren.filter(
      (c) => c.type !== "keyword_argument" && c.type !== "dictionary_splat" && c.type !== "list_splat"
    );
  }

  /** Check if a subprocess call has shell=True */
  private hasShellTrue(callNode: SyntaxNode): boolean {
    const argsNode = callNode.childForFieldName("arguments");
    if (!argsNode) return false;
    for (const child of argsNode.namedChildren) {
      if (child.type === "keyword_argument") {
        const name = child.childForFieldName("name");
        const value = child.childForFieldName("value");
        if (name && name.text === "shell" && value && value.text === "True") {
          return true;
        }
      }
    }
    return false;
  }

  /** Check if a string node has f-string interpolation */
  private hasFStringInterpolation(node: SyntaxNode): boolean {
    if (node.text.startsWith('f"') || node.text.startsWith("f'") ||
        node.text.startsWith('f"""') || node.text.startsWith("f'''")) {
      return true;
    }
    for (const child of node.namedChildren) {
      if (child.type === "interpolation" || child.type === "format_expression") return true;
    }
    return false;
  }

  /** Check f-string/format string for tainted interpolation */
  private checkFStringTaint(node: SyntaxNode): TaintRecord | null {
    const visit = (n: SyntaxNode): TaintRecord | null => {
      if (n.type === "interpolation" || n.type === "format_expression") {
        for (const child of n.namedChildren) {
          const t = this.findTaintedReference(child);
          if (t) return t;
        }
      }
      for (const child of n.namedChildren) {
        const t = visit(child);
        if (t) return t;
      }
      return null;
    };
    return visit(node);
  }

  private computeConfidence(taint: TaintRecord, sink: PythonTaintSink): number {
    let confidence = 0.85;

    if (taint.path.length === 0) confidence = 0.95;
    if (taint.path.length <= 2) confidence += 0.05;
    if (taint.path.length > 4) confidence -= 0.15;

    if (taint.source.category === "http_body" && sink.category === "command_execution") {
      confidence += 0.05;
    }

    if (taint.path.some((p) => p.type === "f_string_embed")) {
      confidence += 0.05;
    }

    if (taint.sanitized) confidence -= 0.5;

    return Math.min(0.99, Math.max(0.1, confidence));
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────

let parser: Parser | null = null;

function getParser(): Parser {
  if (!parser) {
    parser = new Parser();
    parser.setLanguage(PythonLanguage as unknown as Parser.Language);
  }
  return parser;
}

/**
 * Perform AST-based taint analysis on Python source code.
 * Same 3-pass architecture as analyzeASTTaint() for JS/TS.
 */
export function analyzePythonTaint(source: string): PythonTaintFlow[] {
  const p = getParser();
  const tree = p.parse(source);
  if (!tree) return [];

  const engine = new PythonTaintEngine(tree, source);
  engine.analyze();
  return engine.getFlows();
}

/**
 * Convenience: get only unsanitized flows (real vulnerabilities).
 */
export function getUnsanitizedPythonFlows(source: string): PythonTaintFlow[] {
  return analyzePythonTaint(source).filter((f) => !f.sanitized);
}

/**
 * Detect if source code is Python (vs JS/TS).
 * Uses heuristics: shebang, import patterns, def/class keywords, indentation style.
 */
export function isPythonSource(source: string): boolean {
  // Shebang
  if (/^#!.*python/m.test(source)) return true;

  // Python-specific import patterns
  if (/^(?:from\s+\w+\s+import|import\s+\w+)/m.test(source)) {
    // Could also be JS — check for Python-specific modules
    if (/(?:from|import)\s+(?:flask|fastapi|django|fastmcp|mcp\.server|subprocess|pickle|os|sys|yaml|requests)\b/.test(source)) {
      return true;
    }
  }

  // def keyword with colon (Python function def)
  if (/^(?:async\s+)?def\s+\w+\s*\([^)]*\)\s*(?:->.*)?:/m.test(source)) return true;

  // class with colon
  if (/^class\s+\w+.*:/m.test(source)) return true;

  // Python-specific builtins
  if (/(?:print\s*\(|if\s+__name__\s*==\s*['"]__main__['"]|self\.\w+)/.test(source)) return true;

  return false;
}
