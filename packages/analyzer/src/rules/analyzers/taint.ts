/**
 * Lightweight Taint Analysis Engine
 *
 * Traces data flow from untrusted sources to dangerous sinks in source code
 * WITHOUT requiring a full AST parser. Uses lexical analysis with scope-aware
 * variable tracking.
 *
 * This is not a full taint analysis engine (that requires CodeQL or Semgrep).
 * It's a practical middle ground that catches 70-80% of real taint flows
 * using pattern-based source extraction + variable propagation + sink detection.
 *
 * Architecture:
 * 1. Source Identification — extract untrusted input sources (req.body, process.env, etc.)
 * 2. Variable Propagation — track assignments from sources through variables
 * 3. Sink Detection — check if tainted variables reach dangerous functions
 * 4. Sanitizer Detection — check if tainted data passes through known sanitizers
 *
 * A finding is only produced when:
 *   source → [propagation] → sink  (with no sanitizer in the path)
 *
 * Why this matters:
 * The current engine flags `exec("git status")` as C1 (command injection).
 * That's a false positive — the argument is a hardcoded string.
 * Taint analysis only flags `exec(userInput)` where userInput traces back
 * to an untrusted source.
 */

/** A taint source — where untrusted data enters the program */
export interface TaintSource {
  /** Variable name or expression that holds tainted data */
  expression: string;
  /** Source category */
  category: TaintSourceCategory;
  /** Line number where the source appears */
  line: number;
  /** The pattern that matched */
  pattern: string;
}

export type TaintSourceCategory =
  | "http_request"     // req.body, req.params, req.query, request.json()
  | "environment"      // process.env, os.environ
  | "file_read"        // fs.readFile, open().read()
  | "user_input"       // readline, input(), prompt()
  | "network_input"    // fetch(), axios, http.get
  | "database_read"    // query result variables
  | "command_line"     // process.argv, sys.argv
  | "deserialization"; // JSON.parse, yaml.load

/** A taint sink — where tainted data causes damage */
export interface TaintSink {
  /** Function or expression that is dangerous with tainted input */
  expression: string;
  /** Sink category */
  category: TaintSinkCategory;
  /** Line number */
  line: number;
  /** The pattern that matched */
  pattern: string;
  /** Arguments passed to the sink (extracted from the call) */
  arguments: string[];
}

export type TaintSinkCategory =
  | "command_execution"  // exec, spawn, system, subprocess
  | "sql_query"          // db.query, cursor.execute
  | "file_write"         // fs.writeFile, open().write()
  | "path_access"        // fs.readFile(userPath), open(userPath)
  | "code_eval"          // eval, new Function, setTimeout(string)
  | "template_render"    // template.render, res.render with user template
  | "url_request"        // fetch(userUrl), axios(userUrl) → SSRF
  | "html_output"        // res.send, innerHTML → XSS
  | "deserialization";   // pickle.loads, yaml.load(unsafe)

/** A sanitizer — transforms tainted data into safe data */
export interface Sanitizer {
  /** Function or expression that sanitizes */
  expression: string;
  /** Line number */
  line: number;
  /** What sink categories this sanitizer protects against */
  protects_against: TaintSinkCategory[];
}

/** A taint propagation — assignment or data flow from one variable to another */
export interface TaintPropagation {
  /** Source variable/expression */
  from: string;
  /** Destination variable */
  to: string;
  /** Line number */
  line: number;
  /** Type of propagation */
  type: "assignment" | "destructure" | "function_return" | "string_concat";
}

/** Complete taint flow from source through propagation to sink */
export interface TaintFlow {
  /** The untrusted source */
  source: TaintSource;
  /** Chain of variable propagations */
  propagation_chain: TaintPropagation[];
  /** The dangerous sink */
  sink: TaintSink;
  /** Was a sanitizer found in the path? */
  sanitized: boolean;
  /** Sanitizer that was found (if any) */
  sanitizer?: Sanitizer;
  /** Confidence in this taint flow (0.0–1.0) */
  confidence: number;
}

// --- Source Patterns ---

const SOURCE_PATTERNS: Array<{
  pattern: RegExp;
  category: TaintSourceCategory;
  extract_var: (match: RegExpExecArray) => string | null;
}> = [
  // JavaScript/TypeScript HTTP request sources
  {
    pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req(?:uest)?\.(?:body|params|query|headers)\b/g,
    category: "http_request",
    extract_var: (m) => m[1],
  },
  {
    pattern: /(?:const|let|var)\s+\{([^}]+)\}\s*=\s*req(?:uest)?\.(?:body|params|query)\b/g,
    category: "http_request",
    extract_var: (m) => m[1], // destructured — returns comma-separated names
  },
  {
    pattern: /req(?:uest)?\.(?:body|params|query|headers)\s*\.\s*(\w+)/g,
    category: "http_request",
    extract_var: (m) => null, // inline use, not assigned
  },
  // Python HTTP request sources
  {
    pattern: /(\w+)\s*=\s*request\.(?:json|form|args|data|files)\b/g,
    category: "http_request",
    extract_var: (m) => m[1],
  },
  // Environment variables
  {
    pattern: /(?:const|let|var)\s+(\w+)\s*=\s*process\.env\s*\.\s*\w+/g,
    category: "environment",
    extract_var: (m) => m[1],
  },
  {
    pattern: /(\w+)\s*=\s*os\.environ\s*(?:\[|\.get\()/g,
    category: "environment",
    extract_var: (m) => m[1],
  },
  // File read
  {
    pattern: /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:fs\.readFile(?:Sync)?|readFileSync)\s*\(/g,
    category: "file_read",
    extract_var: (m) => m[1],
  },
  {
    pattern: /(\w+)\s*=\s*(?:open\([^)]+\)\.read\(\)|Path\([^)]+\)\.read_text\(\))/g,
    category: "file_read",
    extract_var: (m) => m[1],
  },
  // Command line arguments
  {
    pattern: /(?:const|let|var)\s+(\w+)\s*=\s*process\.argv/g,
    category: "command_line",
    extract_var: (m) => m[1],
  },
  {
    pattern: /(\w+)\s*=\s*sys\.argv/g,
    category: "command_line",
    extract_var: (m) => m[1],
  },
  // User input
  {
    pattern: /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:readline|prompt)\s*\(/g,
    category: "user_input",
    extract_var: (m) => m[1],
  },
  {
    pattern: /(\w+)\s*=\s*input\s*\(/g,
    category: "user_input",
    extract_var: (m) => m[1],
  },
  // JSON/YAML deserialization
  {
    pattern: /(?:const|let|var)\s+(\w+)\s*=\s*JSON\.parse\s*\(/g,
    category: "deserialization",
    extract_var: (m) => m[1],
  },
];

// --- Sink Patterns ---

const SINK_PATTERNS: Array<{
  pattern: RegExp;
  category: TaintSinkCategory;
  extract_args: (match: RegExpExecArray) => string[];
}> = [
  // Command execution sinks
  {
    pattern: /(?:child_process\.)?\bexec(?:Sync)?\s*\(([^)]*)\)/g,
    category: "command_execution",
    extract_args: (m) => [m[1].trim()],
  },
  {
    pattern: /(?:child_process\.)?\bspawn(?:Sync)?\s*\(([^,)]*)/g,
    category: "command_execution",
    extract_args: (m) => [m[1].trim()],
  },
  {
    pattern: /os\.system\s*\(([^)]*)\)/g,
    category: "command_execution",
    extract_args: (m) => [m[1].trim()],
  },
  {
    pattern: /subprocess\.(?:call|run|Popen|check_output)\s*\(([^,)]*)/g,
    category: "command_execution",
    extract_args: (m) => [m[1].trim()],
  },
  // SQL query sinks
  {
    pattern: /\.(?:query|execute|raw)\s*\(([^)]*)\)/g,
    category: "sql_query",
    extract_args: (m) => [m[1].trim()],
  },
  // Code eval sinks
  {
    pattern: /\beval\s*\(([^)]*)\)/g,
    category: "code_eval",
    extract_args: (m) => [m[1].trim()],
  },
  {
    pattern: /new\s+Function\s*\(([^)]*)\)/g,
    category: "code_eval",
    extract_args: (m) => [m[1].trim()],
  },
  // File path access
  {
    pattern: /(?:fs\.(?:readFile|writeFile|unlink|rmdir|mkdir)(?:Sync)?|open)\s*\(([^,)]*)/g,
    category: "path_access",
    extract_args: (m) => [m[1].trim()],
  },
  // URL request (SSRF)
  {
    pattern: /(?:fetch|axios|got|request|http\.get|urllib\.request\.urlopen)\s*\(([^,)]*)/g,
    category: "url_request",
    extract_args: (m) => [m[1].trim()],
  },
  // Template render
  {
    pattern: /\.render\s*\(([^,)]*)/g,
    category: "template_render",
    extract_args: (m) => [m[1].trim()],
  },
  // Deserialization sinks (C12: unsafe deserialization)
  {
    pattern: /pickle\.loads?\s*\(([^)]*)\)/g,
    category: "deserialization",
    extract_args: (m) => [m[1].trim()],
  },
  {
    pattern: /yaml\.(?:load|unsafe_load)\s*\(([^)]*)\)/g,
    category: "deserialization",
    extract_args: (m) => [m[1].trim()],
  },
  {
    pattern: /(?:unserialize|deserialize)\s*\(([^)]*)\)/g,
    category: "deserialization",
    extract_args: (m) => [m[1].trim()],
  },
  // DNS resolution sinks (G7: DNS-based exfiltration)
  {
    pattern: /dns\.(?:resolve|resolve4|resolve6|lookup)\s*\(([^,)]*)/g,
    category: "url_request",
    extract_args: (m) => [m[1].trim()],
  },
];

// --- Sanitizer Patterns ---

const SANITIZER_PATTERNS: Array<{
  pattern: RegExp;
  protects_against: TaintSinkCategory[];
}> = [
  // Shell escaping
  {
    pattern: /(?:shell[Ee]scape|escapeShell|shellescape|shlex\.quote)\s*\(/,
    protects_against: ["command_execution"],
  },
  // execFile with array args (safe alternative to exec)
  {
    pattern: /execFile(?:Sync)?\s*\(/,
    protects_against: ["command_execution"],
  },
  // SQL parameterized queries
  {
    pattern: /\.(?:query|execute)\s*\([^,]+,\s*\[/,
    protects_against: ["sql_query"],
  },
  {
    pattern: /\.(?:query|execute)\s*\([^,]+,\s*\{/,
    protects_against: ["sql_query"],
  },
  // Path sanitization
  {
    pattern: /path\.(?:resolve|normalize|join)\s*\(/,
    protects_against: ["path_access"],
  },
  {
    pattern: /(?:realpath|sanitizePath|validatePath)\s*\(/,
    protects_against: ["path_access"],
  },
  // HTML escaping
  {
    pattern: /(?:escape[Hh]tml|sanitize[Hh]tml|DOMPurify\.sanitize|xss)\s*\(/,
    protects_against: ["html_output"],
  },
  // URL validation
  {
    pattern: /(?:new\s+URL|url\.parse|validateUrl|isValidUrl)\s*\(/,
    protects_against: ["url_request"],
  },
  // Input validation (generic)
  {
    pattern: /(?:zod|joi|yup|ajv|validator)\.(?:parse|validate|assert)/,
    protects_against: [
      "command_execution",
      "sql_query",
      "path_access",
      "code_eval",
      "url_request",
    ],
  },
  // Type checking / allowlist
  {
    pattern: /(?:typeof|instanceof|allowlist|whitelist|\.includes\(|\.has\()/,
    protects_against: ["command_execution", "code_eval"],
  },
];

// --- Propagation Extraction ---

/**
 * Extract variable assignments and data flow propagations from source code.
 * Tracks how data flows from one variable to another.
 */
function extractPropagations(source: string): TaintPropagation[] {
  const propagations: TaintPropagation[] = [];
  const lines = source.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Simple assignment: const x = y
    const assignMatch = line.match(
      /(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\b/
    );
    if (assignMatch) {
      propagations.push({
        from: assignMatch[2],
        to: assignMatch[1],
        line: lineNum,
        type: "assignment",
      });
    }

    // String concatenation/template: const x = `${y} ...`
    const templateMatch = line.match(
      /(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{(\w+)\}/
    );
    if (templateMatch) {
      propagations.push({
        from: templateMatch[2],
        to: templateMatch[1],
        line: lineNum,
        type: "string_concat",
      });
    }

    // String concatenation: const x = y + "..."
    const concatMatch = line.match(
      /(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*\+/
    );
    if (concatMatch) {
      propagations.push({
        from: concatMatch[2],
        to: concatMatch[1],
        line: lineNum,
        type: "string_concat",
      });
    }

    // Destructuring: const { a, b } = obj
    const destructMatch = line.match(
      /(?:const|let|var)\s+\{\s*([^}]+)\}\s*=\s*(\w+)/
    );
    if (destructMatch) {
      const vars = destructMatch[1].split(",").map((v) => v.trim().split(":")[0].trim());
      for (const v of vars) {
        if (v) {
          propagations.push({
            from: destructMatch[2],
            to: v,
            line: lineNum,
            type: "destructure",
          });
        }
      }
    }

    // Python assignment: x = y
    const pyAssign = line.match(/^(\w+)\s*=\s*(\w+)\s*$/);
    if (pyAssign) {
      propagations.push({
        from: pyAssign[2],
        to: pyAssign[1],
        line: lineNum,
        type: "assignment",
      });
    }
  }

  return propagations;
}

// --- Main Taint Analysis ---

/**
 * Perform taint analysis on source code.
 *
 * Algorithm:
 * 1. Extract all taint sources (untrusted input points)
 * 2. Extract all taint sinks (dangerous function calls)
 * 3. Extract variable propagations (assignments between variables)
 * 4. Extract sanitizers (functions that make data safe)
 * 5. For each sink, check if any argument is tainted:
 *    a. Direct use of source expression in sink argument
 *    b. Variable assigned from source, used in sink
 *    c. Variable propagated through chain from source to sink
 * 6. For each tainted flow, check if a sanitizer exists between source and sink
 *
 * Returns all unsanitized taint flows (real vulnerabilities)
 * and sanitized flows (informational — the developer handled it).
 */
export function analyzeTaint(source: string): TaintFlow[] {
  const lines = source.split("\n");
  const flows: TaintFlow[] = [];

  // Step 1: Extract sources
  const sources: TaintSource[] = [];
  for (const sp of SOURCE_PATTERNS) {
    let match: RegExpExecArray | null;
    sp.pattern.lastIndex = 0;
    while ((match = sp.pattern.exec(source)) !== null) {
      const line = source.substring(0, match.index).split("\n").length;
      const varName = sp.extract_var(match);
      sources.push({
        expression: varName || match[0],
        category: sp.category,
        line,
        pattern: sp.pattern.source,
      });
    }
  }

  // Step 2: Extract sinks
  const sinks: TaintSink[] = [];
  for (const sk of SINK_PATTERNS) {
    let match: RegExpExecArray | null;
    sk.pattern.lastIndex = 0;
    while ((match = sk.pattern.exec(source)) !== null) {
      const line = source.substring(0, match.index).split("\n").length;
      sinks.push({
        expression: match[0],
        category: sk.category,
        line,
        pattern: sk.pattern.source,
        arguments: sk.extract_args(match),
      });
    }
  }

  // Step 3: Extract propagations
  const propagations = extractPropagations(source);

  // Step 4: Extract sanitizers
  const sanitizers: Sanitizer[] = [];
  for (const san of SANITIZER_PATTERNS) {
    let match: RegExpExecArray | null;
    const regex = new RegExp(san.pattern.source, "g");
    while ((match = regex.exec(source)) !== null) {
      const line = source.substring(0, match.index).split("\n").length;
      sanitizers.push({
        expression: match[0],
        line,
        protects_against: san.protects_against,
      });
    }
  }

  // Step 5: Build taint map — which variables are tainted?
  const taintedVars = new Map<string, TaintSource>(); // varName → originating source
  for (const src of sources) {
    if (src.expression) {
      // Handle destructured variables (comma-separated)
      const vars = src.expression.split(",").map((v) => v.trim());
      for (const v of vars) {
        if (v) taintedVars.set(v, src);
      }
    }
  }

  // Propagate taint through assignments (fixed-point iteration)
  let changed = true;
  let iterations = 0;
  const maxIterations = 10; // Prevent infinite loops in cyclic assignments
  while (changed && iterations < maxIterations) {
    changed = false;
    iterations++;
    for (const prop of propagations) {
      if (taintedVars.has(prop.from) && !taintedVars.has(prop.to)) {
        taintedVars.set(prop.to, taintedVars.get(prop.from)!);
        changed = true;
      }
    }
  }

  // Step 6: Check each sink for tainted arguments
  for (const sink of sinks) {
    for (const arg of sink.arguments) {
      // Check if any tainted variable appears in the sink argument
      for (const [varName, originSource] of taintedVars) {
        // Match variable name as a word boundary in the argument
        const varRegex = new RegExp(`\\b${escapeRegex(varName)}\\b`);
        if (!varRegex.test(arg)) continue;

        // Check if argument is a string literal (not tainted)
        if (isStringLiteral(arg)) continue;

        // Build propagation chain
        const chain = buildPropagationChain(
          originSource.expression,
          varName,
          propagations
        );

        // Check for sanitizers between source and sink
        const sanitizer = findSanitizer(
          sanitizers,
          sink.category,
          originSource.line,
          sink.line
        );

        const confidence = computeFlowConfidence(
          originSource,
          sink,
          chain,
          sanitizer !== undefined
        );

        flows.push({
          source: originSource,
          propagation_chain: chain,
          sink,
          sanitized: sanitizer !== undefined,
          sanitizer,
          confidence,
        });
      }

      // Also check for direct inline source use in sink
      // e.g., exec(req.body.command) — source is used directly, no variable
      for (const sp of SOURCE_PATTERNS) {
        const inlineRegex = new RegExp(sp.pattern.source.replace(/\(\w\+\)/g, "\\w+"));
        if (inlineRegex.test(arg) && !isStringLiteral(arg)) {
          const sanitizer = findSanitizer(sanitizers, sink.category, sink.line - 5, sink.line);
          flows.push({
            source: {
              expression: arg,
              category: sp.category,
              line: sink.line,
              pattern: "inline_source_in_sink",
            },
            propagation_chain: [],
            sink,
            sanitized: sanitizer !== undefined,
            sanitizer,
            confidence: 0.9,
          });
        }
      }
    }
  }

  return flows;
}

// --- Helper Functions ---

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Check if an expression is a string literal (safe — not tainted) */
function isStringLiteral(expr: string): boolean {
  const trimmed = expr.trim();
  return (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith("`") && !trimmed.includes("${"))
  );
}

/** Build the propagation chain from source variable to sink variable */
function buildPropagationChain(
  sourceVar: string,
  sinkVar: string,
  propagations: TaintPropagation[]
): TaintPropagation[] {
  if (sourceVar === sinkVar) return [];

  // BFS from sourceVar to sinkVar through propagations
  const visited = new Set<string>();
  const queue: Array<{ var: string; path: TaintPropagation[] }> = [
    { var: sourceVar, path: [] },
  ];

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current.var)) continue;
    visited.add(current.var);

    for (const prop of propagations) {
      if (prop.from === current.var) {
        const newPath = [...current.path, prop];
        if (prop.to === sinkVar) return newPath;
        queue.push({ var: prop.to, path: newPath });
      }
    }
  }

  return []; // No chain found (might be direct use)
}

/** Find a sanitizer that protects the given sink category between source and sink lines */
function findSanitizer(
  sanitizers: Sanitizer[],
  sinkCategory: TaintSinkCategory,
  sourceLineMin: number,
  sinkLine: number
): Sanitizer | undefined {
  return sanitizers.find(
    (s) =>
      s.protects_against.includes(sinkCategory) &&
      s.line >= sourceLineMin &&
      s.line <= sinkLine
  );
}

/** Compute confidence score for a taint flow */
function computeFlowConfidence(
  source: TaintSource,
  sink: TaintSink,
  chain: TaintPropagation[],
  sanitized: boolean
): number {
  let confidence = 0.7; // Base confidence

  // Higher confidence for direct HTTP request → command execution flows
  if (source.category === "http_request" && sink.category === "command_execution") {
    confidence += 0.15;
  }

  // Short propagation chains are more reliable
  if (chain.length <= 1) confidence += 0.1;
  if (chain.length > 3) confidence -= 0.15;

  // Sanitized flows have lower finding confidence (they're handled)
  if (sanitized) confidence -= 0.3;

  // String concatenation in chain increases confidence (common injection pattern)
  if (chain.some((p) => p.type === "string_concat")) {
    confidence += 0.1;
  }

  return Math.min(1.0, Math.max(0.1, confidence));
}

/**
 * Get unsanitized taint flows only (the real vulnerabilities).
 */
export function getUnsanitizedFlows(source: string): TaintFlow[] {
  return analyzeTaint(source).filter((f) => !f.sanitized);
}
