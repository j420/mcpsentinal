/**
 * Schema Structural Inference Engine
 *
 * Infers tool capabilities from JSON Schema STRUCTURE — not description text.
 *
 * Why this matters:
 * Current capability classification matches description keywords:
 *   "reads sensitive user data from private database" → reads-private-data
 *   "Looks up account info" → MISSES (no keyword match)
 *
 * Schema inference analyzes the actual interface contract:
 *   { query: { type: "string" } } + no constraints → data access (broad)
 *   { path: { type: "string", pattern: "^/safe/" } } → filesystem access (constrained)
 *   { url: { type: "string", format: "uri" } } → network access
 *   { command: { type: "string" } } → code execution (!!)
 *
 * The schema is the truth. Descriptions lie. Schemas define what the tool
 * actually accepts.
 *
 * Analysis dimensions:
 * 1. Parameter Semantic Classification — what kind of data does each param accept?
 * 2. Constraint Density — how constrained is the input space?
 * 3. Attack Surface Score — how much unconstrained input surface exists?
 * 4. Capability Inference — what can this tool DO based on its input contract?
 * 5. Risk Signal Aggregation — combine structural signals into capability assessment
 */

/** Semantic type of a parameter inferred from schema structure */
export type ParameterSemanticType =
  | "filesystem_path"
  | "url_endpoint"
  | "sql_expression"
  | "shell_command"
  | "code_expression"
  | "credential"
  | "data_content"
  | "identifier"
  | "configuration"
  | "numeric_value"
  | "boolean_flag"
  | "structured_object"
  | "generic_string";

/** Constraint analysis for a single parameter */
export interface ParameterConstraintProfile {
  name: string;
  semantic_type: ParameterSemanticType;
  /** How constrained is this parameter? 0.0 = unconstrained, 1.0 = fully constrained */
  constraint_density: number;
  /** Individual constraint signals */
  constraints: {
    has_enum: boolean;
    has_pattern: boolean;
    has_max_length: boolean;
    has_min_length: boolean;
    has_format: boolean;
    has_default: boolean;
    is_required: boolean;
    is_boolean: boolean;
    is_number: boolean;
    is_array: boolean;
    is_object: boolean;
    additional_properties_allowed: boolean;
  };
  /** Risk contribution (0.0 = safe, 1.0 = maximum risk) */
  risk_contribution: number;
  /** Evidence for the classification */
  evidence: string;
}

/** Inferred capability with structural evidence */
export interface InferredCapability {
  capability:
    | "filesystem_access"
    | "network_access"
    | "database_access"
    | "code_execution"
    | "credential_handling"
    | "data_transformation"
    | "configuration_mutation"
    | "destructive_operation";
  /** Confidence (0.0-1.0) based purely on schema structure */
  confidence: number;
  /** Which parameters contributed to this inference */
  contributing_parameters: string[];
  /** Structural evidence (what in the schema led to this conclusion) */
  evidence: string[];
}

/** Complete schema analysis result for a tool */
export interface SchemaAnalysisResult {
  tool_name: string;
  /** Per-parameter profiles */
  parameters: ParameterConstraintProfile[];
  /** Inferred capabilities */
  capabilities: InferredCapability[];
  /** Overall attack surface score (0.0 = minimal, 1.0 = maximum) */
  attack_surface_score: number;
  /** Constraint density across all parameters (0.0 = none, 1.0 = fully constrained) */
  overall_constraint_density: number;
  /** Human-readable summary */
  summary: string;
}

// ─── Parameter Semantic Classification ──────────────────────────────────────

/**
 * Semantic classification rules, ordered by specificity.
 * Each rule checks parameter name AND schema properties.
 * The first match wins (most specific first).
 */
const SEMANTIC_RULES: Array<{
  test: (name: string, schema: Record<string, unknown>) => boolean;
  type: ParameterSemanticType;
  risk_base: number;
}> = [
  // Shell command — highest risk
  {
    test: (name) => /^(command|cmd|shell|exec|script|program|run)$/i.test(name),
    type: "shell_command",
    risk_base: 0.95,
  },
  // Code expression
  {
    test: (name, schema) =>
      /^(code|expression|eval|template|formula|query_code)$/i.test(name) ||
      (name === "query" && !!schema.description?.toString().toLowerCase().includes("code")),
    type: "code_expression",
    risk_base: 0.9,
  },
  // SQL expression
  {
    test: (name) => /^(query|sql|statement|where_clause|filter_expression)$/i.test(name),
    type: "sql_expression",
    risk_base: 0.8,
  },
  // Credential
  {
    test: (name) =>
      /^(password|token|secret|api_key|apikey|auth|credential|bearer|access_token|private_key)$/i.test(name),
    type: "credential",
    risk_base: 0.85,
  },
  // Filesystem path
  {
    test: (name, schema) =>
      /^(path|file|filepath|file_path|filename|dir|directory|folder|location)$/i.test(name) ||
      (schema.format === "path") ||
      (typeof schema.pattern === "string" && /[/\\]/.test(schema.pattern)),
    type: "filesystem_path",
    risk_base: 0.7,
  },
  // URL endpoint
  {
    test: (name, schema) =>
      /^(url|uri|endpoint|href|link|webhook|callback_url|redirect)$/i.test(name) ||
      schema.format === "uri" ||
      schema.format === "url",
    type: "url_endpoint",
    risk_base: 0.65,
  },
  // Configuration
  {
    test: (name) =>
      /^(config|setting|option|preference|env|environment|mode|level|flag)$/i.test(name),
    type: "configuration",
    risk_base: 0.4,
  },
  // Identifier (low risk — constrained reference)
  {
    test: (name) => /^(id|name|slug|key|ref|handle|label|tag|type|category|status)$/i.test(name),
    type: "identifier",
    risk_base: 0.15,
  },
  // Boolean flag (minimal risk)
  {
    test: (_, schema) => schema.type === "boolean",
    type: "boolean_flag",
    risk_base: 0.05,
  },
  // Number (low risk)
  {
    test: (_, schema) => schema.type === "number" || schema.type === "integer",
    type: "numeric_value",
    risk_base: 0.1,
  },
  // Structured object
  {
    test: (_, schema) => schema.type === "object" && !!schema.properties,
    type: "structured_object",
    risk_base: 0.3,
  },
  // Data content (medium risk — arbitrary text)
  {
    test: (name) =>
      /^(content|text|body|message|data|payload|input|value|description|comment|note)$/i.test(name),
    type: "data_content",
    risk_base: 0.45,
  },
];

// ─── Main Analysis ──────────────────────────────────────────────────────────

/**
 * Analyze a tool's JSON Schema to infer capabilities from structure.
 */
export function analyzeSchema(
  toolName: string,
  inputSchema: Record<string, unknown> | null,
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
  } | null
): SchemaAnalysisResult {
  if (!inputSchema || !inputSchema.properties) {
    return {
      tool_name: toolName,
      parameters: [],
      capabilities: [],
      attack_surface_score: 0,
      overall_constraint_density: 1.0,
      summary: "No input schema — cannot analyze",
    };
  }

  const props = inputSchema.properties as Record<string, Record<string, unknown>>;
  const required = new Set((inputSchema.required as string[]) || []);

  // Step 1: Classify each parameter
  const parameters: ParameterConstraintProfile[] = Object.entries(props).map(
    ([name, schema]) => classifyParameter(name, schema, required.has(name))
  );

  // Step 2: Infer capabilities from parameter profiles
  const capabilities = inferCapabilities(parameters, annotations);

  // Step 3: Compute attack surface score
  const attack_surface_score = computeAttackSurface(parameters);

  // Step 4: Compute overall constraint density
  const overall_constraint_density =
    parameters.length > 0
      ? parameters.reduce((sum, p) => sum + p.constraint_density, 0) / parameters.length
      : 1.0;

  // Step 5: Build summary
  const highRiskParams = parameters.filter((p) => p.risk_contribution > 0.6);
  const summary =
    `${parameters.length} parameters analyzed. ` +
    `Attack surface: ${(attack_surface_score * 100).toFixed(0)}%. ` +
    `Constraint density: ${(overall_constraint_density * 100).toFixed(0)}%. ` +
    (highRiskParams.length > 0
      ? `High-risk parameters: ${highRiskParams.map((p) => `${p.name} (${p.semantic_type})`).join(", ")}.`
      : "No high-risk parameters detected.");

  return {
    tool_name: toolName,
    parameters,
    capabilities,
    attack_surface_score,
    overall_constraint_density,
    summary,
  };
}

// ─── Parameter Classification ───────────────────────────────────────────────

function classifyParameter(
  name: string,
  schema: Record<string, unknown>,
  isRequired: boolean
): ParameterConstraintProfile {
  // Determine semantic type
  let semantic_type: ParameterSemanticType = "generic_string";
  let risk_base = 0.3; // default risk for unknown string params

  for (const rule of SEMANTIC_RULES) {
    if (rule.test(name, schema)) {
      semantic_type = rule.type;
      risk_base = rule.risk_base;
      break;
    }
  }

  // Analyze constraints
  const constraints = {
    has_enum: Array.isArray(schema.enum) && schema.enum.length > 0,
    has_pattern: typeof schema.pattern === "string",
    has_max_length: typeof schema.maxLength === "number",
    has_min_length: typeof schema.minLength === "number",
    has_format: typeof schema.format === "string",
    has_default: schema.default !== undefined,
    is_required: isRequired,
    is_boolean: schema.type === "boolean",
    is_number: schema.type === "number" || schema.type === "integer",
    is_array: schema.type === "array",
    is_object: schema.type === "object",
    additional_properties_allowed:
      schema.type === "object" && schema.additionalProperties !== false,
  };

  // Compute constraint density (0 = unconstrained, 1 = fully constrained)
  let constraintScore = 0;
  let constraintTotal = 0;

  if (schema.type === "string") {
    constraintTotal += 4; // enum, pattern, maxLength, format
    if (constraints.has_enum) constraintScore += 2; // enum is strong
    if (constraints.has_pattern) constraintScore += 1.5;
    if (constraints.has_max_length) constraintScore += 0.5;
    if (constraints.has_format) constraintScore += 1;
  } else if (constraints.is_number) {
    constraintTotal += 2;
    if (typeof schema.minimum === "number") constraintScore += 1;
    if (typeof schema.maximum === "number") constraintScore += 1;
  } else if (constraints.is_boolean) {
    constraintScore = 1;
    constraintTotal = 1; // booleans are inherently constrained
  } else if (constraints.is_object) {
    constraintTotal += 2;
    if (!constraints.additional_properties_allowed) constraintScore += 1;
    if (schema.properties) constraintScore += 0.5;
  }

  const constraint_density = constraintTotal > 0 ? constraintScore / constraintTotal : 0.5;

  // Risk contribution: base risk modulated by constraint density
  // High constraints reduce risk; no constraints amplify risk
  const risk_contribution = risk_base * (1 - constraint_density * 0.7);

  // Build evidence string
  const constraintList: string[] = [];
  if (constraints.has_enum)
    constraintList.push(`enum[${(schema.enum as unknown[]).length} values]`);
  if (constraints.has_pattern) constraintList.push(`pattern: ${schema.pattern}`);
  if (constraints.has_max_length) constraintList.push(`maxLength: ${schema.maxLength}`);
  if (constraints.has_format) constraintList.push(`format: ${schema.format}`);
  if (constraints.is_boolean) constraintList.push("boolean (inherently safe)");
  if (constraints.is_number) constraintList.push("numeric");

  const evidence =
    `${name}: ${semantic_type} (type=${schema.type || "any"})` +
    (constraintList.length > 0 ? ` [${constraintList.join(", ")}]` : " [NO CONSTRAINTS]") +
    ` → risk=${(risk_contribution * 100).toFixed(0)}%`;

  return {
    name,
    semantic_type,
    constraint_density,
    constraints,
    risk_contribution,
    evidence,
  };
}

// ─── Capability Inference ───────────────────────────────────────────────────

function inferCapabilities(
  parameters: ParameterConstraintProfile[],
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean } | null
): InferredCapability[] {
  const capabilities: InferredCapability[] = [];

  // Group parameters by semantic type
  const byType = new Map<ParameterSemanticType, ParameterConstraintProfile[]>();
  for (const param of parameters) {
    if (!byType.has(param.semantic_type)) byType.set(param.semantic_type, []);
    byType.get(param.semantic_type)!.push(param);
  }

  // Filesystem access
  const fsPaths = byType.get("filesystem_path") || [];
  if (fsPaths.length > 0) {
    const unconstrained = fsPaths.filter((p) => p.constraint_density < 0.3);
    capabilities.push({
      capability: "filesystem_access",
      confidence: Math.min(0.95, 0.5 + fsPaths.length * 0.15 + unconstrained.length * 0.2),
      contributing_parameters: fsPaths.map((p) => p.name),
      evidence: [
        `${fsPaths.length} filesystem path parameter(s): ${fsPaths.map((p) => p.name).join(", ")}`,
        unconstrained.length > 0
          ? `${unconstrained.length} UNCONSTRAINED (no pattern/enum) — accepts arbitrary paths`
          : "All path parameters have constraints (pattern or enum)",
      ],
    });
  }

  // Network access
  const urls = byType.get("url_endpoint") || [];
  if (urls.length > 0) {
    capabilities.push({
      capability: "network_access",
      confidence: Math.min(0.95, 0.5 + urls.length * 0.2),
      contributing_parameters: urls.map((p) => p.name),
      evidence: [
        `${urls.length} URL parameter(s): ${urls.map((p) => p.name).join(", ")}`,
        urls.some((u) => u.constraints.has_format)
          ? "Has format:uri validation"
          : "NO URL format validation — accepts arbitrary strings as URLs",
      ],
    });
  }

  // Database access
  const sqls = byType.get("sql_expression") || [];
  if (sqls.length > 0) {
    capabilities.push({
      capability: "database_access",
      confidence: Math.min(0.95, 0.6 + sqls.length * 0.2),
      contributing_parameters: sqls.map((p) => p.name),
      evidence: [
        `${sqls.length} SQL/query parameter(s): ${sqls.map((p) => p.name).join(", ")}`,
        sqls.some((s) => s.constraint_density < 0.2)
          ? "UNCONSTRAINED query parameter — SQL injection surface"
          : "Query parameters have some constraints",
      ],
    });
  }

  // Code execution
  const cmds = [
    ...(byType.get("shell_command") || []),
    ...(byType.get("code_expression") || []),
  ];
  if (cmds.length > 0) {
    capabilities.push({
      capability: "code_execution",
      confidence: Math.min(0.99, 0.7 + cmds.length * 0.15),
      contributing_parameters: cmds.map((p) => p.name),
      evidence: [
        `${cmds.length} command/code parameter(s): ${cmds.map((p) => `${p.name} (${p.semantic_type})`).join(", ")}`,
        "Parameters that accept shell commands or code expressions enable arbitrary execution",
      ],
    });
  }

  // Credential handling
  const creds = byType.get("credential") || [];
  if (creds.length > 0) {
    capabilities.push({
      capability: "credential_handling",
      confidence: Math.min(0.95, 0.6 + creds.length * 0.2),
      contributing_parameters: creds.map((p) => p.name),
      evidence: [
        `${creds.length} credential parameter(s): ${creds.map((p) => p.name).join(", ")}`,
      ],
    });
  }

  // Destructive operation (from annotations)
  if (annotations?.destructiveHint === true) {
    capabilities.push({
      capability: "destructive_operation",
      confidence: 0.95,
      contributing_parameters: [],
      evidence: [
        "Tool declares destructiveHint: true in annotations",
        "This is an explicit declaration by the server author",
      ],
    });
  }

  // Data transformation: has content input params but no dangerous types
  const dataParams = byType.get("data_content") || [];
  if (dataParams.length > 0 && cmds.length === 0 && sqls.length === 0) {
    capabilities.push({
      capability: "data_transformation",
      confidence: 0.5 + dataParams.length * 0.1,
      contributing_parameters: dataParams.map((p) => p.name),
      evidence: [
        `${dataParams.length} data content parameter(s) with no command/SQL parameters`,
        "Suggests data processing without execution capabilities",
      ],
    });
  }

  // Configuration mutation
  const configs = byType.get("configuration") || [];
  if (configs.length > 0) {
    capabilities.push({
      capability: "configuration_mutation",
      confidence: 0.4 + configs.length * 0.15,
      contributing_parameters: configs.map((p) => p.name),
      evidence: [
        `${configs.length} configuration parameter(s): ${configs.map((p) => p.name).join(", ")}`,
      ],
    });
  }

  return capabilities;
}

// ─── Attack Surface Computation ─────────────────────────────────────────────

/**
 * Compute overall attack surface score.
 *
 * Based on:
 * - Number of high-risk unconstrained parameters
 * - Proportion of string params without validation
 * - Presence of dangerous semantic types
 */
function computeAttackSurface(parameters: ParameterConstraintProfile[]): number {
  if (parameters.length === 0) return 0;

  // Weighted sum of risk contributions
  const totalRisk = parameters.reduce((sum, p) => sum + p.risk_contribution, 0);

  // Normalize: more parameters = more surface, but diminishing returns
  const paramFactor = Math.log2(parameters.length + 1) / Math.log2(20); // log-scaled
  const avgRisk = totalRisk / parameters.length;

  // Count unconstrained dangerous params (no enum, no pattern, no maxLength)
  const unconstrainedDangerous = parameters.filter(
    (p) => p.risk_contribution > 0.5 && p.constraint_density < 0.2
  ).length;

  const score =
    avgRisk * 0.4 +
    paramFactor * 0.2 +
    Math.min(1.0, unconstrainedDangerous * 0.25) * 0.4;

  return Math.min(1.0, Math.max(0.0, score));
}

/**
 * Analyze multiple tools and infer cross-tool relationships.
 * Returns tool-level analysis plus cross-tool patterns.
 */
export function analyzeToolSet(
  tools: Array<{
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
    annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean } | null;
  }>
): {
  tools: SchemaAnalysisResult[];
  cross_tool_patterns: CrossToolPattern[];
} {
  const results = tools.map((t) =>
    analyzeSchema(t.name, t.input_schema, t.annotations)
  );

  const cross_tool_patterns = detectCrossToolPatterns(results);

  return { tools: results, cross_tool_patterns };
}

/** A dangerous pattern detected across multiple tools */
export interface CrossToolPattern {
  type: "lethal_trifecta" | "exfiltration_chain" | "credential_exposure" | "unrestricted_access";
  tools: string[];
  confidence: number;
  evidence: string;
}

function detectCrossToolPatterns(results: SchemaAnalysisResult[]): CrossToolPattern[] {
  const patterns: CrossToolPattern[] = [];

  // Collect capabilities across all tools
  const capMap = new Map<string, SchemaAnalysisResult[]>();
  for (const result of results) {
    for (const cap of result.capabilities) {
      const key = cap.capability;
      if (!capMap.has(key)) capMap.set(key, []);
      capMap.get(key)!.push(result);
    }
  }

  // Lethal trifecta: database/filesystem access + network access + any ingestion
  const hasDataAccess = capMap.has("database_access") || capMap.has("filesystem_access");
  const hasNetwork = capMap.has("network_access");
  const hasCredentials = capMap.has("credential_handling");

  if (hasDataAccess && hasNetwork) {
    const dataTools = [
      ...(capMap.get("database_access") || []),
      ...(capMap.get("filesystem_access") || []),
    ];
    const networkTools = capMap.get("network_access") || [];

    const confidence = Math.min(
      Math.max(...dataTools.flatMap((t) => t.capabilities.map((c) => c.confidence))),
      Math.max(...networkTools.flatMap((t) => t.capabilities.map((c) => c.confidence)))
    );

    patterns.push({
      type: "lethal_trifecta",
      tools: [...new Set([...dataTools, ...networkTools].map((t) => t.tool_name))],
      confidence,
      evidence:
        `Data access tools: [${dataTools.map((t) => t.tool_name).join(", ")}] ` +
        `+ Network tools: [${networkTools.map((t) => t.tool_name).join(", ")}]. ` +
        `Schema structural analysis confirms both capabilities ` +
        `(not keyword matching — parameter types prove data access and URL acceptance).`,
    });
  }

  // Credential exposure: credential handling + network access
  if (hasCredentials && hasNetwork) {
    const credTools = capMap.get("credential_handling") || [];
    const networkTools = capMap.get("network_access") || [];
    patterns.push({
      type: "credential_exposure",
      tools: [...new Set([...credTools, ...networkTools].map((t) => t.tool_name))],
      confidence: 0.8,
      evidence:
        `Credential parameters in [${credTools.map((t) => t.tool_name).join(", ")}] ` +
        `coexist with network URL parameters in [${networkTools.map((t) => t.tool_name).join(", ")}]. ` +
        `Credentials can flow to network endpoints.`,
    });
  }

  // Unrestricted access: high attack surface + code execution
  const codeExec = capMap.get("code_execution") || [];
  for (const tool of codeExec) {
    if (tool.attack_surface_score > 0.6) {
      patterns.push({
        type: "unrestricted_access",
        tools: [tool.tool_name],
        confidence: tool.attack_surface_score,
        evidence:
          `Tool "${tool.tool_name}" has code execution capability ` +
          `with ${(tool.attack_surface_score * 100).toFixed(0)}% attack surface score. ` +
          `${tool.summary}`,
      });
    }
  }

  return patterns;
}
