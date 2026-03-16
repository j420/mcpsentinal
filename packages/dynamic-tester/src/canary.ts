/**
 * Canary input generator.
 *
 * Generates SAFE, read-only test inputs for each tool based on its
 * JSON Schema. All values are clearly identifiable as sentinel canary
 * values so they can never be confused with real user data.
 *
 * Safety invariants:
 *   - String values are never valid shell commands
 *   - Path values are always within /tmp/mcp-sentinel-canary/
 *   - URL values point to a localhost canary endpoint that always returns 200
 *   - Boolean values default to false (safer for permission-like flags)
 *   - Numeric values default to 0 or 1 (minimal)
 */
import type { CanaryInput } from "./types.js";

const CANARY_TAG = "mcp-sentinel-canary";
const CANARY_PATH = `/tmp/${CANARY_TAG}/test.txt`;
const CANARY_URL = `http://127.0.0.1:0/${CANARY_TAG}`;
const CANARY_STRING = `${CANARY_TAG}-test-value`;
const CANARY_SQL = `SELECT 1 -- ${CANARY_TAG}`;

type JsonSchema = Record<string, unknown>;

/**
 * Generate a safe canary input object for a tool, based on its input_schema.
 */
export function generateCanaryInput(
  toolName: string,
  inputSchema: JsonSchema | null
): CanaryInput {
  if (!inputSchema || !inputSchema.properties) {
    return {
      tool_name: toolName,
      input: {},
      coverage: [],
    };
  }

  const properties = inputSchema.properties as Record<string, JsonSchema>;
  const required = Array.isArray(inputSchema.required)
    ? (inputSchema.required as string[])
    : [];

  const input: Record<string, unknown> = {};
  const coverage: CanaryInput["coverage"] = [];

  for (const [paramName, paramSchema] of Object.entries(properties)) {
    // Only fill required params + params with dangerous names
    const isDangerous = DANGEROUS_PARAM_NAMES.some((p) => paramName.toLowerCase().includes(p));
    if (!required.includes(paramName) && !isDangerous) continue;

    const value = generateParamValue(paramName, paramSchema, coverage);
    input[paramName] = value;
  }

  return { tool_name: toolName, input, coverage };
}

function generateParamValue(
  name: string,
  schema: JsonSchema,
  coverage: CanaryInput["coverage"]
): unknown {
  const type = schema.type as string | undefined;
  const lowerName = name.toLowerCase();

  // Path parameters → safe /tmp canary path
  if (
    lowerName.includes("path") ||
    lowerName.includes("file") ||
    lowerName.includes("dir")
  ) {
    if (!coverage.includes("path")) coverage.push("path");
    return CANARY_PATH;
  }

  // URL parameters → localhost canary
  if (lowerName.includes("url") || lowerName.includes("endpoint") || lowerName.includes("uri")) {
    if (!coverage.includes("url")) coverage.push("url");
    return CANARY_URL;
  }

  // SQL / query parameters → safe SELECT 1
  if (lowerName.includes("sql") || lowerName.includes("query")) {
    if (!coverage.includes("sql")) coverage.push("sql");
    return CANARY_SQL;
  }

  // Command parameters → safe echo (no side effects)
  if (lowerName.includes("command") || lowerName.includes("cmd")) {
    if (!coverage.includes("command")) coverage.push("command");
    return `echo ${CANARY_TAG}`;
  }

  // Schema-driven fallback
  switch (type) {
    case "string": {
      // Respect enum if present
      if (Array.isArray(schema.enum) && schema.enum.length > 0) {
        return schema.enum[0];
      }
      if (!coverage.includes("string")) coverage.push("string");
      return CANARY_STRING;
    }
    case "integer":
    case "number": {
      if (!coverage.includes("number")) coverage.push("number");
      const min = typeof schema.minimum === "number" ? schema.minimum : 0;
      const max = typeof schema.maximum === "number" ? schema.maximum : 1;
      return Math.max(min, Math.min(max, 1));
    }
    case "boolean": {
      if (!coverage.includes("boolean")) coverage.push("boolean");
      // Default to false — safer (avoids enabling destructive flags)
      return schema.default === false ? false : false;
    }
    case "array": {
      if (!coverage.includes("array")) coverage.push("array");
      return [];
    }
    case "object": {
      if (!coverage.includes("object")) coverage.push("object");
      return {};
    }
    default:
      return CANARY_STRING;
  }
}

// Parameter names that indicate dangerous operations — we always fill these
// so the probe actually exercises the risky code path
const DANGEROUS_PARAM_NAMES = [
  "path", "file", "dir", "url", "endpoint", "uri",
  "sql", "query", "command", "cmd", "script",
  "key", "token", "secret", "credential",
];

/**
 * Generate injection probe payloads for a parameter.
 * These are specifically designed to test for injection vulnerabilities.
 *
 * All payloads are chosen to be detectable (echo a unique token) but
 * non-destructive (no rm, no curl to real endpoints, no write outside /tmp).
 */
export interface InjectionPayload {
  type: "command_injection" | "path_traversal" | "sql_injection" | "xss" | "ssti";
  value: string;
  /** Expected in output if vulnerable */
  canary_token: string;
}

export function getInjectionPayloads(paramName: string): InjectionPayload[] {
  const lowerName = paramName.toLowerCase();
  const payloads: InjectionPayload[] = [];

  if (lowerName.includes("path") || lowerName.includes("file") || lowerName.includes("dir")) {
    payloads.push({
      type: "path_traversal",
      value: "/tmp/mcp-sentinel-canary/../../../tmp/mcp-sentinel-canary/test.txt",
      canary_token: "mcp-sentinel-canary",
    });
    payloads.push({
      type: "path_traversal",
      value: "/tmp/mcp-sentinel-canary/%2e%2e%2f%2e%2e%2ftmp/test.txt",
      canary_token: "mcp-sentinel-canary",
    });
  }

  if (lowerName.includes("command") || lowerName.includes("cmd")) {
    payloads.push({
      type: "command_injection",
      value: `echo mcp-sentinel-cmd-canary`,
      canary_token: "mcp-sentinel-cmd-canary",
    });
    payloads.push({
      type: "command_injection",
      value: `echo mcp-sentinel-cmd-canary; echo safe`,
      canary_token: "mcp-sentinel-cmd-canary",
    });
  }

  if (lowerName.includes("sql") || lowerName.includes("query")) {
    payloads.push({
      type: "sql_injection",
      value: `' OR '1'='1' -- mcp-sentinel-sql-canary`,
      canary_token: "mcp-sentinel-sql-canary",
    });
    payloads.push({
      type: "sql_injection",
      value: `1; SELECT 'mcp-sentinel-sql-canary' --`,
      canary_token: "mcp-sentinel-sql-canary",
    });
  }

  if (lowerName.includes("url") || lowerName.includes("endpoint")) {
    // No real network — point to localhost
    payloads.push({
      type: "xss",
      value: `javascript:void('mcp-sentinel-xss-canary')`,
      canary_token: "mcp-sentinel-xss-canary",
    });
  }

  if (lowerName.includes("template") || lowerName.includes("content")) {
    payloads.push({
      type: "ssti",
      value: `{{7*7}} mcp-sentinel-ssti-canary`,
      canary_token: "mcp-sentinel-ssti-canary",
    });
    payloads.push({
      type: "ssti",
      value: `<%= 'mcp-sentinel-ssti-canary' %>`,
      canary_token: "mcp-sentinel-ssti-canary",
    });
  }

  return payloads;
}
