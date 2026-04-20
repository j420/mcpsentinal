/**
 * Location — structured position a reviewer can navigate to.
 *
 * Introduced in Phase 1, Chunk 1.1 (Rule Standard v2). Prior to this, every
 * evidence link carried a `location: string` — prose like "in the request
 * handler at line 42" or "MCP server tools/list response". That was fine for
 * debugging but useless for auditors: a regulator cannot paste "tool approval
 * dialog" into an editor.
 *
 * Every v2 EvidenceLink and VerificationStep carries a Location. Legacy v1
 * rules still pass a plain string (backward compat), which the evidence
 * renderer coerces to a kind:"synthetic" Location.
 *
 * The 10 kinds cover the MCP attack surface that evidence can cite:
 *
 *   - source       file:line:col — TypeScript/Python source position
 *   - tool         MCP tool name — identifies the tool as a scope
 *   - parameter    tool + parameter path — parameter within a tool schema
 *   - schema       tool + RFC6901 JSON pointer into input/output schema
 *   - dependency   ecosystem + package name + version
 *   - config       config file + JSON pointer
 *   - initialize   which field of the initialize handshake
 *   - resource     MCP resource URI + optional field
 *   - prompt       MCP prompt name + optional field
 *   - capability   declared_capabilities key
 *
 * Design notes:
 *
 *   - `col` is optional because some extractors (line-only grep, error
 *     messages without column info) cannot recover columns. Callers MUST
 *     leave it undefined, not pass 0.
 *
 *   - `length` on the source kind is optional — used when a span is known
 *     (an entire expression, a quoted string). Omit for point locations.
 *
 *   - `json_pointer` is RFC 6901 for deterministic schema refs: e.g.
 *     "/properties/cmd/default" rather than prose "the cmd default value".
 *
 *   - `parameter_path` is a JSON path expression (JSONPath subset), e.g.
 *     "input_schema.properties.cmd" — one level of abstraction above a
 *     JSON pointer, meant for human display alongside the tool name.
 */

export type Location =
  | {
      kind: "source";
      file: string;
      line: number;
      col?: number;
      length?: number;
    }
  | { kind: "tool"; tool_name: string }
  | { kind: "parameter"; tool_name: string; parameter_path: string }
  | { kind: "schema"; tool_name: string; json_pointer: string }
  | {
      kind: "dependency";
      ecosystem: "npm" | "pypi" | "go" | "rubygems" | "cargo";
      name: string;
      version: string;
    }
  | { kind: "config"; file: string; json_pointer: string }
  | {
      kind: "initialize";
      field: "server_name" | "server_version" | "instructions";
    }
  | {
      kind: "resource";
      uri: string;
      field?: "name" | "description" | "uri" | "mimeType";
    }
  | {
      kind: "prompt";
      name: string;
      field?: "name" | "description" | "argument";
    }
  | {
      kind: "capability";
      capability:
        | "tools"
        | "resources"
        | "prompts"
        | "sampling"
        | "logging";
    };

/**
 * Render a Location (or a legacy prose string) into a single-line human label.
 *
 * Used by:
 *   - log lines, API responses, badge SVGs that carry the finding inline;
 *   - the EvidenceChainBuilder when it interpolates a location into a
 *     confidence-factor rationale string.
 *
 * A structured Location never loses information — callers that need the
 * machine-readable form should pick the Location off the link directly.
 */
export function renderLocation(loc: Location | string): string {
  if (typeof loc === "string") return loc;
  switch (loc.kind) {
    case "source": {
      const pos = loc.col !== undefined ? `${loc.line}:${loc.col}` : `${loc.line}`;
      return loc.length !== undefined
        ? `${loc.file}:${pos}+${loc.length}`
        : `${loc.file}:${pos}`;
    }
    case "tool":
      return `tool ${loc.tool_name}`;
    case "parameter":
      return `tool ${loc.tool_name} parameter ${loc.parameter_path}`;
    case "schema":
      return `tool ${loc.tool_name} schema ${loc.json_pointer}`;
    case "dependency":
      return `${loc.ecosystem}:${loc.name}@${loc.version}`;
    case "config":
      return `${loc.file}${loc.json_pointer}`;
    case "initialize":
      return `initialize.${loc.field}`;
    case "resource":
      return loc.field ? `resource ${loc.uri}#${loc.field}` : `resource ${loc.uri}`;
    case "prompt":
      return loc.field ? `prompt ${loc.name}#${loc.field}` : `prompt ${loc.name}`;
    case "capability":
      return `capability:${loc.capability}`;
  }
}

/** Narrowing helper — true if the argument is a structured Location, not a prose string. */
export function isLocation(x: unknown): x is Location {
  return (
    typeof x === "object" &&
    x !== null &&
    "kind" in x &&
    typeof (x as { kind: unknown }).kind === "string"
  );
}
