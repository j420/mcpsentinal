import { createHash } from "crypto";

/** Represents a single tool's cryptographic fingerprint */
export interface ToolFingerprint {
  /** Tool name */
  name: string;
  /** SHA-256 hash of canonical tool representation */
  hash: string;
  /** Individual field hashes for granular diff */
  field_hashes: {
    name: string;
    description: string;
    schema: string;
    annotations: string;
  };
}

/** Complete server tool surface fingerprint */
export interface ServerToolPin {
  /** SHA-256 hash of ALL tools combined (order-independent) */
  composite_hash: string;
  /** Individual tool fingerprints */
  tools: ToolFingerprint[];
  /** ISO timestamp when pin was created */
  pinned_at: string;
  /** Number of tools at pin time */
  tool_count: number;
}

/**
 * Compare two server pins and return a structured diff.
 * This is the core of rug-pull detection.
 */
export interface ToolPinDiff {
  /** Overall: did anything change? */
  changed: boolean;
  /** Tools added since last pin */
  added: ToolFingerprint[];
  /** Tools removed since last pin */
  removed: ToolFingerprint[];
  /** Tools whose hash changed (same name, different content) */
  modified: Array<{
    name: string;
    previous_hash: string;
    current_hash: string;
    /** Which specific fields changed */
    changed_fields: Array<"description" | "schema" | "annotations">;
  }>;
  /** Tools that stayed exactly the same */
  unchanged: number;
}

/**
 * Recursively sort all object keys and produce a deterministic JSON string.
 * Arrays are preserved in order (array element order is semantically meaningful).
 * Null/undefined values are normalized to null.
 */
function canonicalStringify(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalStringify(item));
    return `[${items.join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const entries = sortedKeys.map(
    (key) => `${JSON.stringify(key)}:${canonicalStringify(obj[key])}`
  );
  return `{${entries.join(",")}}`;
}

/** SHA-256 hash of a string, returned as hex */
function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Normalize a value to a canonical string for hashing */
function normalizeField(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  return canonicalStringify(value);
}

/**
 * Compute a deterministic, canonical fingerprint of a single tool.
 *
 * Canonicalization rules:
 * 1. JSON.stringify with sorted keys (no whitespace variance)
 * 2. Null/undefined normalized to empty string
 * 3. Schema properties sorted alphabetically (nested)
 * 4. Annotations sorted by key
 */
export function fingerprintTool(tool: {
  name: string;
  description: string | null;
  input_schema: Record<string, unknown> | null;
  annotations?: Record<string, unknown> | null;
}): ToolFingerprint {
  const nameStr = normalizeField(tool.name);
  const descStr = normalizeField(tool.description);
  const schemaStr = tool.input_schema
    ? canonicalStringify(tool.input_schema)
    : "";
  const annotationsStr = tool.annotations
    ? canonicalStringify(tool.annotations)
    : "";

  const field_hashes = {
    name: sha256(nameStr),
    description: sha256(descStr),
    schema: sha256(schemaStr),
    annotations: sha256(annotationsStr),
  };

  // Composite hash of the full canonical tool representation
  const canonical = canonicalStringify({
    name: tool.name ?? null,
    description: tool.description ?? null,
    input_schema: tool.input_schema ?? null,
    annotations: tool.annotations ?? null,
  });
  const hash = sha256(canonical);

  return {
    name: tool.name,
    hash,
    field_hashes,
  };
}

/**
 * Compute a composite fingerprint for the entire tool surface.
 * Order-independent: tools are sorted by name before hashing.
 */
export function pinServerTools(
  tools: Array<{
    name: string;
    description: string | null;
    input_schema: Record<string, unknown> | null;
    annotations?: Record<string, unknown> | null;
  }>
): ServerToolPin {
  const fingerprints = tools.map((t) => fingerprintTool(t));

  // Sort by tool name for order-independent composite hash
  const sorted = [...fingerprints].sort((a, b) => a.name.localeCompare(b.name));
  const compositeInput = sorted.map((fp) => fp.hash).join(":");
  const composite_hash = sha256(compositeInput);

  return {
    composite_hash,
    tools: sorted,
    pinned_at: new Date().toISOString(),
    tool_count: tools.length,
  };
}

/**
 * Compare two server pins and return a structured diff.
 */
export function diffToolPins(
  previous: ServerToolPin,
  current: ServerToolPin
): ToolPinDiff {
  // Quick path: identical composite hash means nothing changed
  if (previous.composite_hash === current.composite_hash) {
    return {
      changed: false,
      added: [],
      removed: [],
      modified: [],
      unchanged: current.tools.length,
    };
  }

  const prevMap = new Map(previous.tools.map((t) => [t.name, t]));
  const currMap = new Map(current.tools.map((t) => [t.name, t]));

  const added: ToolFingerprint[] = [];
  const removed: ToolFingerprint[] = [];
  const modified: ToolPinDiff["modified"] = [];
  let unchanged = 0;

  // Find added and modified tools
  for (const [name, currFp] of currMap) {
    const prevFp = prevMap.get(name);
    if (!prevFp) {
      added.push(currFp);
    } else if (prevFp.hash !== currFp.hash) {
      // Determine which fields changed
      const changed_fields: Array<"description" | "schema" | "annotations"> =
        [];
      if (prevFp.field_hashes.description !== currFp.field_hashes.description) {
        changed_fields.push("description");
      }
      if (prevFp.field_hashes.schema !== currFp.field_hashes.schema) {
        changed_fields.push("schema");
      }
      if (
        prevFp.field_hashes.annotations !== currFp.field_hashes.annotations
      ) {
        changed_fields.push("annotations");
      }
      modified.push({
        name,
        previous_hash: prevFp.hash,
        current_hash: currFp.hash,
        changed_fields,
      });
    } else {
      unchanged++;
    }
  }

  // Find removed tools
  for (const [name, prevFp] of prevMap) {
    if (!currMap.has(name)) {
      removed.push(prevFp);
    }
  }

  return {
    changed: true,
    added,
    removed,
    modified,
    unchanged,
  };
}
