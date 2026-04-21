/**
 * K15 tool-enumeration fixtures. These are JS records — the rule consumes
 * AnalysisContext.tools, not source code.
 */

import type { AnalysisContext } from "../../../../engine.js";

type Tool = AnalysisContext["tools"][number];

function tool(
  name: string,
  description: string,
  opts: {
    input_schema?: Record<string, unknown> | null;
    annotations?: Record<string, unknown> | null;
  } = {},
): Tool {
  return {
    name,
    description,
    input_schema: opts.input_schema ?? null,
    annotations: (opts.annotations ?? null) as Tool["annotations"],
  };
}

export const TP_01_MEMORY_STORE_AND_RECALL: Tool[] = [
  tool(
    "memory_store",
    "Write a record to the shared memory used across agent sessions",
    { input_schema: { type: "object", properties: { content: { type: "string" } }, required: ["content"] } },
  ),
  tool(
    "memory_recall",
    "Retrieve records from the shared memory used across agent sessions",
    { input_schema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } },
  ),
];

export const TP_02_SCRATCHPAD_WRITE_READ: Tool[] = [
  tool(
    "scratchpad_append",
    "Append text to the cross-agent scratchpad workspace",
  ),
  tool(
    "scratchpad_list",
    "List entries from the cross-agent scratchpad workspace",
  ),
];

export const TP_03_VECTOR_STORE_PAIR: Tool[] = [
  tool(
    "vector_upsert",
    "Upsert an embedding into the shared vector store for all agents",
  ),
  tool(
    "vector_search",
    "Search the shared vector store across all agents",
  ),
];

export const TN_01_ISOLATED_WRITE_NAME: Tool[] = [
  tool(
    "isolated_memory_store",
    "Store an entry in the shared memory",
  ),
  tool(
    "memory_recall",
    "Retrieve entries from the shared memory",
  ),
];

export const TN_02_AGENT_ID_REQUIRED: Tool[] = [
  tool(
    "memory_store",
    "Write a record to the shared memory",
    {
      input_schema: {
        type: "object",
        properties: {
          agent_id: { type: "string" },
          content: { type: "string" },
        },
        required: ["agent_id", "content"],
      },
    },
  ),
  tool(
    "memory_recall",
    "Retrieve records from the shared memory",
  ),
];

export const TN_03_LOGGER_ONLY: Tool[] = [
  tool(
    "log_message",
    "Write an entry to the shared audit log for operators",
  ),
  // No read-side tool → pair cannot form.
];

export const TN_04_TRUST_BOUNDARY_ANNOTATION: Tool[] = [
  tool(
    "memory_store",
    "Write a record to the shared memory",
    { annotations: { trustBoundary: "per-agent" } as Record<string, unknown> },
  ),
  tool(
    "memory_recall",
    "Retrieve records from the shared memory",
  ),
];
