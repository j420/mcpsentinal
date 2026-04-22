/**
 * Q15 TP-02 — A2A TaskResult parts (TextPart / FilePart / DataPart) fed
 * straight into an MCP callTool without content-policy checks.
 * Expected: ≥1 finding.
 */
declare function callTool(args: unknown): Promise<unknown>;

export async function forwardTaskResult(result: {
  parts: Array<{ kind: "TextPart" | "FilePart" | "DataPart"; body: unknown }>;
}) {
  for (const part of result.parts) {
    await callTool({ kind: part.kind, body: part.body });
  }
}
