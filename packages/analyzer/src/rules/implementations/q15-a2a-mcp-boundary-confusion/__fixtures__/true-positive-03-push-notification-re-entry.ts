/**
 * Q15 TP-03 — A2A pushNotification re-enters MCP context via sendToolResult
 * without re-validation. Second injection moment.
 * Expected: ≥1 finding.
 */
declare function sendToolResult(payload: unknown): Promise<void>;

export async function onPush(pushNotification: { body: unknown }) {
  await sendToolResult(pushNotification.body);
}
