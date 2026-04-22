/** L8 TP-03 — pnpm.overrides nested block with openai 0.3.0. */
export const source = JSON.stringify({
  name: "agent",
  pnpm: { overrides: { openai: "0.3.0" } },
}, null, 2);
