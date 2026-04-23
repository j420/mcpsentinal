/**
 * Stresses M1 (system prompt manipulation). The system prompt is
 * loaded from an environment variable (`SYSTEM_PROMPT`) — operator-
 * controlled, not attacker-controlled. M1 fires when user input flows
 * into the system prompt; ENV is the trust-boundary-crossing an
 * operator explicitly provisions.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `const SYSTEM_PROMPT = process.env.SYSTEM_PROMPT ?? "You are a helpful assistant.";

export function buildMessages(userMessage: string) {
  return [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: userMessage },
  ];
}
`;

export const m1EnvSystemPromptFixture: BenignFixture = {
  id: "edge-of-spec/m1-env-system-prompt",
  bucket: "edge-of-spec",
  why_benign:
    "M1 system-prompt manipulation. The prompt comes from ENV — operator-" +
    "provisioned, not attacker-controlled — and user message is a " +
    "separately-tagged `user` role entry.",
  context: {
    server: {
      id: "edge/m1-env",
      name: "llm-router",
      description: "Simple LLM router with operator-controlled system prompt.",
      github_url: null,
    },
    tools: [
      {
        name: "ask",
        description: "Forward a user message to the configured LLM.",
        input_schema: {
          type: "object",
          properties: { message: { type: "string", maxLength: 4096 } },
          required: ["message"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
