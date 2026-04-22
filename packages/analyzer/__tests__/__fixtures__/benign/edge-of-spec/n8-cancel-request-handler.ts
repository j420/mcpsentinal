/**
 * Stresses N8 (missing cancellation handling). The server explicitly
 * handles `$/cancelRequest`. N-category protocol edge rules that fire
 * on "missing cancellation" must not fire here — the handler exists
 * and does the right thing.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `const inflight = new Map<string, AbortController>();

export function registerRequest(id: string): AbortSignal {
  const ctrl = new AbortController();
  inflight.set(id, ctrl);
  return ctrl.signal;
}

export function onCancelRequest(params: { id: string }): void {
  const ctrl = inflight.get(params.id);
  if (ctrl) {
    ctrl.abort();
    inflight.set(params.id, new AbortController());
  }
}

// Wire the handler:
export function register(server: { on: (m: string, cb: (p: { id: string }) => void) => void }) {
  server.on("$/cancelRequest", onCancelRequest);
}
`;

export const n8CancelRequestHandlerFixture: BenignFixture = {
  id: "edge-of-spec/n8-cancel-request-handler",
  bucket: "edge-of-spec",
  why_benign:
    "N8 cancellation handling. Server explicitly handles $/cancelRequest " +
    "with AbortController plumbing — compliant shape, not missing.",
  context: {
    server: {
      id: "edge/n8-cancel",
      name: "cancelable-service",
      description: "Service with proper cancel-request plumbing.",
      github_url: null,
    },
    tools: [
      {
        name: "long_task",
        description: "Start a cancelable long-running task.",
        input_schema: {
          type: "object",
          properties: { work_id: { type: "string", format: "uuid" } },
          required: ["work_id"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
