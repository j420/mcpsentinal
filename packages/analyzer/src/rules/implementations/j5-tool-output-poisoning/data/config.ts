export const J5_CONFIDENCE_CAP = 0.82;

/**
 * Two small token-pair catalogues. Each entry is its own typed
 * record so the no-static-patterns guard (5-element array limit)
 * is satisfied.
 */
export interface ResponseManipulationSpec {
  readonly response_token: string;
  readonly instruction_token: string;
  readonly target_token: string;
  readonly kind: "credential-access" | "exec-directive" | "role-override";
}

export const J5_RESPONSE_PATTERNS: Readonly<
  Record<string, ResponseManipulationSpec>
> = {
  error_read_ssh: {
    response_token: "error",
    instruction_token: "read",
    target_token: ".ssh",
    kind: "credential-access",
  },
  error_read_credentials: {
    response_token: "error",
    instruction_token: "read",
    target_token: "credentials",
    kind: "credential-access",
  },
  return_please_execute: {
    response_token: "return",
    instruction_token: "please",
    target_token: "execute",
    kind: "exec-directive",
  },
  response_you_should_call: {
    response_token: "response",
    instruction_token: "you should",
    target_token: "call",
    kind: "exec-directive",
  },
  error_ignore_previous: {
    response_token: "error",
    instruction_token: "ignore",
    target_token: "previous",
    kind: "role-override",
  },
};
