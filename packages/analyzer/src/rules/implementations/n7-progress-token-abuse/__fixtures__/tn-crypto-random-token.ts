/**
 * True negative — cryptographic random token bound to the active session.
 */

import * as crypto from "node:crypto";

export function startRequest(sessionId: string): string {
  const progressToken = crypto.randomUUID();
  registerOwnership(progressToken, sessionId);
  return progressToken;
}

declare function registerOwnership(token: string, sessionId: string): void;
