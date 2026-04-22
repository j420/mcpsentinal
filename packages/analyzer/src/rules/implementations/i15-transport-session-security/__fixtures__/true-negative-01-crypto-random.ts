import { randomUUID } from "node:crypto";
export function createSession() {
  return randomUUID();
}
