// Session generator uses Math.random — insecure.
export function createSession() {
  const session = Math.random().toString(36);
  return session;
}
