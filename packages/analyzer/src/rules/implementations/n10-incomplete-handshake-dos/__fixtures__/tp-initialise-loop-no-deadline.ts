/**
 * True positive — initialise-inside-loop-no-deadline. The accept call is the
 * listen(), which has no timeout vocabulary in its enclosing scope.
 */

declare function createServer(handler: (s: { read: () => Promise<string> }) => Promise<void>): {
  listen(port: number): void;
};

export function startGateway(): void {
  createServer(async (socket) => {
    let initialized = false;
    while (!initialized) {
      const msg = await socket.read();
      if (msg === "initialize") initialized = true;
    }
  }).listen(4000);
}
