/**
 * True positive — WebSocketServer with no handshake timeout option.
 */

declare class WebSocketServer {
  constructor(opts?: { port?: number; host?: string });
  on(ev: string, fn: (...a: unknown[]) => void): void;
}

export function startWsServer(): void {
  const wss = new WebSocketServer({ port: 8080 });
  wss.on("connection", (socket: any) => {
    socket.on("message", (msg: unknown) => {
      // Handle initialize — but the handler has no deadline.
      void msg;
    });
  });
}
