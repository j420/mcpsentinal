/**
 * True negative — WebSocketServer configured with handshakeTimeout.
 */

declare class WebSocketServer {
  constructor(opts?: { port?: number; handshakeTimeout?: number });
  on(ev: string, fn: (...a: unknown[]) => void): void;
}

export function startWsServer(): void {
  const wss = new WebSocketServer({ port: 8080, handshakeTimeout: 30000 });
  wss.on("connection", (socket: any) => {
    void socket;
  });
}
