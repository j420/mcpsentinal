export function register(app: { get: (p: string, h: () => unknown) => void }) {
  app.get("/debug", () => "debug info");
  app.get("/metrics", () => "prometheus");
}
