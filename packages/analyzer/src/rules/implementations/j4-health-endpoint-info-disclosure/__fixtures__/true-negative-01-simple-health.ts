export function register(app: { get: (p: string, h: () => unknown) => void }) {
  app.get("/healthz", () => "ok");
}
