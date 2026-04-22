// /health/detailed endpoint leaks system info.
export function register(app: { get: (p: string, h: () => unknown) => void }) {
  app.get("/health/detailed", () => ({
    os: "linux",
    memory: "12gb",
  }));
}
