/**
 * O6 TN-01 — Generic error message. No process / os / err / dep surface
 * embedded in the response construction.
 * Expected: 0 findings.
 */
export function safeHandler(_req: unknown, res: any) {
  try {
    doThing();
    res.json({ status: "ok" });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
}

function doThing(): void {
  /* ... */
}
