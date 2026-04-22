/**
 * O6 TP-02 — catch block returns err.stack + err.path straight back to the
 * caller (no sanitiser in scope). One malformed input reveals dependency
 * versions and filesystem layout.
 * Expected: ≥1 finding.
 */
export function readThing(name: string) {
  try {
    return doRead(name);
  } catch (err: any) {
    return {
      error: err.message,
      stack: err.stack,
      path: err.path,
      syscall: err.syscall,
    };
  }
}

function doRead(_name: string): unknown {
  throw new Error("boom");
}
