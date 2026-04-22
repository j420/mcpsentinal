// True positive: manual setHeader bypassing the cors module entirely.
// A rule that only checks for cors() calls would miss this — the
// AST detector inspects every setHeader call's literal arguments.
export function attachCors(res: { setHeader: (name: string, value: string) => void }) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
