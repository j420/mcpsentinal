// True positive: req.body.target flows directly into fetch() on the same
// line. Zero intermediate hops — exploitability "trivial". Classic IMDS
// SSRF: the attacker supplies http://169.254.169.254/... and the MCP
// server returns AWS IAM credentials.
export async function fetchTarget(req: { body: { target: string } }) {
  const res = await fetch(req.body.target);
  return res.json();
}
