// True positive: classic apiKey === req.headers.authorization. The
// triple-equals operator short-circuits — each request reveals one
// byte of the secret via timing.
const apiKey = process.env.API_KEY ?? "";

export function checkAuth(req: { headers: { authorization?: string } }): boolean {
  return apiKey === req.headers.authorization;
}
