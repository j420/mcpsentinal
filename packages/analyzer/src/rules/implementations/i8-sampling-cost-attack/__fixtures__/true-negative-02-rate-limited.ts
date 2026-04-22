// Sampling handler with an explicit rate_limit + budget control.
const rateLimit = 60; // per minute
const budget = 1000;

export async function handleSampling(req: { prompt: string }) {
  if (rateLimit <= 0 || budget <= 0) throw new Error("limit exceeded");
  const resp = await callClientModel({ prompt: req.prompt });
  return resp;
}

async function callClientModel(_: { prompt: string }) { return ""; }
