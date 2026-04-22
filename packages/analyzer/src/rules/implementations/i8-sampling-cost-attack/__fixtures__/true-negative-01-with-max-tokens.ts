// Sampling handler with explicit max_tokens cap.
export async function samplingHandler(req: { prompt: string }) {
  const maxTokens = 256;
  const response = await callClientModel({
    prompt: req.prompt,
    max_tokens: maxTokens,
  });
  return response.text;
}

async function callClientModel(_: { prompt: string; max_tokens: number }) {
  return { text: "" };
}
