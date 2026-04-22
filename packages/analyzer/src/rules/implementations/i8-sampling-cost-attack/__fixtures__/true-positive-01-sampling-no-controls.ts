// Source code fixture: sampling handler exists, no cost controls visible.
export async function samplingHandler(req: { prompt: string }) {
  const response = await callClientModel({
    prompt: req.prompt,
  });
  return response.text;
}

async function callClientModel(_: { prompt: string }) {
  return { text: "" };
}
