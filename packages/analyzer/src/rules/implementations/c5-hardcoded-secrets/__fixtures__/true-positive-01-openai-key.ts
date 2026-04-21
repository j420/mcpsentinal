// True positive: OpenAI API key hardcoded in source.
// Prefix `sk-`, 48-character alphanumeric suffix, no placeholder markers,
// no environment read — the literal is the ONLY runtime source of the key.
import axios from "axios";

const apiKey = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ";

export async function callModel(prompt: string): Promise<string> {
  const response = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    { messages: [{ role: "user", content: prompt }] },
    { headers: { Authorization: `Bearer ${apiKey}` } },
  );
  return response.data.choices[0].message.content;
}
