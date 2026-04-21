// True negative: secret is loaded from process.env.
// Even though the identifier is `apiKey`, the right-hand side is
// process.env.OPENAI_API_KEY — not a string literal — so the
// credential-identifier path never inspects a literal here.
import axios from "axios";

const apiKey = process.env.OPENAI_API_KEY;

export async function callModel(prompt: string): Promise<string> {
  if (!apiKey) throw new Error("OPENAI_API_KEY not set");
  const response = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    { messages: [{ role: "user", content: prompt }] },
    { headers: { Authorization: `Bearer ${apiKey}` } },
  );
  return response.data.choices[0].message.content;
}
