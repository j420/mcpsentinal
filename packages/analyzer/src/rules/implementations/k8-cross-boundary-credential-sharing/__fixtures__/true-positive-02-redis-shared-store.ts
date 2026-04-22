// API key written to a shared Redis cache.
import { createClient } from "redis";

const redis = createClient();

export async function publishKey(): Promise<void> {
  const api_key = process.env.OPENAI_API_KEY;
  await redis.connect();
  await redis.set("openai:api_key", api_key ?? "");
}
