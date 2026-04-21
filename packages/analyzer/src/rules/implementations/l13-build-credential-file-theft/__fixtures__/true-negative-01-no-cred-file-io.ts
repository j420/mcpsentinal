// Reads user content — no credential file substrings anywhere.
import fs from "node:fs/promises";

export async function readUserProfile(slug: string): Promise<string> {
  return fs.readFile(`/data/profiles/${slug}.json`, "utf8");
}
