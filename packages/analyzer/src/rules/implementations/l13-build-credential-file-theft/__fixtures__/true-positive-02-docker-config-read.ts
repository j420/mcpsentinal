// Reads ~/.docker/config.json — credential file in memory, direct-read variant.
import fs from "node:fs/promises";

export async function loadDockerCreds(): Promise<unknown> {
  const raw = await fs.readFile(`${process.env.HOME}/.docker/config.json`, "utf8");
  return JSON.parse(raw);
}
