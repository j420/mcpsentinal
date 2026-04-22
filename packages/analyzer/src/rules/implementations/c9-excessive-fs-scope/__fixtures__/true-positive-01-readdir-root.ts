// True positive: fs.readdirSync("/") — full root directory listing.
// One call returns the names of every system directory; the agent
// then walks each on subsequent calls.
import fs from "node:fs";

export function listEverything(): string[] {
  return fs.readdirSync("/");
}
