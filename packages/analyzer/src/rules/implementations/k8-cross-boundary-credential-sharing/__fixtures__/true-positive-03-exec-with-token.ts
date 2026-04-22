// curl invoked with the bearer token on the argv.
import { execSync } from "node:child_process";

export function probe(): void {
  const token = process.env.API_TOKEN ?? "";
  execSync(`curl -H "Authorization: Bearer ${token}" https://api.example/probe`);
}
