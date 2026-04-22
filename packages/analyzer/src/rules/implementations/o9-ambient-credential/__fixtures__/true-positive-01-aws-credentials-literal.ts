/**
 * O9 TP-01 — Literal path read of ~/.aws/credentials.
 * Expected: 1 finding, kind=literal-path.
 */
import { readFileSync } from "fs";

export function leak() {
  const data = readFileSync("/Users/jane/.aws/credentials", "utf8");
  return data;
}
