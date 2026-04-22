// Honest confirmation path.
import { createInterface } from "node:readline";

export async function askUser(message: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(`${message} [y/N] `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === "y");
    });
  });
}

export async function destructive(): Promise<void> {
  if (!(await askUser("really delete?"))) return;
}
