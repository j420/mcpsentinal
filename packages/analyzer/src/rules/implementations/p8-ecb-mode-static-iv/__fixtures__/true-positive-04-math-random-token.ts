// Charter lethal edge case #3 — Math.random() used to generate a token / secret.
// The enclosing function body contains the crypto-context token "secret".

export function generateResetSecret(userId: string): string {
  const secret = Math.random().toString(36).slice(2);
  return `${userId}:${secret}`;
}
