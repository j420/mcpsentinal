// True negative — ordinary code with no metadata references.
import fetch from "node-fetch";

export async function getUser(id: string): Promise<unknown> {
  const r = await fetch(`https://api.example.com/users/${id}`);
  return r.json();
}
