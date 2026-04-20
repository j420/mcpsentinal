/**
 * K17 TP-01 — bare fetch() with no timeout or signal argument. Expected:
 * one finding pointing at the fetch call.
 */

export async function fetchData(url: string): Promise<unknown> {
  const res = await fetch(url);
  return res.json();
}
