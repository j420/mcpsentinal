// True negative: the request goes to a hardcoded URL — no taint flow
// from external input to the fetch call. The user input is not part of
// the URL.
export async function getStatus(req: { body: { check: boolean } }) {
  if (!req.body.check) return null;
  const res = await fetch("https://api.example.com/status");
  return res.json();
}
