// True negative: fully hardcoded internal-API URL. No user input
// participates in the URL. The function takes no request input.
export async function fetchInternalStatus() {
  const res = await fetch("https://api.example.com/internal/status");
  return res.json();
}
