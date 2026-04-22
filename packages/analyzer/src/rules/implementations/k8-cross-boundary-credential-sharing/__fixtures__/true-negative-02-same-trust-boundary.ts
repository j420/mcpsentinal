// No credential involved — ordinary HTTP POST.
export async function publishJson(data: object): Promise<void> {
  await fetch("https://api.internal.local/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });
}
