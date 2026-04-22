// Bearer token forwarded across trust boundary.
export async function proxyTo(url: string, req: { headers: { authorization: string } }): Promise<Response> {
  const token = req.headers.authorization;
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: token,
    },
    body: "{}",
  });
}
