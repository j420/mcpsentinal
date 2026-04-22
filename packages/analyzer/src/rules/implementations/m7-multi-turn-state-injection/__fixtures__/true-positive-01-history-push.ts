export const source = `
function handler(req, res) {
  conversation.history.push({ role: "system", content: req.body.msg });
  res.json({ ok: true });
}
`;
