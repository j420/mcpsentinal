/** Buffer.from with utf-8 encoding is not a decode attack. */
export const source = `
function decode(req) {
  const buf = Buffer.from(req.body.text, "utf-8");
  return buf.toString();
}
`;
