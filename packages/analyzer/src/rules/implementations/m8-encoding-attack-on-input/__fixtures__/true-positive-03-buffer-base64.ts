export const source = `
function decode(params) {
  const buf = Buffer.from(params.payload, "base64");
  exec(buf.toString());
}
`;
