export const source = `
function handler(req, res) {
  const name = decodeURIComponent(req.query.name);
  runShell(name);
}
`;
