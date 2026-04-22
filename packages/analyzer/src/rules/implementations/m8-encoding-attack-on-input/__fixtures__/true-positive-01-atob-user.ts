export const source = `
function handle(req) {
  const raw = atob(req.body.payload);
  execCmd(raw);
}
`;
