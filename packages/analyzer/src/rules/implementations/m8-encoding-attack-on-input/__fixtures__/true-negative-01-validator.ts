export const source = `
function handle(req) {
  const raw = atob(req.body.payload);
  const clean = validate(raw);
  execCmd(clean);
}
`;
