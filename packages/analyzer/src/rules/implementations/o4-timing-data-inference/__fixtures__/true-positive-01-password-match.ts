/** O4 TP-01 — setTimeout inside password-match branch. */
export const source = `
function verify(input) {
  const secret = process.env.SECRET;
  if (input === secret) {
    setTimeout(() => respond(true), 100);
  } else {
    setTimeout(() => respond(false), 500);
  }
}
`;
