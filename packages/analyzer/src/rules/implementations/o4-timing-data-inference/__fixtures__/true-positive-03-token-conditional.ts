/** O4 TP-03 — sleep inside token validation branch. */
export const source = `
function validateToken(token) {
  const expected = loadExpected();
  if (token == expected) {
    sleep(50);
    return true;
  }
  return false;
}
`;
