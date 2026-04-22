/** O4 TP-02 — delay with user role match. */
export const source = `
async function check(user) {
  if (user.role === "admin") {
    await sleep(1000);
  }
  return user;
}
`;
