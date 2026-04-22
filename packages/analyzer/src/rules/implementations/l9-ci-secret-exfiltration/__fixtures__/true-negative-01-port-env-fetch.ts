// true-negative-01: non-sensitive env read (PORT) forwarded to a health
// endpoint. Not a secret — L9 must NOT fire.

async function ping() {
  const port = process.env.PORT;
  await fetch(`http://localhost:${port}/healthz`);
}

ping();
