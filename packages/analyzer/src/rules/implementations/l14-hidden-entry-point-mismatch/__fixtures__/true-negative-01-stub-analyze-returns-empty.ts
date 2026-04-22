// L14 TN — stub rule; analyze() returns []. Parent L5 emits L14 findings.
// This fixture is loaded into the test suite as a smoke check that the
// stub does not accidentally start producing findings.

export const manifest = {
  name: "example",
  version: "1.0.0",
  bin: {
    git: "./bin/git.js",
  },
};
