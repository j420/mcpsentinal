/**
 * Stresses L10 (lockfile integrity). A pnpm-lock.yaml snippet where
 * every entry carries an `integrity: sha512-...` hash. L10 fires
 * when lockfile entries are missing integrity; fully-integrity-
 * attested lockfiles are the compliant shape.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `# File: pnpm-lock.yaml
lockfileVersion: '9.0'
packages:
  /pino@9.5.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
    dependencies:
      fast-redact: 3.5.0
  /fast-redact@3.5.0:
    resolution:
      integrity: sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==
  /zod@3.23.8:
    resolution:
      integrity: sha512-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC==
`;

export const l10IntegrityLockfileFixture: BenignFixture = {
  id: "edge-of-spec/l10-integrity-lockfile",
  bucket: "edge-of-spec",
  why_benign:
    "L10 lockfile integrity. Every lockfile entry has an `integrity: " +
    "sha512-...` attestation — compliant shape.",
  context: {
    server: {
      id: "edge/l10-lockfile",
      name: "attested-deps",
      description: "Service with fully-attested pnpm lockfile.",
      github_url: null,
    },
    tools: [],
    source_code: sourceCode,
    dependencies: [
      {
        name: "pino",
        version: "9.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-20"),
      },
    ],
    connection_metadata: null,
  },
};
