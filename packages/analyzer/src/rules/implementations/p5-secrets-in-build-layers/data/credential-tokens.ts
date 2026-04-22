/**
 * P5 — credential-identifier vocabulary.
 *
 * Token set covers cloud, registry, database, and TLS credential
 * identifiers. Matching is case-insensitive, whole-token, and treats
 * an identifier as a match only when it is the ARG / ENV key (not
 * buried inside a comment or longer string).
 */

export type CredentialKind = "password" | "token" | "key" | "credentials" | "database" | "ssh-key";

export interface CredentialToken {
  name: string;
  kind: CredentialKind;
  weight: number;
}

export const CREDENTIAL_TOKENS: Record<string, CredentialToken> = {
  PASSWORD: { name: "PASSWORD", kind: "password", weight: 0.95 },
  SECRET: { name: "SECRET", kind: "token", weight: 0.9 },
  TOKEN: { name: "TOKEN", kind: "token", weight: 0.85 },
  API_KEY: { name: "API_KEY", kind: "key", weight: 0.95 },
  PRIVATE_KEY: { name: "PRIVATE_KEY", kind: "ssh-key", weight: 1.0 },
  AWS_ACCESS_KEY_ID: { name: "AWS_ACCESS_KEY_ID", kind: "key", weight: 1.0 },
  AWS_SECRET_ACCESS_KEY: { name: "AWS_SECRET_ACCESS_KEY", kind: "key", weight: 1.0 },
  DATABASE_URL: { name: "DATABASE_URL", kind: "database", weight: 0.85 },
  CREDENTIALS: { name: "CREDENTIALS", kind: "credentials", weight: 0.85 },
  NPM_TOKEN: { name: "NPM_TOKEN", kind: "token", weight: 0.95 },
  GITHUB_TOKEN: { name: "GITHUB_TOKEN", kind: "token", weight: 0.95 },
  DOCKERHUB_PASSWORD: { name: "DOCKERHUB_PASSWORD", kind: "password", weight: 0.95 },
};

/** Dockerfile directives we care about. */
export type DockerDirective = "ARG" | "ENV" | "COPY" | "ADD" | "RUN";

/** Credential file basenames matched by the COPY / ADD path. */
export const CREDENTIAL_FILE_BASENAMES: Record<string, { description: string }> = {
  ".env": { description: ".env — dotenv file commonly containing secrets." },
  ".npmrc": { description: ".npmrc — contains npm auth tokens." },
  "credentials.json": { description: "credentials.json — GCP / Stripe / cloud-provider creds." },
  "secrets.json": { description: "secrets.json — application secrets file." },
  "id_rsa": { description: "id_rsa — SSH private key." },
  "id_ed25519": { description: "id_ed25519 — SSH private key." },
  ".aws/credentials": { description: "AWS credentials file." },
  ".gitconfig": { description: ".gitconfig — contains git auth tokens if misconfigured." },
};

/** Tokens indicating a BuildKit secret mount is already in use — exempt. */
export const BUILDKIT_SECRET_TOKENS: Record<string, { description: string }> = {
  "--mount=type=secret": { description: "BuildKit secret mount — correct pattern." },
  "--secret": { description: "BuildKit CLI --secret flag." },
};
