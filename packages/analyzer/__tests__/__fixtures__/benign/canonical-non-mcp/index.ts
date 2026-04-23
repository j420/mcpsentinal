/**
 * Canonical non-MCP bucket. 25 regular TypeScript/JavaScript code
 * patterns a naive rule MIGHT trip on but shouldn't — validated guard
 * whitelists, parameterised queries, properly-scoped OAuth shims,
 * yaml.safeLoad, env-sourced secrets, and more.
 */
import type { BenignFixture } from "../types.js";
import { a1HelpTextFixture } from "./a1-help-text-instructions.js";
import { a6EmojiRtlFixture } from "./a6-emoji-rtl-i18n.js";
import { a9Base64ImageFixture } from "./a9-base64-image.js";
import { b7SafeDefaultsFixture } from "./b7-safe-defaults.js";
import { c1ExecFileArrayFixture } from "./c1-execfile-array.js";
import { c2PathStrippedFixture } from "./c2-path-stripped.js";
import { c5EnvSecretsFixture } from "./c5-env-secrets.js";
import { c12YamlSafeLoadFixture } from "./c12-yaml-safe-load.js";
import { c14JwtPinnedAlgFixture } from "./c14-jwt-pinned-alg.js";
import { c16SandboxFunctionFixture } from "./c16-sandbox-function.js";
import { d1PatchedVersionFixture } from "./d1-patched-version.js";
import { d3ScopedCompanyFixture } from "./d3-scoped-company.js";
import { f1ReadLogFixture } from "./f1-read-log-no-network.js";
import { g7DnsByIpFixture } from "./g7-dns-by-ip.js";
import { i1ReadOnlyQueryFixture } from "./i1-read-only-query.js";
import { i4ScopedResourceFixture } from "./i4-scoped-resource.js";
import { i11ProjectRootFixture } from "./i11-project-root.js";
import { k6NarrowOauthFixture } from "./k6-narrow-oauth-scope.js";
import { k7ShortLivedTokenFixture } from "./k7-short-lived-token.js";
import { k17AbortSignalFixture } from "./k17-abort-signal-fetch.js";
import { l5BinLegitimateFixture } from "./l5-bin-legitimate.js";
import { l9LegitFetchBodyFixture } from "./l9-legit-fetch-body.js";
import { p1PinnedDistroFixture } from "./p1-pinned-distro.js";
import { p3NonRootUserFixture } from "./p3-non-root-user.js";

export const canonicalNonMcpFixtures: readonly BenignFixture[] = [
  a1HelpTextFixture,
  a6EmojiRtlFixture,
  a9Base64ImageFixture,
  b7SafeDefaultsFixture,
  c1ExecFileArrayFixture,
  c2PathStrippedFixture,
  c5EnvSecretsFixture,
  c12YamlSafeLoadFixture,
  c14JwtPinnedAlgFixture,
  c16SandboxFunctionFixture,
  d1PatchedVersionFixture,
  d3ScopedCompanyFixture,
  f1ReadLogFixture,
  g7DnsByIpFixture,
  i1ReadOnlyQueryFixture,
  i4ScopedResourceFixture,
  i11ProjectRootFixture,
  k6NarrowOauthFixture,
  k7ShortLivedTokenFixture,
  k17AbortSignalFixture,
  l5BinLegitimateFixture,
  l9LegitFetchBodyFixture,
  p1PinnedDistroFixture,
  p3NonRootUserFixture,
];
