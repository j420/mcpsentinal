/**
 * Edge-of-spec bucket. 53 fixtures crafted to stress-test the false-positive
 * boundary of specific rules. At least one fixture per active category
 * (A–Q). Each fixture's `why_benign` names the rule(s) it stresses.
 *
 * Coverage: A(3) B(3) C(8) D(2) E(1) F(2) G(5) H(2) I(5) J(4) K(6) L(3)
 * M(1) N(2) O(1) P(3) Q(1) — 53 total.
 */
import type { BenignFixture } from "../types.js";

import { a1LegitIgnoreDocFixture } from "./a1-legit-ignore-doc.js";
import { a5LongTutorialFixture } from "./a5-long-tutorial.js";
import { a8AnalyticsDashboardFixture } from "./a8-analytics-dashboard.js";
import { b2StrictFilenameFixture } from "./b2-strict-filename.js";
import { b3ConstrainedEnumsFixture } from "./b3-constrained-enums.js";
import { b7VerboseDefaultFixture } from "./b7-verbose-default.js";
import { c1ConstExecFixture } from "./c1-const-exec.js";
import { c2GuardedResolveFixture } from "./c2-guarded-resolve.js";
import { c3AllowlistFetchFixture } from "./c3-allowlist-fetch.js";
import { c4ParametrisedSqlFixture } from "./c4-parametrised-sql.js";
import { c5StripeTestKeyFixture } from "./c5-stripe-test-key.js";
import { c10EmptyTargetAssignFixture } from "./c10-empty-target-assign.js";
import { c11BoundedRegexFixture } from "./c11-bounded-regex.js";
import { c13LiteralTemplateFixture } from "./c13-literal-template.js";
import { c14PinnedJwtFixture } from "./c14-pinned-jwt.js";
import { d2StableChalkFixture } from "./d2-stable-chalk.js";
import { d5VerifiedScopeFixture } from "./d5-verified-scope.js";
import { e2LocalhostDevFixture } from "./e2-localhost-dev.js";
import { f1TwoLegsFixture } from "./f1-two-legs.js";
import { f4StrictComplianceFixture } from "./f4-strict-compliance.js";
import { g1HmacWebhookFixture } from "./g1-hmac-webhook.js";
import { g2FactualDocFixture } from "./g2-factual-doc.js";
import { g3McpContentShapeFixture } from "./g3-mcp-content-shape.js";
import { g5NoPriorApprovalFixture } from "./g5-no-prior-approval.js";
import { g7LegitDnsFixture } from "./g7-legit-dns.js";
import { h1PkceOauthFixture } from "./h1-pkce-oauth.js";
import { h2NeutralInstructionsFixture } from "./h2-neutral-instructions.js";
import { i1CorrectDestructiveFixture } from "./i1-correct-destructive.js";
import { i4ScopedFileUriFixture } from "./i4-scoped-file-uri.js";
import { i6EscapedPlaceholderFixture } from "./i6-escaped-placeholder.js";
import { i9SmtpConfigNoCredsFixture } from "./i9-smtp-config-no-creds.js";
import { i10SelfOriginRedirectFixture } from "./i10-self-origin-redirect.js";
import { j2ConstGitArgsFixture } from "./j2-const-git-args.js";
import { j3BoundedEnumFixture } from "./j3-bounded-enum.js";
import { j4MinimalHealthFixture } from "./j4-minimal-health.js";
import { j6NeutralDescriptionFixture } from "./j6-neutral-description.js";
import { k1PinoStructuredFixture } from "./k1-pino-structured.js";
import { k2AuditLoggerFallbackFixture } from "./k2-audit-logger-fallback.js";
import { k4MandatoryTokenFixture } from "./k4-mandatory-token.js";
import { k7ShortTtlFixture } from "./k7-short-ttl.js";
import { k13SanitisedOutputFixture } from "./k13-sanitised-output.js";
import { k17AbortSignalTimeoutFixture } from "./k17-abort-signal-timeout.js";
import { l3PinnedDigestFixture } from "./l3-pinned-digest.js";
import { l5HarmoniousManifestFixture } from "./l5-harmonious-manifest.js";
import { l10IntegrityLockfileFixture } from "./l10-integrity-lockfile.js";
import { m1EnvSystemPromptFixture } from "./m1-env-system-prompt.js";
import { n1NullNotificationIdFixture } from "./n1-null-notification-id.js";
import { n8CancelRequestHandlerFixture } from "./n8-cancel-request-handler.js";
import { o5NonSensitiveEnvFixture } from "./o5-non-sensitive-env.js";
import { p1DistrolessFixture } from "./p1-distroless.js";
import { p3NonRootUserFixture } from "./p3-non-root-user.js";
import { p7CapConstrainedFixture } from "./p7-cap-constrained.js";
import { q10ValidatedBridgeFixture } from "./q10-validated-bridge.js";

export const edgeOfSpecFixtures: readonly BenignFixture[] = [
  a1LegitIgnoreDocFixture,
  a5LongTutorialFixture,
  a8AnalyticsDashboardFixture,
  b2StrictFilenameFixture,
  b3ConstrainedEnumsFixture,
  b7VerboseDefaultFixture,
  c1ConstExecFixture,
  c2GuardedResolveFixture,
  c3AllowlistFetchFixture,
  c4ParametrisedSqlFixture,
  c5StripeTestKeyFixture,
  c10EmptyTargetAssignFixture,
  c11BoundedRegexFixture,
  c13LiteralTemplateFixture,
  c14PinnedJwtFixture,
  d2StableChalkFixture,
  d5VerifiedScopeFixture,
  e2LocalhostDevFixture,
  f1TwoLegsFixture,
  f4StrictComplianceFixture,
  g1HmacWebhookFixture,
  g2FactualDocFixture,
  g3McpContentShapeFixture,
  g5NoPriorApprovalFixture,
  g7LegitDnsFixture,
  h1PkceOauthFixture,
  h2NeutralInstructionsFixture,
  i1CorrectDestructiveFixture,
  i4ScopedFileUriFixture,
  i6EscapedPlaceholderFixture,
  i9SmtpConfigNoCredsFixture,
  i10SelfOriginRedirectFixture,
  j2ConstGitArgsFixture,
  j3BoundedEnumFixture,
  j4MinimalHealthFixture,
  j6NeutralDescriptionFixture,
  k1PinoStructuredFixture,
  k2AuditLoggerFallbackFixture,
  k4MandatoryTokenFixture,
  k7ShortTtlFixture,
  k13SanitisedOutputFixture,
  k17AbortSignalTimeoutFixture,
  l3PinnedDigestFixture,
  l5HarmoniousManifestFixture,
  l10IntegrityLockfileFixture,
  m1EnvSystemPromptFixture,
  n1NullNotificationIdFixture,
  n8CancelRequestHandlerFixture,
  o5NonSensitiveEnvFixture,
  p1DistrolessFixture,
  p3NonRootUserFixture,
  p7CapConstrainedFixture,
  q10ValidatedBridgeFixture,
];
