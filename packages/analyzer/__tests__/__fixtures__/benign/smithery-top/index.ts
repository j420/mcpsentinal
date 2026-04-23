/**
 * Smithery top 20 bucket. Shapes representative of the top-20 MCP servers
 * on Smithery based on their public tool surface. We DO NOT fabricate
 * tools that do not exist; when the exact parameter shape is not
 * knowable without a live fetch, the schema is a realistic-but-simplified
 * typed variant and `why_benign` documents the simplification.
 */
import type { BenignFixture } from "../types.js";
import { githubIssuesFixture } from "./github-issues.js";
import { neonPostgresFixture } from "./neon-postgres.js";
import { slackSmitheryFixture } from "./slack.js";
import { cloudflareFixture } from "./cloudflare.js";
import { stripeFixture } from "./stripe.js";
import { braveSearchSmitheryFixture } from "./brave-search.js";
import { notionFixture } from "./notion.js";
import { linearFixture } from "./linear.js";
import { sentryFixture } from "./sentry.js";
import { perplexityFixture } from "./perplexity.js";
import { exaFixture } from "./exa.js";
import { browserbaseFixture } from "./browserbase.js";
import { e2bFixture } from "./e2b.js";
import { supabaseFixture } from "./supabase.js";
import { firecrawlFixture } from "./firecrawl.js";
import { gmailFixture } from "./gmail.js";
import { googleDriveFixture } from "./google-drive.js";
import { googleCalendarFixture } from "./google-calendar.js";
import { vercelFixture } from "./vercel.js";
import { playwrightFixture } from "./playwright.js";
import { tavilyFixture } from "./tavily.js";

export const smitheryTopFixtures: readonly BenignFixture[] = [
  githubIssuesFixture,
  neonPostgresFixture,
  slackSmitheryFixture,
  cloudflareFixture,
  stripeFixture,
  braveSearchSmitheryFixture,
  notionFixture,
  linearFixture,
  sentryFixture,
  perplexityFixture,
  exaFixture,
  browserbaseFixture,
  e2bFixture,
  supabaseFixture,
  firecrawlFixture,
  gmailFixture,
  googleDriveFixture,
  googleCalendarFixture,
  vercelFixture,
  playwrightFixture,
  tavilyFixture,
];
