/**
 * PlaceholderSlot — honest "this slot exists, the live equivalent is over there"
 * card for IA slots whose preview content has not been built yet.
 *
 * Three rules this enforces:
 *   1. The new IA is fully navigable — no 404s in the preview tree.
 *   2. The user always lands somewhere useful — every placeholder links to
 *      the live page that already serves the same purpose.
 *   3. The follow-up plan is visible — every placeholder cites the bucket
 *      number it tracks against.
 */

interface Props {
  label: string;
  title: string;
  description: string;
  liveHref: string;
  liveLabel: string;
  followUp: string;
}

export default function PlaceholderSlot({
  label,
  title,
  description,
  liveHref,
  liveLabel,
  followUp,
}: Props) {
  return (
    <>
      <section style={{ padding: "var(--s8) 0 var(--s5)" }}>
        <p
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "11px",
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--text-3)",
            marginBottom: "var(--s2)",
          }}
        >
          {label} · IA slot
        </p>
        <h1
          style={{
            fontFamily: "var(--font-body)",
            fontSize: "clamp(28px, 4vw, 40px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            color: "var(--text)",
            marginBottom: "var(--s3)",
            maxWidth: "720px",
          }}
        >
          {title}
        </h1>
        <p
          style={{
            fontSize: "15px",
            color: "var(--text-2)",
            lineHeight: 1.6,
            maxWidth: "640px",
          }}
        >
          {description}
        </p>
      </section>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: "var(--s4)",
          padding: "var(--s5) 0",
        }}
      >
        <a
          href={liveHref}
          style={{
            display: "block",
            padding: "var(--s5)",
            background: "var(--surface)",
            border: "1px solid var(--accent-ring)",
            borderRadius: "var(--r-lg)",
            textDecoration: "none",
          }}
        >
          <p
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              color: "var(--accent-2)",
              marginBottom: "var(--s2)",
            }}
          >
            Available now
          </p>
          <p
            style={{
              fontSize: "16px",
              fontWeight: 600,
              color: "var(--text)",
              marginBottom: "var(--s2)",
            }}
          >
            {liveLabel}
          </p>
          <p
            style={{
              fontSize: "13px",
              color: "var(--text-2)",
              lineHeight: 1.5,
            }}
          >
            The live page is unmodified. Click through to the existing
            surface.
          </p>
        </a>

        <div
          style={{
            padding: "var(--s5)",
            background: "var(--surface-2)",
            border: "1px solid var(--border)",
            borderRadius: "var(--r-lg)",
          }}
        >
          <p
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              color: "var(--text-3)",
              marginBottom: "var(--s2)",
            }}
          >
            Follow-up
          </p>
          <p
            style={{
              fontSize: "14px",
              color: "var(--text-2)",
              lineHeight: 1.55,
            }}
          >
            {followUp}
          </p>
        </div>
      </section>
    </>
  );
}
