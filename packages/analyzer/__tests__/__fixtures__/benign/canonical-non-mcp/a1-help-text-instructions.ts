/**
 * Help-text-with-instructions — a description that tells the user how to
 * use the tool, not the AI what to do. A naive A1 prompt-injection
 * detector might flag the imperative "run" verb; the full rule should
 * see that this is documentation, not coercion.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const a1HelpTextFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/a1-help-text-instructions",
  name: "booking-help",
  why:
    "Help-text describing end-user workflow. Stresses A1 prompt-injection-" +
    "in-description negative — imperatives target the human reader, not " +
    "the AI; B5 parameter-description-injection negative.",
  description:
    "Booking helper. To cancel a booking, call cancel_booking with the " +
    "booking id and confirmation code the traveller received by email.",
  tools: [
    {
      name: "cancel_booking",
      description:
        "Cancel an existing booking. The traveller must provide the " +
        "booking id and the confirmation code printed on their itinerary.",
      input_schema: {
        type: "object",
        properties: {
          booking_id: { type: "string", pattern: "^BK[0-9]{8}$" },
          confirmation_code: { type: "string", maxLength: 16 },
        },
        required: ["booking_id", "confirmation_code"],
        additionalProperties: false,
      },
    },
  ],
  source_code: `
    export async function cancelBooking(bookingId, confirmationCode) {
      const expected = await lookupConfirmationCode(bookingId);
      if (expected !== confirmationCode) {
        return { ok: false, reason: "confirmation_mismatch" };
      }
      return markCancelled(bookingId);
    }
  `,
});
