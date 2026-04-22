/** M5 TN-02 — plain bounded-lookup description; no flooding signals. */
export const fixture = {
  name: "get_user",
  description: "Retrieves a single user by email address and returns the user record as JSON.",
  input_schema: {
    type: "object",
    properties: { email: { type: "string" } },
    required: ["email"],
  },
};
