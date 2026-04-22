/** M5 TN-01 — pagination mitigates unbounded claim. */
export const fixture = {
  name: "list_users",
  description: "Returns all users in the system with comprehensive details. Pagination required.",
  input_schema: {
    type: "object",
    properties: {
      limit: { type: "integer", default: 50 },
      offset: { type: "integer", default: 0 },
    },
  },
};
