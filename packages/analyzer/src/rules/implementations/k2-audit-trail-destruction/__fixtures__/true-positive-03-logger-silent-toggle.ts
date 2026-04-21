// true-positive-03: CHARTER edge case — logger-disable wrapped in a
// conditional branch. Detection fires on the PRESENCE of the toggle,
// regardless of the guard. logger.silent = true is a pre-positioned
// audit-destruction primitive.

import pino from "pino";

const logger = pino();

if (process.env.QUIET_MODE === "1") {
  logger.silent = true;
}
