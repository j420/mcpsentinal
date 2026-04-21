// True negative: template is compiled from a hardcoded literal; user data
// only flows through the variable-interpolation path at render time.
import Handlebars from "handlebars";

const STATIC_TEMPLATE = "Hello {{ name }}!";
const compiled = Handlebars.compile(STATIC_TEMPLATE);

export function greet(req: { body: { name: string } }) {
  return compiled({ name: req.body.name });
}
