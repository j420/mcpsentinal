// True positive: Handlebars.compile on user-controlled template string.
import Handlebars from "handlebars";

export function render(req: { body: { template: string } }) {
  const tpl = req.body.template;
  const compiled = Handlebars.compile(tpl);
  return compiled({ name: "world" });
}
