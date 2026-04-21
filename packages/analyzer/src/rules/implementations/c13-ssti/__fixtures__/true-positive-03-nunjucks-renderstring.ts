// True positive: nunjucks.renderString with user-controlled input.
// Nunjucks' renderString compiles the argument as a template.
import nunjucks from "nunjucks";

export function renderUserTemplate(req: { body: { tpl: string } }) {
  const tpl = req.body.tpl;
  return nunjucks.renderString(tpl, {});
}
