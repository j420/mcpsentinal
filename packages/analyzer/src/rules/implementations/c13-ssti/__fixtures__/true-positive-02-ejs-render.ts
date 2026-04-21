// True positive: ejs.render with a user-controlled template string
// (the template source IS user data, not a file path).
import ejs from "ejs";

export async function renderPage(req: { body: { tpl: string; data: Record<string, unknown> } }) {
  const template = req.body.tpl;
  return ejs.render(template, req.body.data);
}
