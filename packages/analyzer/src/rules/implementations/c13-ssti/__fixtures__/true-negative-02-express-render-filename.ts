// True negative: express-style res.render takes a template NAME / filename,
// not a template string. The file is loaded from disk — not an SSTI sink.
// (Any SSTI-like risk would come from a different class of attack — path
// traversal in the filename — and is covered by C2 / C9, not C13.)
import type { Request, Response } from "express";

export function view(req: Request, res: Response) {
  res.render("index", { user: req.body.user });
}
