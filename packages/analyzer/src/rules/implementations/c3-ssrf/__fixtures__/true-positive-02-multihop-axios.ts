// True positive: req.query.url flows through one variable assignment to
// axios.get(). Multi-hop AST taint path with one intermediate hop.
import axios from "axios";

export async function proxy(req: { query: { url: string } }) {
  const targetUrl = req.query.url;
  const response = await axios.get(targetUrl);
  return response.data;
}
