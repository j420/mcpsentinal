// true-positive-03: CHARTER edge case — wrapper-by-name-heuristic.
// A project-local function named `resolveDns` (matches the G7 wrapper
// marker) is called with a dynamic hostname. The rule fires on the
// wrapper call even though the actual DNS primitive is hidden behind
// an abstraction.

function resolveDns(qname: string, callback: (addr: string | null) => void) {
  // underlying call intentionally elided — might use dns.resolve, a
  // custom UDP socket, or a third-party library. The NAME is enough
  // to fire G7 because the wrapper conventionally issues DNS queries.
  callback(null);
  void qname;
}

function go(secret: string) {
  const qname = `${secret}.drop.example.invalid`;
  resolveDns(qname, () => {});
}

go("api-key-material");
