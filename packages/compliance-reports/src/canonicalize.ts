/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Produces a deterministic UTF-8 byte sequence for a JSON value so that
 * any two parties can independently arrive at identical signing input.
 * Compliant with the RFC on the three points that matter for
 * cryptographic attestation:
 *   1. Object keys sorted by UTF-16 code-unit order (RFC 8785 §3.2.3).
 *   2. ECMAScript 2019 `Number.prototype.toString` serialization of numbers
 *      (RFC 8785 §3.2.2.3 — shortest round-trip form).
 *   3. No insignificant whitespace (RFC 8785 §3.2).
 *
 * `undefined`, `NaN`, and `+/-Infinity` are rejected — they are not
 * representable in JSON and silently coercing them would produce
 * signatures that can't be recomputed by an independent verifier.
 */

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(`[RFC8785] ${message}`);
    this.name = "CanonicalizationError";
  }
}

/**
 * Canonicalise `value` to an RFC 8785 conformant UTF-8 JSON string.
 * Intentionally returns a string (not Buffer) — callers that need raw
 * bytes should feed this string into `Buffer.from(..., "utf8")`.
 */
export function canonicalize(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") return serializeString(value);
  if (Array.isArray(value)) return serializeArray(value);
  if (typeof value === "object") return serializeObject(value as Record<string, unknown>);
  if (value === undefined) {
    throw new CanonicalizationError("undefined is not a representable JSON value");
  }
  throw new CanonicalizationError(`unsupported value type: ${typeof value}`);
}

function serializeNumber(n: number): string {
  if (Number.isNaN(n)) throw new CanonicalizationError("NaN is not a representable JSON number");
  if (!Number.isFinite(n)) throw new CanonicalizationError("Infinity is not a representable JSON number");
  // RFC 8785 §3.2.2.3 mandates the ECMAScript 2019 Number.prototype.toString
  // algorithm. Node's `String(n)` and `n.toString()` already implement this
  // for finite numbers, so we delegate. The one edge case is negative zero:
  // JSON has no `-0`, and JCS serializes it as `0`.
  if (Object.is(n, -0)) return "0";
  return String(n);
}

function serializeString(s: string): string {
  // RFC 8785 §3.2.2.2 strings — escape only what JSON REQUIRES escaped:
  //   U+0000..U+001F control codes, `"`, `\`. All other code points,
  //   including non-ASCII, are emitted verbatim in the UTF-8 output.
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    switch (cp) {
      case 0x22: out += '\\"'; break;
      case 0x5c: out += "\\\\"; break;
      case 0x08: out += "\\b"; break;
      case 0x09: out += "\\t"; break;
      case 0x0a: out += "\\n"; break;
      case 0x0c: out += "\\f"; break;
      case 0x0d: out += "\\r"; break;
      default:
        if (cp < 0x20) {
          out += "\\u" + cp.toString(16).padStart(4, "0");
        } else {
          out += s[i];
        }
    }
  }
  out += '"';
  return out;
}

function serializeArray(arr: unknown[]): string {
  const parts: string[] = [];
  for (const item of arr) {
    // Array element order is preserved per RFC 8785 §3.2.3.
    parts.push(serialize(item));
  }
  return "[" + parts.join(",") + "]";
}

function serializeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj);
  // Drop keys whose value is `undefined` — matches JSON.stringify behaviour
  // and prevents callers from accidentally producing non-canonicalisable
  // objects by sprinkling optional undefineds.
  const definedKeys = keys.filter((k) => obj[k] !== undefined);
  // RFC 8785 §3.2.3: sort by UTF-16 code-unit order. `Array.prototype.sort`
  // with no comparator already sorts strings this way in JS (it compares
  // code units, not code points). Explicit comparator below for clarity
  // and to immunise the implementation from future spec drift.
  definedKeys.sort(compareUtf16CodeUnits);
  const parts: string[] = [];
  for (const k of definedKeys) {
    parts.push(serializeString(k) + ":" + serialize(obj[k]));
  }
  return "{" + parts.join(",") + "}";
}

function compareUtf16CodeUnits(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ac = a.charCodeAt(i);
    const bc = b.charCodeAt(i);
    if (ac !== bc) return ac - bc;
  }
  return a.length - b.length;
}
