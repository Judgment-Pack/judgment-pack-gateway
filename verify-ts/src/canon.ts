// The canonical form (SPEC.md §1.1): the exact bytes a signature covers.

import type { Member, Value } from "./json.ts";

// The integers the domain holds: within ±(2^53 - 1).
const maxInteger = 2n ** 53n - 1n;

// canonical is the value's canonical bytes, or null when the value is
// outside the domain: a float literal, an integer past ±(2^53 - 1), a
// string holding a lone surrogate, or an object giving a name twice.
export function canonical(v: Value): Uint8Array | null {
  const out: string[] = [];
  // Work still to write, last first: a value, or text written as it is.
  const work: (Value | string)[] = [v];
  for (let w = work.pop(); w !== undefined; w = work.pop()) {
    if (typeof w === "string") {
      out.push(w);
      continue;
    }
    switch (w.type) {
      case "null":
        out.push("null");
        break;
      case "boolean":
        out.push(w.value ? "true" : "false");
        break;
      case "number":
        if (w.integer === null || w.integer > maxInteger || w.integer < -maxInteger) {
          return null;
        }
        out.push(w.integer.toString()); // -0 is 0n, written 0
        break;
      case "string": {
        const quoted = quote(w.value);
        if (quoted === null) {
          return null;
        }
        out.push(quoted);
        break;
      }
      case "array":
        out.push("[");
        work.push("]");
        for (let k = w.items.length - 1; k >= 0; k--) {
          work.push(w.items[k]!);
          if (k > 0) {
            work.push(",");
          }
        }
        break;
      case "object": {
        const members: Member[] = [];
        for (const m of w.members) {
          if (!m.name.isWellFormed()) {
            return null;
          }
          members.push(m);
        }
        members.sort((a, b) => compareCodePoints(a.name, b.name));
        for (let k = 1; k < members.length; k++) {
          if (members[k]!.name === members[k - 1]!.name) {
            return null;
          }
        }
        out.push("{");
        work.push("}");
        for (let k = members.length - 1; k >= 0; k--) {
          const m = members[k]!;
          work.push(m.value);
          work.push(quote(m.name)! + ":");
          if (k > 0) {
            work.push(",");
          }
        }
        break;
      }
    }
  }
  return new TextEncoder().encode(out.join(""));
}

// compareCodePoints orders two well-formed strings by Unicode code point,
// which is not the order of their UTF-16 code units outside the BMP.
export function compareCodePoints(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const x = a.codePointAt(i)!;
    const y = b.codePointAt(j)!;
    if (x !== y) {
      return x - y;
    }
    i += x > 0xffff ? 2 : 1;
    j += y > 0xffff ? 2 : 1;
  }
  return a.length - i - (b.length - j);
}

// quote is the string as the canonical form writes it: raw UTF-8 but for
// the quote, the backslash, the short escapes and the rest of C0 as \u00xx
// in lowercase hex; or null for a string holding a lone surrogate.
export function quote(s: string): string | null {
  if (!s.isWellFormed()) {
    return null;
  }
  let out = '"';
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    let escaped: string | undefined;
    if (c === 0x22) {
      escaped = '\\"';
    } else if (c === 0x5c) {
      escaped = "\\\\";
    } else if (c < 0x20) {
      escaped = shortForms.get(c) ?? "\\u00" + c.toString(16).padStart(2, "0");
    }
    if (escaped !== undefined) {
      out += s.slice(start, i) + escaped;
      start = i + 1;
    }
  }
  return out + s.slice(start) + '"';
}

const shortForms = new Map<number, string>([
  [0x08, "\\b"],
  [0x0c, "\\f"],
  [0x0a, "\\n"],
  [0x0d, "\\r"],
  [0x09, "\\t"],
]);
