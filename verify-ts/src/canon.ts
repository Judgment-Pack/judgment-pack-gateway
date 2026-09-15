// The canonical form (SPEC.md §1.1): the exact bytes a signature covers.

import type { Member, Value } from "./json.ts";

// The integers the domain holds: within ±(2^53 - 1).
const maxInteger = 2n ** 53n - 1n;

// canonical is the value's canonical bytes, or null when the value is
// outside the domain: a float literal, an integer past ±(2^53 - 1), a
// string holding a lone surrogate, or an object giving a name twice. The
// bytes are written as they are made, into a buffer that grows, so a
// string of millions of escapes costs its bytes and no more.
export function canonical(v: Value): Uint8Array | null {
  const out = new ByteWriter();
  // Work still to write, last first: a value, text written as it is, or a
  // member's name with its colon.
  const work: (Value | string | { readonly memberName: string })[] = [v];
  for (let w = work.pop(); w !== undefined; w = work.pop()) {
    if (typeof w === "string") {
      out.ascii(w);
      continue;
    }
    if ("memberName" in w) {
      writeQuoted(out, w.memberName);
      out.ascii(":");
      continue;
    }
    switch (w.type) {
      case "null":
        out.ascii("null");
        break;
      case "boolean":
        out.ascii(w.value ? "true" : "false");
        break;
      case "number":
        if (w.integer === null || w.integer > maxInteger || w.integer < -maxInteger) {
          return null;
        }
        out.ascii(w.integer.toString()); // -0 is 0n, written 0
        break;
      case "string":
        if (!writeQuoted(out, w.value)) {
          return null;
        }
        break;
      case "array":
        out.ascii("[");
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
        out.ascii("{");
        work.push("}");
        for (let k = members.length - 1; k >= 0; k--) {
          const m = members[k]!;
          work.push(m.value);
          work.push({ memberName: m.name });
          if (k > 0) {
            work.push(",");
          }
        }
        break;
      }
    }
  }
  return out.bytes();
}

// ByteWriter is bytes written one piece after another, into a buffer that
// doubles as it fills.
class ByteWriter {
  private buffer = Buffer.alloc(256);
  private n = 0;

  private room(k: number): void {
    if (this.n + k <= this.buffer.length) {
      return;
    }
    let size = this.buffer.length * 2;
    while (size < this.n + k) {
      size *= 2;
    }
    const grown = Buffer.alloc(size);
    this.buffer.copy(grown, 0, 0, this.n);
    this.buffer = grown;
  }

  // ascii writes a string of ASCII characters.
  ascii(s: string): void {
    this.room(s.length);
    this.n += this.buffer.write(s, this.n, "latin1");
  }

  // utf8 writes a well-formed string as UTF-8.
  utf8(s: string): void {
    this.room(Buffer.byteLength(s, "utf8"));
    this.n += this.buffer.write(s, this.n, "utf8");
  }

  bytes(): Uint8Array {
    return this.buffer.subarray(0, this.n);
  }
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

// writeQuoted writes the string as the canonical form writes one: raw
// UTF-8 but for the quote, the backslash, the short escapes and the rest
// of C0 as \u00xx in lowercase hex; or is false, writing nothing more,
// for a string holding a lone surrogate.
function writeQuoted(out: ByteWriter, s: string): boolean {
  if (!s.isWellFormed()) {
    return false;
  }
  out.ascii('"');
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
      if (i > start) {
        out.utf8(s.slice(start, i));
      }
      out.ascii(escaped);
      start = i + 1;
    }
  }
  if (s.length > start) {
    out.utf8(s.slice(start));
  }
  out.ascii('"');
  return true;
}

const shortForms = new Map<number, string>([
  [0x08, "\\b"],
  [0x0c, "\\f"],
  [0x0a, "\\n"],
  [0x0d, "\\r"],
  [0x09, "\\t"],
]);
