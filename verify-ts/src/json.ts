// JSON as it was written. A number keeps its spelling, so the integer 1 and
// the float 1.0 stay apart; an object keeps every member in the order
// written, a name given twice included, so each reader decides what a name
// given twice means to it. Reading is iterative, so no document's depth
// reaches the call stack.

export type Value =
  | { readonly type: "null" }
  | { readonly type: "boolean"; readonly value: boolean }
  | { readonly type: "number"; readonly text: string; readonly integer: bigint | null }
  | { readonly type: "string"; readonly value: string }
  | { readonly type: "array"; readonly items: Value[] }
  | { readonly type: "object"; readonly members: Member[] };

export type Member = { readonly name: string; readonly value: Value };

export type ObjectValue = Extract<Value, { type: "object" }>;

// The reference reads nothing nested deeper than this (SPEC.md §5), and
// neither does this reader.
export const maxDepth = 10000;

// maxValues is the most values -- scalars and containers alike -- one
// document may hold. Parsed, a value costs far more than its bytes: a
// document within the byte bound holding millions of small values would
// take gigabytes. SPEC.md sets no such bound; this reader's is this.
export const maxValues = 1 << 20;

// TooLarge is a document holding more than maxValues values: not a
// refusal of it as JSON, but a limit of this reader's, for the caller to
// answer as the input deserves.
export class TooLarge extends Error {}

class NotJSON extends Error {}

type Frame =
  | { readonly type: "array"; readonly items: Value[] }
  | { readonly type: "object"; readonly members: Member[]; name: string };

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// parse is the one JSON value the bytes hold, or null when they are not
// UTF-8 holding exactly one JSON value (RFC 8259), whitespace around it
// allowed and a byte order mark not. A document of more than maxValues
// values throws TooLarge.
export function parse(bytes: Uint8Array): Value | null {
  let text: string;
  try {
    text = utf8.decode(bytes);
  } catch {
    return null;
  }
  try {
    return new Reader(text).document();
  } catch (e) {
    if (e instanceof NotJSON) {
      return null;
    }
    throw e;
  }
}

const numberForm = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;

class Reader {
  private i = 0;
  private values = 0;
  private readonly s: string;

  constructor(s: string) {
    this.s = s;
  }

  document(): Value {
    const stack: Frame[] = [];
    for (;;) {
      let value = this.opening(stack);
      if (value === null) {
        continue; // a container opened, and its first item is next
      }
      // A value is complete: it joins the container it is in, and each
      // container it completes joins the one around it.
      for (;;) {
        const top = stack[stack.length - 1];
        if (top === undefined) {
          this.space();
          if (this.i !== this.s.length) {
            throw new NotJSON();
          }
          return value;
        }
        if (top.type === "array") {
          top.items.push(value);
        } else {
          top.members.push({ name: top.name, value });
        }
        this.space();
        const c = this.s.charCodeAt(this.i);
        if (c === 0x2c) {
          this.i++;
          if (top.type === "object") {
            top.name = this.name();
          }
          break;
        }
        if ((top.type === "array" && c === 0x5d) || (top.type === "object" && c === 0x7d)) {
          this.i++;
          stack.pop();
          value = top.type === "array" ? { type: "array", items: top.items } : { type: "object", members: top.members };
          continue;
        }
        throw new NotJSON();
      }
    }
  }

  // opening reads the start of a value: a scalar whole, or an empty
  // container whole, or else it opens a container on the stack and is null.
  private opening(stack: Frame[]): Value | null {
    if (++this.values > maxValues) {
      throw new TooLarge();
    }
    this.space();
    const c = this.s.charCodeAt(this.i);
    if (c === 0x7b || c === 0x5b) {
      if (stack.length >= maxDepth) {
        throw new NotJSON();
      }
      this.i++;
      this.space();
      if (c === 0x5b) {
        if (this.s.charCodeAt(this.i) === 0x5d) {
          this.i++;
          return { type: "array", items: [] };
        }
        stack.push({ type: "array", items: [] });
        return null;
      }
      if (this.s.charCodeAt(this.i) === 0x7d) {
        this.i++;
        return { type: "object", members: [] };
      }
      stack.push({ type: "object", members: [], name: this.name() });
      return null;
    }
    if (c === 0x22) {
      return { type: "string", value: this.string() };
    }
    for (const [word, value] of literals) {
      if (this.s.startsWith(word, this.i)) {
        this.i += word.length;
        return value;
      }
    }
    numberForm.lastIndex = this.i;
    const m = numberForm.exec(this.s);
    if (m === null) {
      throw new NotJSON();
    }
    this.i = numberForm.lastIndex;
    const integer = m[1] === undefined && m[2] === undefined ? BigInt(m[0]) : null;
    return { type: "number", text: m[0], integer };
  }

  // name reads a member's name and the colon after it.
  private name(): string {
    this.space();
    if (this.s.charCodeAt(this.i) !== 0x22) {
      throw new NotJSON();
    }
    const name = this.string();
    this.space();
    if (this.s.charCodeAt(this.i) !== 0x3a) {
      throw new NotJSON();
    }
    this.i++;
    return name;
  }

  // string reads a string from its opening quote. An escaped surrogate
  // stays what it was escaped as, paired or not: the canonical form refuses
  // one that is alone, and a reader that does not canonicalize need not.
  private string(): string {
    const s = this.s;
    let i = this.i + 1;
    let start = i;
    let out = "";
    for (;;) {
      if (i >= s.length) {
        throw new NotJSON();
      }
      const c = s.charCodeAt(i);
      if (c === 0x22) {
        out += s.slice(start, i);
        this.i = i + 1;
        return out;
      }
      if (c < 0x20) {
        throw new NotJSON();
      }
      if (c !== 0x5c) {
        i++;
        continue;
      }
      out += s.slice(start, i);
      const e = s.charCodeAt(i + 1);
      const short = shortEscapes.get(e);
      if (short !== undefined) {
        out += short;
        i += 2;
      } else if (e === 0x75) {
        const hex = s.slice(i + 2, i + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          throw new NotJSON();
        }
        out += String.fromCharCode(parseInt(hex, 16));
        i += 6;
      } else {
        throw new NotJSON();
      }
      start = i;
    }
  }

  private space(): void {
    const s = this.s;
    let i = this.i;
    for (;;) {
      const c = s.charCodeAt(i);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) {
        break;
      }
      i++;
    }
    this.i = i;
  }
}

const literals: ReadonlyArray<readonly [string, Value]> = [
  ["true", { type: "boolean", value: true }],
  ["false", { type: "boolean", value: false }],
  ["null", { type: "null" }],
];

const shortEscapes = new Map<number, string>([
  [0x22, '"'],
  [0x5c, "\\"],
  [0x2f, "/"],
  [0x62, "\b"],
  [0x66, "\f"],
  [0x6e, "\n"],
  [0x72, "\r"],
  [0x74, "\t"],
]);

// member is the value of the object's first member of that name.
export function member(o: ObjectValue, name: string): Value | undefined {
  for (const m of o.members) {
    if (m.name === name) {
      return m.value;
    }
  }
  return undefined;
}

// count is how many of the object's members have that name.
export function count(o: ObjectValue, name: string): number {
  let n = 0;
  for (const m of o.members) {
    if (m.name === name) {
      n++;
    }
  }
  return n;
}

// hasDuplicate is whether any object in the value, at any depth, gives one
// name twice.
export function hasDuplicate(v: Value): boolean {
  const work: Value[] = [v];
  for (let w = work.pop(); w !== undefined; w = work.pop()) {
    if (w.type === "array") {
      for (const item of w.items) {
        work.push(item);
      }
    } else if (w.type === "object") {
      const seen = new Set<string>();
      for (const m of w.members) {
        if (seen.has(m.name)) {
          return true;
        }
        seen.add(m.name);
        work.push(m.value);
      }
    }
  }
  return false;
}
